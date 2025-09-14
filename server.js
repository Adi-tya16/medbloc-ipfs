require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const QRCode = require('qrcode');
const FormData = require('form-data'); // <-- ADD THIS LINE

// Firebase Admin SDK for backend services
const admin = require('firebase-admin');

// --- IMPORTANT: PARSE FIREBASE PRIVATE KEY ---
// Firebase requires the private_key to have its newlines preserved.
// When storing it in a .env file, you must wrap it in quotes and encode the newlines as \n.
// This code will decode it back to the format Firebase needs.
let privateKey;
try {
    if (!process.env.FIREBASE_PRIVATE_KEY) {
        throw new Error("FIREBASE_PRIVATE_KEY environment variable is not set.");
    }
    privateKey = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
} catch (error) {
    console.error("Error parsing FIREBASE_PRIVATE_KEY:", error.message);
    process.exit(1); // Exit if the key is not configured correctly
}

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    privateKey: privateKey,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
  }),
});

const db = admin.firestore();
const app = express();
const port = 3001;

// --- MIDDLEWARE SETUP ---
// Enable CORS for all origins. This is suitable for development.
// When you deploy to a live server, you should restrict this to your specific frontend URL
// by setting the CORS_ORIGIN environment variable on your server platform (e.g., Render).
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*'
}));


// To handle JSON payloads
app.use(express.json());

// Multer setup for temporary file storage
const upload = multer({ dest: 'uploads/' });

// --- AUTHENTICATION MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.sendStatus(401); // if there isn't any token

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // if token is no longer valid
        
        // FIX: Add a check to ensure the token payload has the required user ID (uid)
        if (!user || !user.uid) {
            return res.status(403).json({ message: "Invalid token: User ID is missing." });
        }

        req.user = user;
        next(); // move on to the next middleware or the route handler
    });
};


// --- API ROUTES ---

// 1. Root endpoint for health check
app.get('/', (req, res) => {
    res.send('✅ IPFS QR Portal Backend is running!');
});

// 2. User Registration
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required." });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        // Use email as the document ID for easy lookup and to prevent duplicates
        const userRef = db.collection('users').doc(email);
        const doc = await userRef.get();

        if (doc.exists) {
            return res.status(409).json({ message: "User already exists." });
        }
        
        const userPayload = {
            email,
            password: hashedPassword,
            createdAt: new Date().toISOString()
        };
        await userRef.set(userPayload);
        
        // Firestore creates a unique ID for the user document, let's get it to use in the token
        const newUserDoc = await userRef.get();
        const userRecord = newUserDoc.data();
        userRecord.uid = newUserDoc.id; // Add the unique document ID to the user record

        res.status(201).json({ message: "User created successfully. Please login." });

    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ message: "Error creating user." });
    }
});

// 3. User Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const userRef = db.collection('users').doc(email);
        const doc = await userRef.get();

        if (!doc.exists) {
            return res.status(400).json({ message: "Invalid credentials." });
        }
        const user = doc.data();

        if (await bcrypt.compare(password, user.password)) {
            // Create a token payload. We'll use the document ID (email) as the unique identifier.
            const accessTokenPayload = { email: user.email, uid: doc.id };
            const accessToken = jwt.sign(accessTokenPayload, process.env.JWT_SECRET);
            res.json({ accessToken, email: user.email });
        } else {
            res.status(400).json({ message: "Invalid credentials." });
        }
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Server error during login." });
    }
});


// 4. File Upload (Protected Route)
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: "No file was uploaded." });
    }
    
    try {
        const formData = new FormData();
        const fileStream = fs.createReadStream(req.file.path);
        // FIX: Added original filename to the form data, which is required by Pinata
        formData.append('file', fileStream, { filename: req.file.originalname });

        const pinataResponse = await axios.post('https://api.pinata.cloud/pinning/pinFileToIPFS', formData, {
            headers: {
                ...formData.getHeaders(),
                'Authorization': `Bearer ${process.env.PINATA_JWT}`
            }
        });

        // Save file metadata to the user's collection in Firestore
        const userFilesRef = db.collection('users').doc(req.user.uid).collection('files');
        await userFilesRef.add({
            ipfsHash: pinataResponse.data.IpfsHash,
            originalName: req.file.originalname,
            timestamp: new Date().toISOString(),
        });

        res.json({ ipfsHash: pinataResponse.data.IpfsHash });
    } catch (error) {
        console.error("Pinata Upload Error:", error.response ? error.response.data : error.message);
        res.status(500).json({ message: "An error occurred during file upload." });
    } finally {
        // Clean up the temp file
        fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting temp file:", err);
        });
    }
});

// 5. Get User's Files (Protected Route)
app.get('/api/files', authenticateToken, async (req, res) => {
    try {
        const filesSnapshot = await db.collection('users').doc(req.user.uid).collection('files').orderBy('timestamp', 'desc').get();
        const files = filesSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json(files);
    } catch (error) {
        console.error("Fetch Files Error:", error);
        res.status(500).json({ message: "Could not fetch user files." });
    }
});

// 6. Generate and return a QR code for the user's public page
app.get('/api/share', authenticateToken, async (req, res) => {
    try {
        const publicUrl = `${process.env.FRONTEND_URL}/public.html?user=${req.user.uid}`;
        // DEBUGGING: Log the generated URL to the console
        console.log('Generated Public URL for QR Code:', publicUrl);
        const qrCodeUrl = await QRCode.toDataURL(publicUrl);
        res.json({ qrCodeUrl });
    } catch (error) {
        console.error("QR Code Generation Error:", error);
        res.status(500).json({ message: "Failed to generate QR code." });
    }
});

// 7. Get Files for a Public User
app.get('/api/public/files/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const userDoc = await db.collection('users').doc(userId).get();
        if (!userDoc.exists) {
            return res.status(404).json({ message: "User not found." });
        }
        
        const filesSnapshot = await db.collection('users').doc(userId).collection('files').orderBy('timestamp', 'desc').get();
        const files = filesSnapshot.docs.map(doc => doc.data());

        res.json({ userEmail: userDoc.data().email, files });
    } catch (error) {
        console.error("Fetch Public Files Error:", error);
        res.status(500).json({ message: "Could not fetch public files." });
    }
});


// --- START SERVER ---
app.listen(port, () => {
    console.log(`✅ Backend server is running at http://localhost:${port}`);
});

