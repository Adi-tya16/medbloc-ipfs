// =================================================================
// ==                 IPFS USER PORTAL - BACKEND                  ==
// =================================================================

// ---------------------------
// 1. Imports & Configuration
// ---------------------------
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const pinataSDK = require('@pinata/sdk');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

// ---------------------------
// 2. Middleware
// ---------------------------
// Enable CORS for all routes and origins
app.use(cors());
// Parse JSON bodies (as sent by API clients)
app.use(express.json());

// Multer setup for temporary file storage
const upload = multer({ dest: 'uploads/' });

// ---------------------------
// 3. Service Initializations
// ---------------------------
// Initialize Pinata SDK
const pinata = new pinataSDK({ pinataJWTKey: process.env.PINATA_JWT });

// Initialize Firebase Admin SDK
// IMPORTANT: Ensure your .env file has the correct Firebase variables
const serviceAccount = {
  projectId: process.env.FIREBASE_PROJECT_ID,
  privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// JWT Secret from environment variables
const JWT_SECRET = process.env.JWT_SECRET;

// ---------------------------
// 4. Authentication Middleware
// ---------------------------
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) {
        return res.sendStatus(401); // No token, unauthorized
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Token is not valid, forbidden
        }
        req.user = user; // Add the decoded user payload to the request object
        next();
    });
};


// ---------------------------
// 5. API Routes
// ---------------------------

// Root endpoint for health check
app.get('/', (req, res) => {
    res.send('IPFS User Portal Backend is running!');
});

// == AUTHENTICATION ROUTES ==

// POST /api/register
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required." });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const userRef = db.collection('users').doc(email);
        const doc = await userRef.get();

        if (doc.exists) {
            return res.status(409).json({ message: "User already exists." });
        }

        await userRef.set({
            email: email,
            password: hashedPassword,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.status(201).json({ message: "User created successfully." });
    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ message: "Error creating user." });
    }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const userRef = db.collection('users').doc(email);
        const doc = await userRef.get();

        if (!doc.exists) {
            return res.status(401).json({ message: "Invalid credentials." });
        }

        const user = doc.data();
        if (await bcrypt.compare(password, user.password)) {
            // Passwords match, create JWT
            const accessToken = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1d' });
            res.json({ accessToken: accessToken, email: user.email });
        } else {
            res.status(401).json({ message: "Invalid credentials." });
        }
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Server error during login." });
    }
});


// == PROTECTED ROUTES (Require Authentication) ==

// POST /api/upload
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }
    const filePath = path.join(__dirname, req.file.path);
    const readableStreamForFile = fs.createReadStream(filePath);
    
    try {
        const options = {
            pinataMetadata: {
                name: req.file.originalname,
                keyvalues: {
                    user: req.user.email // Associate file with the logged-in user
                }
            },
            pinataOptions: {
                cidVersion: 0
            }
        };
        const result = await pinata.pinFileToIPFS(readableStreamForFile, options);

        // Save file info to the user's collection in Firestore
        const userUploadsRef = db.collection('users').doc(req.user.email).collection('uploads');
        await userUploadsRef.add({
            ipfsHash: result.IpfsHash,
            fileName: req.file.originalname,
            fileSize: req.file.size,
            uploadedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(200).json(result);
    } catch (error) {
        console.error("Error uploading to Pinata:", error);
        res.status(500).json({ message: "An error occurred during file upload." });
    } finally {
        // Clean up the temporarily uploaded file
        fs.unlinkSync(filePath);
    }
});

// GET /api/files
app.get('/api/files', authenticateToken, async (req, res) => {
    try {
        const userEmail = req.user.email;
        const uploadsSnapshot = await db.collection('users').doc(userEmail).collection('uploads').orderBy('uploadedAt', 'desc').get();
        
        const files = uploadsSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        
        res.status(200).json(files);
    } catch (error) {
        console.error("Error fetching files:", error);
        res.status(500).json({ message: "Failed to fetch user files." });
    }
});

// ---------------------------
// 6. Start the Server
// ---------------------------
app.listen(port, () => {
    console.log(`✅ Backend server is running at http://localhost:${port}`);
});
