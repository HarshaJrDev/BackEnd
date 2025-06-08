// backend/index.js
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const http = require("http");
const { Server } = require("socket.io");
const { GoogleAuth } = require("google-auth-library");
const fetch = require("node-fetch");
require("dotenv").config();
const serviceAccountKey = require('./serviceAccountKey.json');
const admin = require("firebase-admin");

// Initialize Firebase Admin SDK with error handling
try {
    if (!admin.apps.length) {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccountKey)
        });
    }
} catch (error) {
    console.error('Firebase Admin SDK initialization failed:', error);
    process.exit(1);
}

const db = admin.firestore();
const app = express();
app.use(express.json());
app.use(cors());

// Rate limiting for /send-otp endpoint (3 requests per hour per IP)
const limiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: {
        success: false,
        message: "Too many requests from this IP, please try again in an hour.",
        remaining: 0,
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res, next) => {
        const error = new Error(res.locals.rateLimit.message);
        error.status = 429;
        next(error);
    }
});

// In-memory OTP store with cleanup mechanism
const otpStore = new Map();
// Clean up expired OTPs periodically
setInterval(() => {
    const now = Date.now();
    otpStore.forEach((value, key) => {
        if (now > value.expiresAt) {
            otpStore.delete(key);
        }
    });
}, 60000); // Clean every minute

// Email validation regex
const isValidEmail = (email) =>
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// Dummy function simulating sending OTP by email
const sendOTP = async (email, otp) => {
    try {
        console.log(`[Dummy OTP] Sending OTP ${otp} to ${email}`);
        return Promise.resolve();
    } catch (error) {
        throw new Error(`Failed to send OTP: ${error.message}`);
    }
};

// Global error handler
app.use((err, req, res, next) => {
    console.error('Global error handler:', {
        error: err.message,
        stack: err.stack,
        method: req.method,
        url: req.url,
        timestamp: new Date().toISOString()
    });

    const status = err.status || 500;
    const message = err.message || 'Internal server error';

    res.status(status).json({
        success: false,
        message,
        timestamp: new Date().toISOString()
    });
});

// --- OTP endpoints ---
app.post("/send-otp", limiter, async (req, res, next) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return next({
                status: 400,
                message: "Email is required"
            });
        }

        if (!isValidEmail(email)) {
            return next({
                status: 400,
                message: "Invalid email format"
            });
        }

        const otp = Math.floor(100000 + Math.random() * 900000);
        const expiresAt = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes

        await sendOTP(email, otp);
        otpStore.set(email, { otp: String(otp), expiresAt });

        res.json({
            success: true,
            message: "OTP sent successfully",
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        next(error);
    }
});

app.post("/verify-otp", async (req, res, next) => {
    try {
        const { email, otp } = req.body;

        if (!email || !isValidEmail(email) || !otp) {
            return next({
                status: 400,
                message: "Email and OTP are required"
            });
        }

        const record = otpStore.get(email);
        if (!record) {
            return next({
                status: 400,
                message: "No OTP found for this email"
            });
        }

        if (Date.now() > record.expiresAt) {
            otpStore.delete(email);
            return next({
                status: 400,
                message: "OTP has expired"
            });
        }

        if (String(record.otp) !== String(otp)) {
            return next({
                status: 400,
                message: "Invalid OTP"
            });
        }

        otpStore.delete(email);
        res.json({
            success: true,
            message: "OTP verified successfully",
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        next(error);
    }
});

// --- FCM HTTP v1 API setup ---
const SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"];
const FIREBASE_PROJECT_ID = 'kalanabha-f6fcf';

async function getAccessToken() {
    try {
        const auth = new GoogleAuth({ scopes: SCOPES });
        const client = await auth.getClient();
        const accessTokenResponse = await client.getAccessToken();
        return accessTokenResponse.token;
    } catch (error) {
        throw new Error(`Failed to get access token: ${error.message}`);
    }
}

async function sendFcmMessage(token, title, body, data = {}) {
    try {
        const accessToken = await getAccessToken();
        const url = 'https://fcm.googleapis.com/v1/projects/kalanabha-f6fcf/messages:send';
        
        const messagePayload = {
            message: {
                token,
                notification: { title, body },
                data: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)])),
                android: {
                    notification: { channelId: "default" },
                },
                apns: {
                    payload: {
                        aps: {
                            category: "NEW_MESSAGE_CATEGORY",
                            sound: "default",
                        },
                    },
                },
            },
        };

        const res = await fetch(url, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${accessToken}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(messagePayload),
        });

        if (!res.ok) {
            const errorBody = await res.text();
            throw new Error(`FCM request failed: ${res.status} ${res.statusText} - ${errorBody}`);
        }

        return await res.json();
    } catch (error) {
        throw new Error(`Failed to send FCM message: ${error.message}`);
    }
}

// --- Send notifications endpoint ---
app.post("/send-notifications", async (req, res, next) => {
    try {
        const { bookingId, bookingData } = req.body;

        if (!bookingId || !bookingData) {
            return next({
                status: 400,
                message: "bookingId and bookingData are required"
            });
        }

        const tokens = [];
        const driversSnapshot = await db.collection("drivers").get();
        
        driversSnapshot.forEach(doc => {
            const data = doc.data();
            if (data.fcmToken) {
                tokens.push(data.fcmToken);
            }
        });

        if (tokens.length === 0) {
            return next({
                status: 400,
                message: "No driver tokens found"
            });
        }

        const title = "New Booking Available!";
        const body = `Booking #${bookingId} for ${bookingData.customerName || "a customer"}`;

        const sendPromises = tokens.map(token => 
            sendFcmMessage(token, title, body, { bookingId: String(bookingId) })
                .catch(error => ({ status: 'rejected', reason: error }))
        );

        const results = await Promise.allSettled(sendPromises);
        const successCount = results.filter(r => r.status === "fulfilled").length;
        const failureCount = results.length - successCount;

        res.json({
            success: true,
            message: `Notifications sent to drivers.`,
            fcmResponse: { successCount, failureCount },
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        next(error);
    }
});

// --- Socket.IO setup ---
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*", // Set your frontend URL here for production
        methods: ["GET", "POST"],
    },
});

io.on("connection", (socket) => {
    console.log(`Socket connected: ${socket.id}`);

    socket.on("join_room", (roomId) => {
        try {
            socket.join(roomId);
            console.log(`Socket ${socket.id} joined room: ${roomId}`);
        } catch (error) {
            console.error(`Error joining room ${roomId}:`, error);
            socket.emit("error", {
                message: "Failed to join room",
                timestamp: new Date().toISOString()
            });
        }
    });

    socket.on("send_message", ({ roomId, message, senderId }) => {
        try {
            socket.to(roomId).emit("receive_message", {
                message,
                senderId,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            console.error(`Error sending message to room ${roomId}:`, error);
            socket.emit("error", {
                message: "Failed to send message",
                timestamp: new Date().toISOString()
            });
        }
    });

    socket.on("disconnect", () => {
        console.log(`Socket disconnected: ${socket.id}`);
    });
});

// --- Start server ---
const PORT = process.env.PORT || 4200;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});