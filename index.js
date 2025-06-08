// backend/index.js
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const http = require("http");
const { Server } = require("socket.io");
const { GoogleAuth } = require("google-auth-library");
const fetch = require("node-fetch"); // If Node 16 or below, install node-fetch@2
require("dotenv").config();

const serviceAccountKey = require('./serviceAccountKey.json');
const admin = require("firebase-admin");

// Initialize Firebase Admin SDK (do once)
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey)
  });
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
});
app.use("/send-otp", limiter);

// In-memory OTP store (for demonstration only)
const otpStore = new Map();

// Email validation regex
const isValidEmail = (email) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// Dummy function simulating sending OTP by email
const sendOTP = async (email, otp) => {
  console.log(`[Dummy OTP] Sending OTP ${otp} to ${email}`);
  return Promise.resolve();
};

// --- OTP endpoints ---

app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ success: false, message: "Invalid or missing email." });
  }
  const otp = Math.floor(100000 + Math.random() * 900000);
  const expiresAt = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes

  try {
    await sendOTP(email, otp);
    otpStore.set(email, { otp: String(otp), expiresAt });
    return res.status(200).json({ success: true, message: "OTP sent successfully." });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to send OTP." });
  }
});

app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  if (!email || !isValidEmail(email) || !otp) {
    return res.status(400).json({ success: false, message: "Email and OTP required." });
  }
  const record = otpStore.get(email);
  if (!record) return res.status(400).json({ success: false, message: "No OTP found." });
  if (Date.now() > record.expiresAt) {
    otpStore.delete(email);
    return res.status(400).json({ success: false, message: "OTP expired." });
  }
  if (String(record.otp) !== String(otp)) {
    return res.status(400).json({ success: false, message: "Invalid OTP." });
  }
  otpStore.delete(email);
  return res.status(200).json({ success: true, message: "OTP verified." });
});

// --- FCM HTTP v1 API setup ---

const SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"];
const FIREBASE_PROJECT_ID = 'kalanabha-f6fcf'; // Replace with your Firebase project ID

async function getAccessToken() {
  const auth = new GoogleAuth({ scopes: SCOPES });
  const client = await auth.getClient();
  const accessTokenResponse = await client.getAccessToken();
  return accessTokenResponse.token;
}

// Send notification with FCM HTTP v1 API
async function sendFcmMessage(token, title, body, data = {}) {
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
}

// --- Send notifications endpoint ---

app.post("/send-notifications", async (req, res) => {
  try {
    const { bookingId, bookingData } = req.body;
    if (!bookingId || !bookingData) {
      return res.status(400).json({ success: false, message: "bookingId and bookingData required" });
    }

    // Fetch all driver tokens from Firestore collection "drivers"
    const tokens = [];
    const driversSnapshot = await db.collection("drivers").get();

    driversSnapshot.forEach(doc => {
      const data = doc.data();
      if (data.fcmToken) {
        tokens.push(data.fcmToken);
      }
    });

    if (tokens.length === 0) {
      return res.status(400).json({ success: false, message: "No driver tokens found" });
    }

    const title = "New Booking Available!";
    const body = `Booking #${bookingId} for ${bookingData.customerName || "a customer"}`;

    // Send push notifications in parallel
    const sendPromises = tokens.map(token => sendFcmMessage(token, title, body, { bookingId: String(bookingId) }));
    const results = await Promise.allSettled(sendPromises);

    const successCount = results.filter(r => r.status === "fulfilled").length;
    const failureCount = results.length - successCount;

    return res.status(200).json({
      success: true,
      message: `Notifications sent to drivers.`,
      fcmResponse: { successCount, failureCount },
    });
  } catch (error) {
    console.error("Error sending notifications:", error);
    return res.status(500).json({ success: false, message: error.message });
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
    socket.join(roomId);
    console.log(`Socket ${socket.id} joined room: ${roomId}`);
  });

  socket.on("send_message", ({ roomId, message, senderId }) => {
    socket.to(roomId).emit("receive_message", { message, senderId, timestamp: new Date().toISOString() });
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
