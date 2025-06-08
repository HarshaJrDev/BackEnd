// backend/index.js
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const http = require("http");
const { Server } = require("socket.io");
const { google } = require("googleapis");
const axios = require("axios");
require("dotenv").config();
const serviceAccountKey = require("./serviceAccountKey.json");
const admin = require("firebase-admin");

// Initialize Firebase Admin SDK
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey),
  });
}

const db = admin.firestore();
const app = express();
app.use(express.json());
app.use(cors());

// Rate limiting for /send-otp
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: {
    success: false,
    message: "Too many requests, try again in an hour.",
  },
});

// OTP Store
const otpStore = new Map();
setInterval(() => {
  const now = Date.now();
  otpStore.forEach((value, key) => {
    if (now > value.expiresAt) otpStore.delete(key);
  });
}, 60000);

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const sendOTP = async (email, otp) => {
  console.log(`[Dummy OTP] Sent ${otp} to ${email}`);
  return Promise.resolve();
};

app.use((err, req, res, next) => {
  console.error("Global error handler:", err);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || "Internal Server Error",
  });
});

// OTP Endpoints
app.post("/send-otp", limiter, async (req, res, next) => {
  const { email } = req.body;
  if (!email || !isValidEmail(email)) return next({ status: 400, message: "Invalid email" });

  const otp = Math.floor(100000 + Math.random() * 900000);
  otpStore.set(email, { otp: String(otp), expiresAt: Date.now() + 600000 });
  await sendOTP(email, otp);
  res.json({ success: true, message: "OTP sent successfully" });
});

app.post("/verify-otp", async (req, res, next) => {
  const { email, otp } = req.body;
  const record = otpStore.get(email);
  if (!record || Date.now() > record.expiresAt) return next({ status: 400, message: "OTP expired or not found" });
  if (record.otp !== otp) return next({ status: 400, message: "Invalid OTP" });

  otpStore.delete(email);
  res.json({ success: true, message: "OTP verified" });
});

// Firebase Cloud Messaging V1 setup
const SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"];

const getAccessToken = () => {
  return new Promise((resolve, reject) => {
    const jwtClient = new google.auth.JWT(
      serviceAccountKey.client_email,
      null,
      serviceAccountKey.private_key,
      SCOPES
    );
    jwtClient.authorize((err, tokens) => {
      if (err) return reject(err);
      resolve(tokens.access_token);
    });
  });
};

const AxiosConfig = async (token, notification) => {
  const config = {
    method: "post",
    url: `https://fcm.googleapis.com/v1/projects/${serviceAccountKey.project_id}/messages:send`,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    data: notification,
  };

  return axios(config);
};

const sendNotification = async (token, title, body, data = {}) => {
  const access_token = await getAccessToken();
  const message = {
    message: {
      token,
      notification: { title, body },
      data: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)])),
      apns: {
        payload: {
          aps: { sound: "default" },
        },
      },
    },
  };

  return AxiosConfig(access_token, message);
};

// Notification endpoint
app.post("/send-notifications", async (req, res, next) => {
  const { bookingId, bookingData } = req.body;
  if (!bookingId || !bookingData) return next({ status: 400, message: "Missing booking info" });

  const tokens = [];
  const snapshot = await db.collection("drivers").get();
  snapshot.forEach((doc) => {
    const data = doc.data();
    if (data.fcmToken) tokens.push(data.fcmToken);
  });

  const sendPromises = tokens.map((token) =>
    sendNotification(token, "New Booking", `Booking #${bookingId}`, { bookingId })
      .catch((err) => ({ status: "rejected", reason: err.message }))
  );

  const results = await Promise.allSettled(sendPromises);
  const successCount = results.filter((r) => r.status === "fulfilled").length;
  const failureCount = results.length - successCount;

  res.json({
    success: true,
    message: `Notifications sent.`,
    fcmResponse: { successCount, failureCount },
  });
});

// Socket.IO
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);

  socket.on("join_room", (roomId) => {
    socket.join(roomId);
    console.log(`Socket ${socket.id} joined room ${roomId}`);
  });

  socket.on("send_message", ({ roomId, message, senderId }) => {
    socket.to(roomId).emit("receive_message", { message, senderId, timestamp: new Date().toISOString() });
  });

  socket.on("disconnect", () => {
    console.log("Socket disconnected:", socket.id);
  });
});

const PORT = process.env.PORT || 4200;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));