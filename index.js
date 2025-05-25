const express = require("express");
require("dotenv").config();
const sendOTP = require("./mailer");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
app.use(express.json());
app.use(cors());

// In-memory OTP store (can be replaced with MongoDB)
const otpStore = new Map();

// Email validation function
const isValidEmail = (email) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// Rate limiting: max 3 requests per IP per hour for sending OTP
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
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

// --- Send OTP Endpoint ---
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  console.log(`[OTP] Received send-otp request for email: ${email}`);

  if (!email || !isValidEmail(email)) {
    console.log(`[OTP] Invalid email received: ${email}`);
    return res.status(400).json({ success: false, message: "Invalid or missing email address." });
  }

  const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
  const expiresAt = Date.now() + 10 * 60 * 1000; // Expires in 10 minutes

  try {
    await sendOTP(email, otp);
    otpStore.set(email, { otp: String(otp), expiresAt });
    console.log(`[OTP] OTP sent to ${email}: ${otp}`);

    return res.status(200).json({ success: true, message: "OTP sent successfully." });
  } catch (error) {
    console.error(`[OTP] Failed to send OTP to ${email}:`, error);
    return res.status(500).json({ success: false, message: "Failed to send OTP. Please try again." });
  }
});

// --- Verify OTP Endpoint ---
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  console.log(`[OTP] Verify OTP request for email: ${email}, OTP: ${otp}`);

  if (!email || !isValidEmail(email) || !otp) {
    console.log(`[OTP] Missing or invalid data in verify request.`);
    return res.status(400).json({ success: false, message: "Email and OTP are required." });
  }

  const record = otpStore.get(email);

  if (!record) {
    console.log(`[OTP] No OTP record found for email: ${email}`);
    return res.status(400).json({ success: false, message: "No OTP found for this email." });
  }

  if (Date.now() > record.expiresAt) {
    otpStore.delete(email);
    console.log(`[OTP] OTP expired for email: ${email}`);
    return res.status(400).json({ success: false, message: "OTP has expired." });
  }

  if (String(record.otp) !== String(otp)) {
    console.log(`[OTP] Invalid OTP entered for email: ${email}`);
    return res.status(400).json({ success: false, message: "Invalid OTP." });
  }

  otpStore.delete(email);
  console.log(`[OTP] OTP verified successfully for email: ${email}`);
  return res.status(200).json({ success: true, message: "OTP verified successfully." });
});

// --- Create HTTP server and Socket.IO server ---
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*", // adjust for production to your frontend domain
    methods: ["GET", "POST"],
  },
});

// Socket.IO event handlers
io.on("connection", (socket) => {
  console.log(`[Socket.IO] Client connected: ${socket.id}`);

  socket.on("join_room", (roomId) => {
    socket.join(roomId);
    console.log(`[Socket.IO] Socket ${socket.id} joined room: ${roomId}`);
  });

  socket.on("send_message", ({ roomId, message, senderId }) => {
    console.log(`[Socket.IO] Message from ${senderId} in room ${roomId}: ${message}`);
    socket.to(roomId).emit("receive_message", { message, senderId });
  });

  socket.on("disconnect", () => {
    console.log(`[Socket.IO] Client disconnected: ${socket.id}`);
  });
});

// --- Start server ---
const PORT = 4200;
server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});