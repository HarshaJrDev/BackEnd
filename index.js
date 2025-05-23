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

// Rate limiting: max 3 requests per IP per hour
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: { error: "Too many requests from this IP, please try again later." },
});
app.use("/send-otp", limiter);

// Email validation function
const isValidEmail = (email) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// --- Send OTP Endpoint ---
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  console.log(`[OTP] Received send-otp request for email: ${email}`);

  if (!email || !isValidEmail(email)) {
    console.log(`[OTP] Invalid email received: ${email}`);
    return res.status(400).json({ error: "Invalid or missing email address." });
  }

  const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
  const expiresAt = Date.now() + 10 * 60 * 1000; // Expires in 10 minutes

  try {
    await sendOTP(email, otp);
    otpStore.set(email, { otp, expiresAt });
    console.log(`[OTP] OTP sent to ${email}: ${otp}`);

    return res.status(200).json({ message: "OTP sent successfully." });
  } catch (error) {
    console.error(`[OTP] Failed to send OTP to ${email}:`, error);
    return res.status(500).json({ error: "Failed to send OTP. Please try again." });
  }
});

// --- Verify OTP Endpoint ---
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  console.log(`[OTP] Verify OTP request for email: ${email}, OTP: ${otp}`);

  if (!email || !isValidEmail(email) || !otp) {
    console.log(`[OTP] Missing or invalid data in verify request.`);
    return res.status(400).json({ error: "Email and OTP are required." });
  }

  const record = otpStore.get(email);

  if (!record) {
    console.log(`[OTP] No OTP record found for email: ${email}`);
    return res.status(400).json({ error: "No OTP found for this email." });
  }

  if (Date.now() > record.expiresAt) {
    otpStore.delete(email);
    console.log(`[OTP] OTP expired for email: ${email}`);
    return res.status(400).json({ error: "OTP has expired." });
  }

  if (record.otp.toString() !== otp.toString()) {
    console.log(`[OTP] Invalid OTP entered for email: ${email}`);
    return res.status(400).json({ error: "Invalid OTP." });
  }

  otpStore.delete(email);
  console.log(`[OTP] OTP verified successfully for email: ${email}`);
  return res.status(200).json({ message: "OTP verified successfully." });
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
