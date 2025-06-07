const express = require("express");
const dotenv = require("dotenv");
const admin = require("firebase-admin");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const sendOTP = require("./mailer");
const serviceAccount = require("./serviceAccountKey.json");

// Load environment variables
dotenv.config();

// Initialize Firebase Admin SDK


admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Initialize Express app
const app = express();
app.use(express.json());
app.use(cors());

// In-memory OTP store (replace with MongoDB or Redis in production)
const otpStore = new Map();

// Email validation function
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// Rate limiting: max 3 requests per IP per hour for sending OTP
const otpLimiter = rateLimit({
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
app.use("/send-otp", otpLimiter);

// Middleware to verify Firebase ID token
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }

  const idToken = authHeader.split("Bearer ")[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error("[Auth] Authentication error:", error);
    res.status(401).json({ success: false, message: "Invalid token" });
  }
};

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

// --- Request Role Change Endpoint ---
app.post("/request-role", authenticate, async (req, res) => {
  const { role } = req.body;
  const userId = req.user.uid;

  if (!["driver", "admin"].includes(role)) {
    return res.status(400).json({ success: false, message: "Invalid role" });
  }

  try {
    await admin.firestore().collection("roleRequests").doc(userId).set({
      userId,
      requestedRole: role,
      status: "pending",
      requestedAt: new Date(),
    });

    console.log(`[RBAC] Role request submitted for user ${userId}: ${role}`);
    res.status(200).json({ success: true, message: "Role request submitted" });
  } catch (error) {
    console.error(`[RBAC] Role request error for user ${userId}:`, error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// --- Approve Role Change Endpoint ---
app.post("/approve-role", authenticate, async (req, res) => {
  const { userId, role, approve } = req.body;

  // Verify requester is admin
  const requester = await admin.firestore().collection("admins").doc(req.user.uid).get();
  if (!requester.exists) {
    console.log(`[RBAC] Unauthorized role approval attempt by ${req.user.uid}`);
    return res.status(403).json({ success: false, message: "Admin access required" });
  }

  if (!["driver", "admin"].includes(role)) {
    console.log(`[RBAC] Invalid role in approval request: ${role}`);
    return res.status(400).json({ success: false, message: "Invalid role" });
  }

  try {
    const roleRequestRef = admin.firestore().collection("roleRequests").doc(userId);
    const roleRequest = await roleRequestRef.get();

    if (!roleRequest.exists || roleRequest.data().requestedRole !== role) {
      console.log(`[RBAC] Role request not found for user ${userId}`);
      return res.status(404).json({ success: false, message: "Role request not found" });
    }

    if (approve) {
      const userDoc = await admin.firestore().collection("users").doc(userId).get();
      if (userDoc.exists) {
        await admin.firestore().collection(role + "s").doc(userId).set({
          ...userDoc.data(),
          role,
        });
        await admin.firestore().collection("users").doc(userId).delete();
        await roleRequestRef.update({ status: "approved" });
        console.log(`[RBAC] Role approved for user ${userId}: ${role}`);
        res.status(200).json({ success: true, message: "Role approved" });
      } else {
        console.log(`[RBAC] User not found: ${userId}`);
        res.status(404).json({ success: false, message: "User not found" });
      }
    } else {
      await roleRequestRef.update({ status: "rejected" });
      console.log(`[RBAC] Role request rejected for user ${userId}: ${role}`);
      res.status(200).json({ success: true, message: "Role request rejected" });
    }
  } catch (error) {
    console.error(`[RBAC] Approve role error for user ${userId}:`, error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// --- Create HTTP server and Socket.IO server ---
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*", // Adjust for production to your frontend domain
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
const PORT = process.env.PORT || 4200;
server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});