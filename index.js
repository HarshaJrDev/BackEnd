// ... (All your existing imports)
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

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
app.use(express.json());
app.use(cors());

const otpStore = new Map();
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const otpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: {
    success: false,
    message: "Too many requests from this IP, please try again in an hour.",
    remaining: 0,
  },
});
app.use("/send-otp", otpLimiter);

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

app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ success: false, message: "Invalid or missing email address." });
  }
  const otp = Math.floor(100000 + Math.random() * 900000);
  const expiresAt = Date.now() + 10 * 60 * 1000;
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
  const record = otpStore.get(email);
  if (!record || Date.now() > record.expiresAt || String(record.otp) !== String(otp)) {
    return res.status(400).json({ success: false, message: "Invalid or expired OTP." });
  }
  otpStore.delete(email);
  return res.status(200).json({ success: true, message: "OTP verified successfully." });
});

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
    res.status(200).json({ success: true, message: "Role request submitted" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/approve-role", authenticate, async (req, res) => {
  const { userId, role, approve } = req.body;
  const requester = await admin.firestore().collection("admins").doc(req.user.uid).get();
  if (!requester.exists) {
    return res.status(403).json({ success: false, message: "Admin access required" });
  }
  if (!["driver", "admin"].includes(role)) {
    return res.status(400).json({ success: false, message: "Invalid role" });
  }
  try {
    const roleRequestRef = admin.firestore().collection("roleRequests").doc(userId);
    const roleRequest = await roleRequestRef.get();
    if (!roleRequest.exists || roleRequest.data().requestedRole !== role) {
      return res.status(404).json({ success: false, message: "Role request not found" });
    }
    if (approve) {
      const userDoc = await admin.firestore().collection("users").doc(userId).get();
      if (userDoc.exists) {
        await admin.firestore().collection(role + "s").doc(userId).set({ ...userDoc.data(), role });
        await admin.firestore().collection("users").doc(userId).delete();
        await roleRequestRef.update({ status: "approved" });
        res.status(200).json({ success: true, message: "Role approved" });
      } else {
        res.status(404).json({ success: false, message: "User not found" });
      }
    } else {
      await roleRequestRef.update({ status: "rejected" });
      res.status(200).json({ success: true, message: "Role request rejected" });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// --- Push Notification Endpoint ---
app.post("/send-notifications", async (req, res) => {
  const { bookingId, bookingData } = req.body;
  try {
    const driversSnapshot = await admin.firestore().collection("drivers").get();
    const tokens = [];
    driversSnapshot.forEach((doc) => {
      const token = doc.data()?.fcmToken;
      if (token) tokens.push(token);
    });
    if (tokens.length === 0) {
      return res.status(200).json({ success: false, message: "No driver tokens found" });
    }
    const message = {
      notification: {
        title: "\ud83d\udce6 New Booking Request",
        body: "A new delivery is available. Tap to view details.",
      },
      data: {
        screen: "BookingDetails",
        bookingId: bookingId,
      },
      tokens: tokens,
    };
    const response = await admin.messaging().sendMulticast(message);
    res.status(200).json({ success: true, message: `Sent to ${response.successCount} drivers`, response });
  } catch (err) {
    console.error("[FCM Admin] Error:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

io.on("connection", (socket) => {
  console.log(`[Socket.IO] Client connected: ${socket.id}`);
  socket.on("join_room", (roomId) => socket.join(roomId));
  socket.on("send_message", ({ roomId, message, senderId }) => {
    socket.to(roomId).emit("receive_message", { message, senderId });
  });
  socket.on("disconnect", () => {
    console.log(`[Socket.IO] Client disconnected: ${socket.id}`);
  });
});

const PORT = process.env.PORT || 4200;
server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});