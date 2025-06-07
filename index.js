// backend/index.js (or your main server file)
const express = require("express");
const dotenv = require("dotenv");
const admin = require("firebase-admin"); // Firebase Admin SDK
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const sendOTP = require("./mailer"); // Assuming this is your mailer utility

// Load environment variables from .env file (for local development)
dotenv.config();

// --- START FIX ---

// Initialize Firebase Admin SDK
// It's crucial to load service account credentials securely.
let firebaseConfig;

if (process.env.NODE_ENV === 'production' && process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
  // In production, parse the JSON string from the environment variable
  try {
    firebaseConfig = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
    console.log("Firebase Admin SDK: Using credentials from environment variable.");
  } catch (e) {
    console.error("ERROR: Failed to parse FIREBASE_SERVICE_ACCOUNT_KEY environment variable. Please ensure it's valid JSON.", e);
    // Exit or throw an error if essential service account credentials can't be loaded
    process.exit(1);
  }
} else if (process.env.NODE_ENV !== 'production' && process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    // For local development, if GOOGLE_APPLICATION_CREDENTIALS is set
    // This allows Google's libraries to auto-discover the key file path
    console.log("Firebase Admin SDK: Using GOOGLE_APPLICATION_CREDENTIALS for local development.");
}
else {
  // Fallback for local development if not using GOOGLE_APPLICATION_CREDENTIALS,
  // or if FIREBASE_SERVICE_ACCOUNT_KEY is not set in production.
  // This expects serviceAccountKey.json to be present in the same directory.
  // IMPORTANT: Do NOT commit serviceAccountKey.json to your repository for production!
  try {
    firebaseConfig = require("./serviceAccountKey.json");
    console.log("Firebase Admin SDK: Using local serviceAccountKey.json file.");
  } catch (e) {
    console.error("ERROR: serviceAccountKey.json not found. For production, use FIREBASE_SERVICE_ACCOUNT_KEY environment variable. For local, ensure the file exists.", e);
    process.exit(1);
  }
}

// Initialize Firebase Admin SDK with the loaded credentials
if (firebaseConfig) {
  admin.initializeApp({
    credential: admin.credential.cert(firebaseConfig),
    // If you plan to use Realtime Database, uncomment and set your databaseURL
    // databaseURL: `https://${process.env.FIREBASE_PROJECT_ID}.firebaseio.com`
  });
  console.log("Firebase Admin SDK initialized successfully.");
} else {
  console.error("ERROR: Firebase Admin SDK could not be initialized due to missing credentials.");
  process.exit(1);
}

// --- END FIX ---

const app = express();
app.use(express.json());
app.use(cors());

const otpStore = new Map();
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const otpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
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
    console.error("[OTP] Failed to send OTP:", error);
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
    console.error("[RoleRequest] Server error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/approve-role", authenticate, async (req, res) => {
  const { userId, role, approve } = req.body;
  try {
    // Authenticate the admin by checking if their UID exists in the 'admins' collection
    const requester = await admin.firestore().collection("admins").doc(req.user.uid).get();
    if (!requester.exists) {
      return res.status(403).json({ success: false, message: "Admin access required" });
    }

    if (!["driver", "admin"].includes(role)) {
      return res.status(400).json({ success: false, message: "Invalid role" });
    }

    const roleRequestRef = admin.firestore().collection("roleRequests").doc(userId);
    const roleRequest = await roleRequestRef.get();

    if (!roleRequest.exists || roleRequest.data().requestedRole !== role) {
      return res.status(404).json({ success: false, message: "Role request not found or role mismatch" });
    }

    if (approve) {
      const userDoc = await admin.firestore().collection("users").doc(userId).get();
      if (userDoc.exists) {
        // Move user data to the appropriate role collection (e.g., 'drivers' or 'admins')
        await admin.firestore().collection(role + "s").doc(userId).set({ ...userDoc.data(), role });
        // Optionally delete from 'users' collection if roles are mutually exclusive
        await admin.firestore().collection("users").doc(userId).delete();
        await roleRequestRef.update({ status: "approved" });
        res.status(200).json({ success: true, message: "Role approved" });
      } else {
        res.status(404).json({ success: false, message: "User not found" });
      }
    } else {
      // If not approved, just update the status to 'rejected'
      await roleRequestRef.update({ status: "rejected" });
      res.status(200).json({ success: true, message: "Role request rejected" });
    }
  } catch (error) {
    console.error("[ApproveRole] Server error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// --- Push Notification Endpoint ---
app.post("/send-notifications", async (req, res) => {
  const { bookingId, bookingData } = req.body;

  if (!bookingId) {
    return res.status(400).json({ success: false, message: "Missing bookingId" });
  }

  try {
    const driversSnapshot = await admin.firestore().collection("drivers").get();
    const tokens = [];
    driversSnapshot.forEach((doc) => {
      const token = doc.data()?.fcmToken; // Make sure 'fcmToken' is the correct field name
      if (token) tokens.push(token);
    });

    if (tokens.length === 0) {
      // It's a success in that no error occurred, but no notifications were sent
      return res.status(200).json({ success: true, message: "No driver tokens found to send notifications." });
    }

    // Prepare the multicast message
    const message = {
      tokens,
      notification: {
        title: "📦 New Booking Request",
        body: "A new delivery is available. Tap to view details.",
      },
      data: {
        screen: "BookingDetails", // This can be used by your client app to navigate
        bookingId: String(bookingId),
        // Stringify other bookingData fields if they are complex objects to ensure they are sent as strings
        // Example: if bookingData has a 'pickupAddress' object, you might do:
        // pickupAddress: JSON.stringify(bookingData.pickupAddress),
        // ... and so on for other relevant booking details
      },
    };

    const response = await admin.messaging().sendMulticast(message);

    res.status(200).json({
      success: true,
      message: `Notification sent to ${response.successCount} drivers successfully. Failed for ${response.failureCount}.`,
      // You might want to log or return `response.responses` for failed tokens
      fcmResponse: response, // Include the full FCM response for debugging if needed
    });
  } catch (err) {
    console.error("[FCM Admin] Error sending notifications:", err);
    // Send a more specific error message if available, or a generic one
    res.status(500).json({ success: false, message: err.message || "Internal Server Error during notification sending." });
  }
});

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // Be more specific in production, e.g., "https://your-frontend-domain.com"
    methods: ["GET", "POST"],
  },
});

io.on("connection", (socket) => {
  console.log(`[Socket.IO] Client connected: ${socket.id}`);
  socket.on("join_room", (roomId) => {
    socket.join(roomId);
    console.log(`[Socket.IO] Client ${socket.id} joined room: ${roomId}`);
  });
  socket.on("send_message", ({ roomId, message, senderId }) => {
    console.log(`[Socket.IO] Message from ${senderId} to room ${roomId}: ${message}`);
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