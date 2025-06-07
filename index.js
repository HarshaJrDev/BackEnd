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

// --- Firebase Admin SDK Initialization ---
let firebaseConfig;

if (process.env.NODE_ENV === 'production' && process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
  // In production, parse the JSON string from the environment variable
  try {
    firebaseConfig = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
    console.log("Firebase Admin SDK: Using credentials from environment variable.");
  } catch (e) {
    console.error("ERROR: Failed to parse FIREBASE_SERVICE_ACCOUNT_KEY environment variable. Please ensure it's valid JSON.", e);
    // Exit the process if essential credentials can't be loaded in production
    process.exit(1);
  }
} else if (process.env.NODE_ENV !== 'production' && process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    // For local development, if GOOGLE_APPLICATION_CREDENTIALS is set, Admin SDK can auto-discover the key file path
    console.log("Firebase Admin SDK: Using GOOGLE_APPLICATION_CREDENTIALS for local development.");
    // We don't need to load firebaseConfig explicitly here if GOOGLE_APPLICATION_CREDENTIALS is used
    // as admin.initializeApp() will pick it up automatically.
} else {
  // Fallback for local development if not using GOOGLE_APPLICATION_CREDENTIALS.
  // This expects serviceAccountKey.json to be present in the same directory.
  // IMPORTANT: Do NOT commit serviceAccountKey.json to your public repository for production!
  try {
    firebaseConfig = require("./serviceAccountKey.json");
    console.log("Firebase Admin SDK: Using local serviceAccountKey.json file.");
  } catch (e) {
    console.error("ERROR: serviceAccountKey.json not found. For production, use FIREBASE_SERVICE_ACCOUNT_KEY environment variable. For local, ensure the file exists or set GOOGLE_APPLICATION_CREDENTIALS.", e);
    process.exit(1);
  }
}

// Initialize Firebase Admin SDK with the loaded credentials
// If GOOGLE_APPLICATION_CREDENTIALS is set, admin.initializeApp() will use it directly.
if (firebaseConfig) {
  admin.initializeApp({
    credential: admin.credential.cert(firebaseConfig),
    // If you plan to use Firebase Realtime Database, uncomment and set your databaseURL
    // databaseURL: `https://${process.env.FIREBASE_PROJECT_ID}.firebaseio.com`
  });
  console.log("Firebase Admin SDK initialized successfully.");
} else if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) { // If neither service account JSON nor GOOGLE_APPLICATION_CREDENTIALS were found
  console.error("ERROR: Firebase Admin SDK could not be initialized due to missing credentials. Please set FIREBASE_SERVICE_ACCOUNT_KEY or GOOGLE_APPLICATION_CREDENTIALS.");
  process.exit(1);
} else {
    // If GOOGLE_APPLICATION_CREDENTIALS was set, firebaseConfig would be null here, but init should still work.
    // This block is for robustness in case app.initializeApp() without args fails silently.
    try {
        admin.initializeApp();
        console.log("Firebase Admin SDK initialized successfully using GOOGLE_APPLICATION_CREDENTIALS.");
    } catch (e) {
        console.error("ERROR: Firebase Admin SDK could not be initialized with GOOGLE_APPLICATION_CREDENTIALS:", e);
        process.exit(1);
    }
}
// --- END Firebase Admin SDK Initialization ---

const app = express();
app.use(express.json()); // Middleware to parse JSON request bodies
app.use(cors()); // Enable CORS for all routes

// In-memory store for OTPs (for demonstration purposes, consider a more persistent store in production)
const otpStore = new Map();
// Basic email validation regex
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// Rate limiter for OTP sending to prevent abuse
const otpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 3, // Max 3 requests per IP per hour
  message: {
    success: false,
    message: "Too many OTP requests from this IP, please try again in an hour.",
    remaining: 0,
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false,  // Disable the `X-RateLimit-*` headers
});
app.use("/send-otp", otpLimiter); // Apply rate limiter to the /send-otp endpoint

// Middleware to authenticate requests using Firebase ID tokens
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, message: "Unauthorized: No token provided." });
  }
  const idToken = authHeader.split("Bearer ")[1];
  try {
    // Verify the ID token using Firebase Admin SDK
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken; // Attach decoded token to request object
    next(); // Proceed to the next middleware/route handler
  } catch (error) {
    console.error("[Auth] Authentication error:", error);
    res.status(401).json({ success: false, message: "Unauthorized: Invalid or expired token." });
  }
};

// --- API Endpoints ---

// Endpoint to send OTP via email
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ success: false, message: "Invalid or missing email address." });
  }
  const otp = Math.floor(100000 + Math.random() * 900000); // Generate a 6-digit OTP
  const expiresAt = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes
  try {
    await sendOTP(email, otp); // Call your mailer utility to send the OTP
    otpStore.set(email, { otp: String(otp), expiresAt }); // Store OTP (in-memory)
    return res.status(200).json({ success: true, message: "OTP sent successfully. Check your email." });
  } catch (error) {
    console.error("[OTP] Failed to send OTP:", error);
    return res.status(500).json({ success: false, message: "Failed to send OTP. Please try again." });
  }
});

// Endpoint to verify OTP
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore.get(email);
  if (!record || Date.now() > record.expiresAt || String(record.otp) !== String(otp)) {
    return res.status(400).json({ success: false, message: "Invalid or expired OTP." });
  }
  otpStore.delete(email); // Remove OTP after successful verification
  return res.status(200).json({ success: true, message: "OTP verified successfully." });
});

// Endpoint for users to request a specific role (e.g., 'driver', 'admin')
app.post("/request-role", authenticate, async (req, res) => {
  const { role } = req.body;
  const userId = req.user.uid; // User ID from authenticated token
  if (!["driver", "admin"].includes(role)) {
    return res.status(400).json({ success: false, message: "Invalid role requested. Must be 'driver' or 'admin'." });
  }
  try {
    // Store role request in Firestore
    await admin.firestore().collection("roleRequests").doc(userId).set({
      userId,
      requestedRole: role,
      status: "pending", // Initial status
      requestedAt: new Date(),
    });
    res.status(200).json({ success: true, message: `Role request for '${role}' submitted successfully. Awaiting admin approval.` });
  } catch (error) {
    console.error("[RoleRequest] Server error:", error);
    res.status(500).json({ success: false, message: "Server error submitting role request." });
  }
});

// Endpoint for admins to approve or reject role requests
app.post("/approve-role", authenticate, async (req, res) => {
  const { userId, role, approve } = req.body; // 'approve' is a boolean
  try {
    // First, verify that the requester is an admin.
    // This assumes you have a 'admins' collection where admin UIDs are stored.
    const requesterDoc = await admin.firestore().collection("admins").doc(req.user.uid).get();
    if (!requesterDoc.exists) {
      return res.status(403).json({ success: false, message: "Admin access required to perform this action." });
    }

    if (!["driver", "admin"].includes(role)) {
      return res.status(400).json({ success: false, message: "Invalid role specified for approval/rejection." });
    }

    const roleRequestRef = admin.firestore().collection("roleRequests").doc(userId);
    const roleRequest = await roleRequestRef.get();

    // Check if the role request exists and matches the requested role
    if (!roleRequest.exists || roleRequest.data().requestedRole !== role) {
      return res.status(404).json({ success: false, message: "Role request not found or role mismatch." });
    }

    if (approve) {
      const userDoc = await admin.firestore().collection("users").doc(userId).get();
      if (userDoc.exists) {
        // Move user data to the appropriate role collection (e.g., 'drivers' or 'admins')
        // Using 'set' with merge:true is safer to avoid overwriting existing fields
        await admin.firestore().collection(role + "s").doc(userId).set({
            ...userDoc.data(),
            role, // Assign the approved role
            // You might also add a timestamp for when the role was approved
            approvedAt: new Date(),
        }, { merge: true });

        // Optionally, if roles are mutually exclusive, delete the user from the generic 'users' collection
        // await admin.firestore().collection("users").doc(userId).delete();

        // Update the status of the role request
        await roleRequestRef.update({ status: "approved", approvedBy: req.user.uid, approvedAt: new Date() });
        res.status(200).json({ success: true, message: `Role '${role}' approved for user ${userId}.` });
      } else {
        res.status(404).json({ success: false, message: "Target user not found for role approval." });
      }
    } else {
      // If not approved, just update the status to 'rejected'
      await roleRequestRef.update({ status: "rejected", rejectedBy: req.user.uid, rejectedAt: new Date() });
      res.status(200).json({ success: true, message: `Role request for user ${userId} rejected.` });
    }
  } catch (error) {
    console.error("[ApproveRole] Server error:", error);
    res.status(500).json({ success: false, message: `Server error processing role approval: ${error.message}` });
  }
});

// --- Push Notification Endpoint ---
app.post("/send-notifications", async (req, res) => {
  const { bookingId, bookingData } = req.body;

  if (!bookingId) {
    return res.status(400).json({ success: false, message: "Missing bookingId in request." });
  }

  try {
    // Fetch all driver FCM tokens from your 'drivers' collection
    const driversSnapshot = await admin.firestore().collection("drivers").get();
    const tokens = [];
    driversSnapshot.forEach((doc) => {
      const token = doc.data()?.fcmToken; // Ensure 'fcmToken' is the correct field name in your driver documents
      if (token) tokens.push(token);
    });

    if (tokens.length === 0) {
      // Respond successfully if no tokens are found, as no error occurred
      return res.status(200).json({ success: true, message: "No driver tokens found to send notifications.", fcmResponse: { successCount: 0, failureCount: 0 } });
    }

    // Construct the FCM message payload
    const message = {
      tokens, // Array of recipient FCM tokens
      notification: {
        title: "📦 New Booking Request",
        body: "A new delivery is available. Tap to view details and accept!",
      },
      data: {
        screen: "BookingDetails", // Client-side app can use this for navigation
        bookingId: String(bookingId), // Ensure all data fields are strings
        // You can add more stringified booking details here if needed on the client side
        // e.g., pickupAddress: JSON.stringify(bookingData.pickup.address),
        // dropAddress: JSON.stringify(bookingData.drop.address),
      },
      // You can add other options like 'apns' for iOS specific settings
      // or 'android' for Android specific settings if needed
    };

    // Send the multicast message using Firebase Admin SDK
    const response = await admin.messaging().sendMulticast(message);

    console.log(`[FCM Admin] Sent ${response.successCount} notifications, failed for ${response.failureCount}.`);

    res.status(200).json({
      success: true,
      message: `Notifications sent successfully to ${response.successCount} drivers. Failed for ${response.failureCount}.`,
      fcmResponse: response, // Provide the full FCM response for detailed debugging
    });
  } catch (err) {
    console.error("[FCM Admin] Error sending notifications:", err);
    // Return a 500 status for server-side errors during notification sending
    res.status(500).json({ success: false, message: err.message || "Internal Server Error during notification sending." });
  }
});

// --- Socket.IO Setup (for real-time communication) ---
const server = http.createServer(app); // Create an HTTP server from the Express app
const io = new Server(server, {
  cors: {
    origin: "*", // WARNING: Use specific origins in production, e.g., "https://your-frontend-domain.com"
    methods: ["GET", "POST"],
  },
});

// Socket.IO connection handling
io.on("connection", (socket) => {
  console.log(`[Socket.IO] Client connected: ${socket.id}`);

  // Handle 'join_room' event for users to join specific chat rooms (e.g., for a booking)
  socket.on("join_room", (roomId) => {
    socket.join(roomId);
    console.log(`[Socket.IO] Client ${socket.id} joined room: ${roomId}`);
  });

  // Handle 'send_message' event to broadcast messages within a room
  socket.on("send_message", ({ roomId, message, senderId }) => {
    console.log(`[Socket.IO] Message from ${senderId} to room ${roomId}: ${message}`);
    // Emit 'receive_message' to all clients in the room EXCEPT the sender
    socket.to(roomId).emit("receive_message", { message, senderId, timestamp: new Date().toISOString() });
  });

  // Handle client disconnection
  socket.on("disconnect", () => {
    console.log(`[Socket.IO] Client disconnected: ${socket.id}`);
  });
});

// --- Start the Server ---
const PORT = process.env.PORT || 4200; // Use port from environment variable or default to 4200
server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});