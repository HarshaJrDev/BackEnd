const express = require("express");
require("dotenv").config();
const sendOTP = require("./mailer");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());

// In-memory OTP store (can be replaced with MongoDB)
const otpStore = new Map();

// Rate limiting: max 3 requests per IP per hour
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: { error: "Too many requests from this IP, please try again later" }
});
app.use("/send-otp", limiter);

// Simple email validator
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ error: "Invalid or missing email" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000);
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

  try {
    await sendOTP(email, otp);

    // Save to in-memory store
    otpStore.set(email, { otp, expiresAt });

    res.status(200).json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("Failed to send OTP:", err);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

// Endpoint to verify OTP (optional)
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  const record = otpStore.get(email);
  if (!record) {
    return res.status(400).json({ error: "No OTP found for this email" });
  }

  if (Date.now() > record.expiresAt) {
    otpStore.delete(email);
    return res.status(400).json({ error: "OTP has expired" });
  }

  if (record.otp.toString() !== otp.toString()) {
    return res.status(400).json({ error: "Invalid OTP" });
  }

  otpStore.delete(email); // Invalidate OTP after successful use
  res.status(200).json({ message: "OTP verified successfully" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
