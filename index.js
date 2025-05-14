const express = require("express");
require("dotenv").config();
const sendOTP = require("./mailer");

const app = express();
app.use(express.json());

app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000);
  try {
    await sendOTP(email, otp);
    res.status(200).json({ message: "OTP sent", otp });
  } catch (err) {
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
