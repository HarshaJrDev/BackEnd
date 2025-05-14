require('dotenv').config();
const nodemailer = require("nodemailer");

const sendOTP = async (email, otp) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your OTP Code",
    text: `Your OTP code is ${otp}. It is valid for 10 minutes.`,
    html: `
      <div style="font-family: Arial, sans-serif; padding: 10px;">
        <h2>Your OTP Code</h2>
        <p><strong>${otp}</strong> is your one-time password.</p>
        <p>This code will expire in <strong>10 minutes</strong>.</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
};

module.exports = sendOTP;
