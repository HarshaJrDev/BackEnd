const express = require("express");
const sendPushNotification = require("./utility/PushNotification");
const router = express.Router();

// Dummy DB logic, replace with real user DB access
const users = new Map(); // email -> { fcmToken, ... }

router.post("/approve-document", async (req, res) => {
  const { email, documentType } = req.body;
  // 1. Update DB to mark document as approved (pseudo-code)
  // await updateUserDocumentStatus(email, documentType, 'approved');

  // 2. Get user's FCM token (replace with real DB lookup)
  const user = users.get(email);
  if (!user || !user.fcmToken) {
    return res.status(404).json({ success: false, message: "User or FCM token not found." });
  }

  // 3. Send push notification
  try {
    await sendPushNotification(user.fcmToken, {
      title: "Document Approved!",
      body: `Your ${documentType} has been approved. You can now log in.`,
      data: { documentType },
    });
    res.json({ success: true, message: "User notified successfully." });
  } catch (err) {
    console.error("[Push] Error sending notification:", err);
    res.status(500).json({ success: false, message: "Failed to send notification." });
  }
});

module.exports = router;