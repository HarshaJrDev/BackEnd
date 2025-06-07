const fetch = require("node-fetch"); // npm install node-fetch@2

const FCM_SERVER_KEY = process.env.FCM_SERVER_KEY || "YOUR_FCM_SERVER_KEY"; // Set in .env

async function sendPushNotification(token, { title, body, data }) {
  const payload = {
    to: token,
    notification: { title, body },
    data: data || {},
  };

  const response = await fetch("https://fcm.googleapis.com/fcm/send", {
    method: "POST",
    headers: {
      "Authorization": "key=" + FCM_SERVER_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`FCM error: ${response.status} - ${text}`);
  }
  return await response.json();
}

module.exports = sendPushNotification;