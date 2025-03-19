import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import session from "express-session";
import { ImapFlow } from "imapflow";
import MongoStore from "connect-mongo";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.use(
  cors({
    origin: process.env.FRONTEND_URI || "http://localhost:5173",
    credentials: true,
  })
);

app.use(express.json());

// ✅ Session Configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

// ✅ MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ✅ Login Route for User Credentials
app.post("/api/login", (req, res) => {
  const { email, appPassword } = req.body;

  if (!email || !appPassword) {
    return res.status(400).json({ error: "Email and app password are required" });
  }

  req.session.imapCredentials = { email, appPassword };
  res.json({ success: true });
});

// ✅ Fetch Emails Using IMAP
app.get("/api/emails", async (req, res) => {
  if (!req.session.imapCredentials) {
    return res.status(401).json({ error: "User not logged in" });
  }

  const { email, appPassword } = req.session.imapCredentials;

  try {
    const client = new ImapFlow({
      host: "imap.gmail.com",
      port: 993,
      secure: true,
      auth: {
        user: email,
        pass: appPassword,
      },
    });

    await client.connect();

    let mailbox = await client.mailboxOpen("INBOX");
    let emails = [];

    for await (let message of client.fetch(`1:*`, { envelope: true, bodyStructure: true })) {
      emails.push({
        id: message.uid,
        subject: message.envelope.subject || "No Subject",
        from: message.envelope.from?.[0]?.address || "Unknown",
        date: message.envelope.date || "Unknown",
      });
    }

    await client.logout();

    res.json(emails);
  } catch (error) {
    console.error("❌ Error fetching emails:", error.message);
    res.status(500).json({ error: "Failed to fetch emails" });
  }
});

// ✅ Serve React Frontend
app.use(express.static(path.join(__dirname, "dist")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "dist", "index.html"));
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
