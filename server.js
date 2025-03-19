import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import session from "express-session";
import MongoStore from "connect-mongo";
import path from "path";
import { fileURLToPath } from "url";
import Imap from "imap";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ✅ CORS Configuration
app.use(
  cors({
    origin: process.env.FRONTEND_URI,
    credentials: true,
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

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
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

app.use(express.json());

// ✅ MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ✅ Login Route
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const imap = new Imap({
    user: email,
    password: password,
    host: process.env.IMAP_HOST,
    port: process.env.IMAP_PORT,
    tls: true,
  });

  imap.once("ready", () => {
    console.log("✅ IMAP connection established");
    req.session.email = email;
    req.session.password = password;
    imap.end();
    res.json({ success: true });
  });

  imap.once("error", (err) => {
    console.error("❌ IMAP connection failed:", err.message);
    res.status(401).json({ error: "Invalid email or password." });
  });

  imap.connect();
});

// ✅ Fetch Emails Route
app.get("/api/emails", (req, res) => {
  const { email, password } = req.session;

  if (!email || !password) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const imap = new Imap({
    user: email,
    password: password,
    host: process.env.IMAP_HOST,
    port: process.env.IMAP_PORT,
    tls: true,
  });

  imap.once("ready", () => {
    imap.openBox("INBOX", true, (err, box) => {
      if (err) {
        console.error("❌ Failed to open inbox:", err.message);
        return res.status(500).json({ error: "Failed to open inbox" });
      }

      const fetch = imap.seq.fetch("1:10", {
        bodies: ["HEADER.FIELDS (FROM TO SUBJECT DATE)", "TEXT"],
        struct: true,
      });

      const emails = [];

      fetch.on("message", (msg) => {
        const email = {};
        msg.on("body", (stream, info) => {
          let buffer = "";
          stream.on("data", (chunk) => {
            buffer += chunk.toString("utf8");
          });

          stream.on("end", () => {
            if (info.which.includes("HEADER")) {
              email.headers = Imap.parseHeader(buffer);
            } else {
              email.body = buffer;
            }
          });
        });

        msg.once("end", () => {
          emails.push(email);
        });
      });

      fetch.once("end", () => {
        res.json(emails);
        imap.end();
      });
    });
  });

  imap.once("error", (err) => {
    console.error("❌ Email fetching error:", err.message);
    res.status(500).json({ error: "Failed to fetch emails" });
  });

  imap.connect();
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);
