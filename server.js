import express from "express";
import mongoose from "mongoose";
import { google } from "googleapis";
import cors from "cors";
import dotenv from "dotenv";
import passport from "passport";
import session from "express-session";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { WebSocketServer } from "ws";
import MongoStore from "connect-mongo";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const wss = new WebSocketServer({ port: 8080 });

// ✅ CORS Configuration
app.use(
  cors({
    origin: process.env.FRONTEND_URI || "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
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
      secure: process.env.NODE_ENV === "production", // ✅ Use secure cookies in production
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 1000 * 60 * 60 * 24, // ✅ 1 day
    },
  })
);

app.use(express.json());
app.use(passport.initialize());
app.use(passport.session());

// ✅ MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ✅ User Schema
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    googleId: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    accessToken: String,
    refreshToken: String,
    historyId: String,
    lastLogin: Date,
  })
);

// ✅ Google Authentication Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BACKEND_URI}/api/auth/google/callback`, // ✅ Dynamic Callback URL
      passReqToCallback: true,
      state: true,
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
          user = new User({
            googleId: profile.id,
            email: profile.emails[0].value,
            accessToken,
            refreshToken,
            lastLogin: new Date(),
          });
        } else {
          user.accessToken = accessToken;
          user.refreshToken = refreshToken;
          user.lastLogin = new Date();
        }

        await user.save();
        watchEmails(user);
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

// ✅ Passport Serialization
passport.serializeUser((user, done) => done(null, user._id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ✅ Token Refresh Function
async function refreshAccessToken(user) {
  try {
    console.log("🔄 Refreshing token...");
    const auth = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET
    );

    auth.setCredentials({ refresh_token: user.refreshToken });

    const { credentials } = await auth.refreshAccessToken();
    user.accessToken = credentials.access_token;
    user.lastLogin = new Date();

    await user.save();
    console.log("✅ Token refreshed successfully");
  } catch (error) {
    console.error("❌ Failed to refresh access token:", error.message);
  }
}

// ✅ Email Watch Function
const activeUsers = new Set();

async function watchEmails(user) {
  if (activeUsers.has(user.googleId)) return;
  activeUsers.add(user.googleId);

  const auth = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET
  );
  auth.setCredentials({ access_token: user.accessToken });

  const gmail = google.gmail({ version: "v1", auth });
  let lastHistoryId = user.historyId || null;

  setInterval(async () => {
    try {
      if (!user.accessToken) await refreshAccessToken(user);

      const res = await gmail.users.history.list({
        userId: "me",
        startHistoryId: lastHistoryId,
      });

      if (res.data.history) {
        lastHistoryId = res.data.historyId;
        user.historyId = lastHistoryId;
        await user.save();

        wss.clients.forEach((client) => {
          if (
            client.readyState === WebSocket.OPEN &&
            client.userId === user.googleId
          ) {
            client.send(JSON.stringify({ type: "new-emails" }));
          }
        });
      }
    } catch (error) {
      console.error("❌ Email watch error:", error.message);
    }
  }, 15000);
}

// ✅ WebSocket Handling
wss.on("connection", (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const userId = url.searchParams.get("userId");

  if (!userId) {
    ws.close();
    return;
  }

  ws.userId = userId;
});

// ✅ Routes
app.get(
  "/api/auth/google",
  passport.authenticate("google", {
    scope: ["email", "profile", "https://www.googleapis.com/auth/gmail.readonly"],
    accessType: "offline",
    prompt: "consent",
  })
);

app.get(
  "/api/auth/google/callback",
  passport.authenticate("google", { failureRedirect: `${process.env.FRONTEND_URI}/login` }),
  (req, res) => {
    res.redirect(process.env.FRONTEND_URI || "http://localhost:5173");
  }
);

app.get("/api/emails", async (req, res) => {
  if (!req.user) {
    console.log("❌ User not authenticated");
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    if (!req.user.accessToken) await refreshAccessToken(req.user);

    const auth = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET
    );
    auth.setCredentials({ access_token: req.user.accessToken });

    const gmail = google.gmail({ version: "v1", auth });
    const response = await gmail.users.messages.list({
      userId: "me",
      maxResults: 10,
    });

    const emails = await Promise.all(
      response.data.messages.map(async (msg) => {
        const email = await gmail.users.messages.get({ userId: "me", id: msg.id });
        return {
          id: email.data.id,
          subject: email.data.payload.headers.find((h) => h.name === "Subject")?.value,
          snippet: email.data.snippet,
          date: email.data.payload.headers.find((h) => h.name === "Date")?.value,
        };
      })
    );

    res.json(emails);
  } catch (error) {
    console.error("❌ Error fetching emails:", error.message);
    res.status(500).json({ error: "Failed to fetch emails" });
  }
});

// ✅ Catch-All Route for React
app.use((req, res) => {
  res.sendFile(path.join(__dirname, "dist", "index.html"));
});

// ✅ Server Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
