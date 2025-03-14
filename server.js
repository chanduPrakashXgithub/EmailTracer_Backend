const express = require("express");
const mongoose = require("mongoose");
const { google } = require("googleapis");
const cors = require("cors");
const dotenv = require("dotenv");
const passport = require("passport");
const session = require("express-session");
const { Strategy: GoogleStrategy } = require("passport-google-oauth20");
const { WebSocketServer } = require("ws");
const MongoStore = require("connect-mongo");

dotenv.config();

const app = express();
const wss = new WebSocketServer({ port: 8080 });

// ✅ CORS Configuration
app.use(cors({
  origin: process.env.FRONTEND_URI || "http://localhost:5173",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// ✅ Session Configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use(express.json());
app.use(passport.initialize());
app.use(passport.session());

// ✅ MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// ✅ User Schema
const User = mongoose.model("User", new mongoose.Schema({
  googleId: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  accessToken: String,
  refreshToken: String,
  historyId: String,  
  lastLogin: Date
}));

// ✅ Google Authentication Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
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

  const auth = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
  auth.setCredentials({ access_token: user.accessToken });

  const gmail = google.gmail({ version: 'v1', auth });
  let lastHistoryId = user.historyId || null;

  setInterval(async () => {
    try {
      if (!user.accessToken) await refreshAccessToken(user);

      const res = await gmail.users.history.list({ userId: 'me', startHistoryId: lastHistoryId });

      if (res.data.history) {
        lastHistoryId = res.data.historyId;
        user.historyId = lastHistoryId;
        await user.save();

        wss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN && client.userId === user.googleId) {
            client.send(JSON.stringify({ type: 'new-emails' }));
          }
        });
      }
    } catch (error) {
      console.error('❌ Email watch error:', error.message);
    }
  }, 15000);
}

// ✅ WebSocket Handling
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const userId = url.searchParams.get("userId");

  if (!userId) {
    ws.close();
    return;
  }

  ws.userId = userId;
});

// ✅ Routes
app.get('/api/auth/google', passport.authenticate('google', {
  scope: ['email', 'profile', 'https://www.googleapis.com/auth/gmail.readonly'],
  accessType: 'offline',
  prompt: 'consent',
}));

app.get('/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: process.env.FRONTEND_URI + '/login' }),
  (req, res) => {
    res.redirect(process.env.FRONTEND_URI || 'http://localhost:5173');
  }
);

app.get('/api/emails', async (req, res) => {
  if (!req.user) {
    console.log("❌ User not authenticated");
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    if (!req.user.accessToken) {
      console.log("❌ No access token found, trying to refresh...");
      await refreshAccessToken(req.user);
    }

    const auth = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
    auth.setCredentials({ access_token: req.user.accessToken });

    const gmail = google.gmail({ version: 'v1', auth });
    const response = await gmail.users.messages.list({ userId: 'me', maxResults: 10 });

    const messages = response.data.messages || [];
    const emails = await Promise.all(messages.map(async (msg) => {
      const email = await gmail.users.messages.get({ userId: 'me', id: msg.id });
      return {
        id: email.data.id,
        subject: email.data.payload.headers.find(h => h.name === 'Subject')?.value,
        snippet: email.data.snippet,
        date: email.data.payload.headers.find(h => h.name === 'Date')?.value
      };
    }));

    res.json(emails);
  } catch (error) {
    console.error("❌ Error fetching emails:", error.message);
    res.status(500).json({ error: 'Failed to fetch emails' });
  }
});

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

// ✅ Server Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
