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
app.options("*", cors()); // ✅ Preflight handling

app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: { 
      secure: process.env.NODE_ENV === 'production', 
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 1000 * 60 * 60 * 24 
    }
  })
);

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

// ✅ Google Authentication
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:5000/api/auth/google/callback",
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

// ✅ Watch Emails
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
      console.error('Email watch error:', error.message);
    }
  }, 15000);
}

// ✅ WebSocket Handling
wss.on('connection', (ws, req) => {
  console.log("✅ WebSocket Connected");
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
  prompt: 'consent'
}));

app.get('/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: process.env.FRONTEND_URI + '/login' }),
  (req, res) => res.redirect(process.env.FRONTEND_URI || 'http://localhost:5173')
);

app.get('/login', (req, res) => {
  res.redirect(process.env.FRONTEND_URI || 'http://localhost:5173/login');
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
