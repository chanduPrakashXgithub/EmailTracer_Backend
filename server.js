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
  origin: process.env.FRONTEND_URI,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

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
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      passReqToCallback: true,
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

// ✅ Google OAuth Routes
app.get('/api/auth/google', 
  passport.authenticate('google', { 
    scope: ['email', 'profile', 'https://www.googleapis.com/auth/gmail.readonly'],
    accessType: 'offline',
    prompt: 'consent'
  })
);

app.get('/api/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: `${process.env.FRONTEND_URI}/login` }),
  (req, res) => {
    res.redirect(process.env.FRONTEND_URI);
  }
);

// ✅ Login Route
app.get('/login', (req, res) => {
  res.redirect(`${process.env.FRONTEND_URI}/login`);
});

// ✅ Fetch Emails Route
app.get('/api/emails', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  try {
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
    console.error("Error fetching emails:", error.message);
    res.status(500).json({ error: "Failed to fetch emails" });
  }
});

// ✅ Catch-All Route for 404
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// ✅ Server Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
