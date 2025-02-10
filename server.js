const express = require("express");
const mongoose = require("mongoose");
const { google } = require("googleapis");
const cors = require("cors");
const dotenv = require("dotenv");
const passport = require("passport");
const session = require("express-session");
const { Strategy: GoogleStrategy } = require("passport-google-oauth20");
const { WebSocketServer } = require('ws');
const MongoStore = require('connect-mongo');

dotenv.config();

const app = express();
const wss = new WebSocketServer({ port: 8080 });

app.use(cors({
  origin: process.env.CORS_ORIGIN || "http://localhost:3000",
  credentials: true
}));

app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 24 }
  })
);

app.use(passport.initialize());
app.use(passport.session());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection error:", err));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:5000/api/auth/google/callback",
  passReqToCallback: true
}, 
async (req, accessToken, refreshToken, profile, done) => {
  try {
    const db = mongoose.connection.db;
    const user = await db.collection('users').findOneAndUpdate(
      { googleId: profile.id },
      {
        $set: { 
          accessToken,
          refreshToken,
          lastLogin: new Date(),
          email: profile.emails[0].value
        }
      },
      { upsert: true, returnDocument: 'after' }
    );

    if (user.value) {
      watchEmails(user.value._id, accessToken, refreshToken);
      return done(null, user.value);
    } else {
      return done(null, false);
    }
  } catch (error) {
    return done(error);
  }
}));

// Email Watch Function (Prevents Redundant Calls)
const activeUsers = new Set();

async function watchEmails(userId, accessToken, refreshToken) {
  if (activeUsers.has(userId.toString())) return;
  activeUsers.add(userId.toString());

  const auth = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
  auth.setCredentials({ access_token: accessToken });

  const gmail = google.gmail({ version: 'v1', auth });
  let lastHistoryId = null;

  setInterval(async () => {
    try {
      const res = await gmail.users.history.list({ userId: 'me', startHistoryId: lastHistoryId });
      
      if (res.data.history) {
        wss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN && client.userId === userId.toString()) {
            client.send(JSON.stringify({ type: 'new-emails' }));
          }
        });
        lastHistoryId = res.data.historyId;
      }
    } catch (error) {
      console.error('Email watch error:', error.message);
    }
  }, 15000);
}

// WebSocket Authentication
wss.on('connection', (ws, req) => {
  const userId = new URL(req.url, `http://${req.headers.host}`).searchParams.get("userId");
  if (!userId) {
    ws.close();
    return;
  }
  ws.userId = userId;
});

// Serialization / Deserialization
passport.serializeUser((user, done) => done(null, user._id));
passport.deserializeUser(async (id, done) => {
  try {
    const db = mongoose.connection.db;
    const user = await db.collection('users').findOne({ _id: new mongoose.Types.ObjectId(id) });
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Routes
app.get('/api/auth/google', passport.authenticate('google', {
  scope: ['email', 'profile', 'https://www.googleapis.com/auth/gmail.readonly'],
  accessType: 'offline',
  prompt: 'consent'
}));

app.get('/api/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(process.env.FRONTEND_URI || 'http://localhost:3000');
});

app.get('/api/emails', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  try {
    const auth = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
    auth.setCredentials({ access_token: req.user.accessToken, refresh_token: req.user.refreshToken });

    const gmail = google.gmail({ version: 'v1', auth });
    const response = await gmail.users.messages.list({ userId: 'me', maxResults: 10, labelIds: ['INBOX'] });

    const messages = response.data.messages || [];
    const emails = await Promise.all(messages.map(async (msg) => {
      const email = await gmail.users.messages.get({ userId: 'me', id: msg.id, format: 'metadata' });
      return {
        id: email.data.id,
        subject: email.data.payload.headers.find(h => h.name === 'Subject')?.value,
        snippet: email.data.snippet,
        date: email.data.payload.headers.find(h => h.name === 'Date')?.value
      };
    }));

    res.json(emails);
  } catch (error) {
    console.error('Email fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch emails' });
  }
});

app.get('/api/auth/logout', (req, res) => {
  req.logout(err => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    req.session.destroy(err => {
      if (err) console.error('Session destruction error:', err);
      res.clearCookie('connect.sid');
      res.redirect(process.env.FRONTEND_URI || 'http://localhost:3000');
    });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
