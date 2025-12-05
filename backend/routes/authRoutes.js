const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");

const User = require("../models/User");           // ✅ correct
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const createToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
};

// 1. Email Signup
router.post("/signup", async (req, res) => {
  try {
    const { email, password, username } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hash = await bcrypt.hash(password, 10);

    const user = await User.create({
      name: username || null,
      email,
      password: hash,
    });

    const token = createToken(user._id);

    return res.status(201).json({
      message: "Signup successful",
      user: { id: user._id, name: user.name, email: user.email },
      token,
    });
  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// 2. Email/Username Login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email/Username and password are required" });
    }

// Try to find user by email OR username (name field)
const user = await User.findOne({
  $or: [{ email: email }, { name: email }]
});
if (!user || !user.password) {
  return res.status(401).json({ message: "Invalid email/username or password" });
}

const isMatch = await bcrypt.compare(password, user.password);
if (!isMatch) {
  return res.status(401).json({ message: "Invalid email/username or password" });
}

const token = createToken(user._id);

return res.json({
  message: "Login successful",
  user: { id: user._id, name: user.name, email: user.email },
  token,
});
  } catch (err) {
  console.error("Login error:", err);
  return res.status(500).json({ message: "Server error" });
}
});

// 3. Google OAuth Login
router.post("/google", async (req, res) => {
  try {
    const { id_token } = req.body;
    if (!id_token) {
      return res.status(400).json({ message: "id_token is required" });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;

    if (!email) {
      return res.status(400).json({ message: "Google account has no email" });
    }

    let user = await User.findOne({ email });

    if (!user) {
      user = await User.create({
        name: name || null,
        email,
        googleId,
        password: null,
      });
    }

    const token = createToken(user._id);

    return res.json({
      message: "Google login successful",
      user: { id: user._id, name: user.name, email: user.email },
      token,
    });
  } catch (err) {
    console.error("Google login error:", err);
    return res.status(401).json({ message: "Invalid Google token" });
  }
});

// 4. Logout (client will just delete token; this is here for symmetry)
router.post("/logout", authMiddleware, (req, res) => {
  return res.json({ message: "Logged out successfully" });
});

// Protected route example
router.get("/me", authMiddleware, (req, res) => {
  return res.json({ user: req.user });
});

module.exports = router;