// node-backend/models/User.js
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: { type: String },
    email: { type: String, required: true, unique: true },
    password: { type: String },   // null for Google-only users
    googleId: { type: String },   // for Google OAuth
    role: { type: String, enum: ['user', 'admin'], default: 'user' }, // Role-based access control

    // Budget Settings
    monthlyIncome: { type: Number, default: 0 },
    paymentFrequency: { type: String, default: '' },
    spendingCategories: { type: [String], default: [] },
    targetSavingsRate: { type: Number, default: 0 },
    emergencyFundGoal: { type: Number, default: 0 },
    annualSavingsGoal: { type: Number, default: 0 },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
