const express = require("express"); // The web server framework
const cors = require("cors");       // Allows the frontend to talk to this backend
const dotenv = require("dotenv");   // Loads secrets (like passwords) from .env file

const connectDB = require("./config/db"); // Helper to connect to MongoDB
const authRoutes = require("./routes/authRoutes");
const expenseRoutes = require("./routes/expenseRoutes");
const earningRoutes = require("./routes/earningRoutes");
const postRoutes = require("./routes/postRoutes");
const goalRoutes = require("./routes/goalRoutes");
const budgetRoutes = require("./routes/budgetRoutes");
const articleRoutes = require("./routes/articleRoutes");

// Load environment variables
dotenv.config();

// Connect to the Database
connectDB();

const app = express(); // Initialize the App

// Middleware
app.use(cors());          // Enable Cross-Origin requests
app.use(express.json());  // Allow the server to read JSON data sent by the frontend

// ✅ Mount routes
// This tells the server: "If a request starts with /api/auth, send it to authRoutes"
app.use("/api/auth", authRoutes);
app.use("/api/expenses", expenseRoutes);
app.use("/api/earnings", earningRoutes);
app.use("/api/posts", postRoutes);
app.use("/api/goals", goalRoutes);
app.use("/api/budget", budgetRoutes);
app.use("/api/articles", articleRoutes);

// Simple test route
app.get("/", (req, res) => {
  res.send("API is running");
});

const PORT = process.env.PORT || 5000;

// ✅ Use PORT variable and bind to 0.0.0.0
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
