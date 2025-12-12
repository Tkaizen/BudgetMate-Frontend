// backend/promoteToAdmin.js
// Run this script to promote a user to admin role
// Usage: node promoteToAdmin.js <email>

const mongoose = require("mongoose");
const dotenv = require("dotenv");
const User = require("./models/User");

dotenv.config();

async function promoteToAdmin() {
    try {
        const email = process.argv[2];

        if (!email) {
            console.log("❌ Please provide an email address");
            console.log("Usage: node promoteToAdmin.js <email>");
            process.exit(1);
        }

        // Connect to MongoDB
        await mongoose.connect(process.env.MONGO_URI);
        console.log("✅ Connected to MongoDB");

        // Find user by email
        const user = await User.findOne({ email: email.toLowerCase() });

        if (!user) {
            console.log(`❌ User with email "${email}" not found`);
            process.exit(1);
        }

        // Update role to admin
        user.role = 'admin';
        await user.save();

        console.log(`✅ Successfully promoted ${user.name || user.email} to admin`);
        console.log(`   Email: ${user.email}`);
        console.log(`   Role: ${user.role}`);

        process.exit(0);
    } catch (error) {
        console.error("❌ Error promoting user:", error);
        process.exit(1);
    }
}

promoteToAdmin();
