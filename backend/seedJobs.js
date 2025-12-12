// backend/seedJobs.js
// Run this script to populate the database with initial job postings
// Usage: node seedJobs.js

const mongoose = require("mongoose");
const dotenv = require("dotenv");
const Job = require("./models/Job");
const User = require("./models/User");

dotenv.config();

const INITIAL_JOBS = [
    {
        title: 'Freelance Writing',
        description: 'Write articles for blogs and publications',
        difficulty: 'Easy',
        payRange: '₱ 50–200 per article',
        timeCommitment: '5–10 hrs/week',
        tags: ['Writing', 'Remote', 'Flexible'],
        fullDescription: 'Create engaging content for various online platforms. Perfect for those with strong writing skills and creativity. No prior experience required, but a portfolio helps.',
        requirements: ['Good writing skills', 'Basic grammar knowledge', 'Internet connection'],
        howToStart: 'Sign up on freelancing platforms like Upwork, Fiverr, or Freelancer.com. Create a compelling profile and start bidding on projects.',
        isPublished: true
    },
    {
        title: 'Virtual Assistant',
        description: 'Help businesses with administrative tasks',
        difficulty: 'Easy',
        payRange: '₱ 15–25/hour',
        timeCommitment: '10–20 hrs/week',
        tags: ['Admin', 'Remote', 'Flexible'],
        fullDescription: 'Provide administrative support to businesses remotely. Tasks include email management, scheduling, data entry, and customer service.',
        requirements: ['Organizational skills', 'Good communication', 'Computer literacy', 'Reliable internet'],
        howToStart: 'Create profiles on platforms like Upwork, OnlineJobs.ph, or Virtual Staff Finder. Highlight your organizational and communication skills.',
        isPublished: true
    },
    {
        title: 'Graphic Design',
        description: 'Create visuals for brands',
        difficulty: 'Medium',
        payRange: '₱ 300–1000 per project',
        timeCommitment: 'Flexible',
        tags: ['Creative', 'Design', 'Remote'],
        fullDescription: 'Design logos, social media posts, and marketing materials. Requires knowledge of tools like Canva, Photoshop, or Illustrator.',
        requirements: ['Design software skills', 'Creativity', 'Portfolio'],
        howToStart: 'Build a portfolio and showcase your work on Behance or Dribbble. Apply for gigs on freelancing sites.',
        isPublished: true
    }
];

async function seedJobs() {
    try {
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGO_URI);
        console.log("✅ Connected to MongoDB");

        // Find an admin user to assign as creator
        const adminUser = await User.findOne({ role: 'admin' });

        if (!adminUser) {
            console.log("⚠️  No admin user found. Please create an admin user first.");
            console.log("You can manually set a user's role to 'admin' in MongoDB.");
            process.exit(1);
        }

        console.log(`✅ Found admin user: ${adminUser.email}`);

        // Clear existing jobs (optional - comment out if you want to keep existing jobs)
        await Job.deleteMany({});
        console.log("🗑️  Cleared existing jobs");

        // Create jobs with admin as creator
        const jobsWithCreator = INITIAL_JOBS.map(job => ({
            ...job,
            createdBy: adminUser._id
        }));

        const createdJobs = await Job.insertMany(jobsWithCreator);
        console.log(`✅ Successfully seeded ${createdJobs.length} jobs`);

        createdJobs.forEach((job, index) => {
            console.log(`   ${index + 1}. ${job.title}`);
        });

        process.exit(0);
    } catch (error) {
        console.error("❌ Error seeding jobs:", error);
        process.exit(1);
    }
}

seedJobs();
