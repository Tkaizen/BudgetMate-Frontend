// backend/seedArticles.js
// This script seeds the database with curated financial education articles
// Run this once to populate the database with budget-related content

require("dotenv").config();
const mongoose = require("mongoose");
const Article = require("./models/Article");
const User = require("./models/User");

const MONGODB_URI = process.env.MONGODB_URI;

// Curated articles focused on budgeting and personal finance
const initialArticles = [
    {
        title: "50/30/20 Rule Explained",
        description: "Learn how to split your income into needs, wants, and savings for better financial health.",
        url: "https://www.investopedia.com/ask/answers/022916/what-502030-budget-rule.asp",
        iconName: "pie-chart",
        color: "#E3823C",
        category: "budgeting",
    },
    {
        title: "Emergency Fund Basics",
        description: "Why you need an emergency fund and how much you should save.",
        url: "https://www.nerdwallet.com/article/banking/emergency-fund-why-it-matters",
        iconName: "savings",
        color: "#4CAF50",
        category: "savings",
    },
    {
        title: "Investing for Beginners",
        description: "A simple guide to starting your investment journey.",
        url: "https://www.investopedia.com/articles/basics/06/invest1000.asp",
        iconName: "trending-up",
        color: "#433DA3",
        category: "investing",
    },
    {
        title: "Debt Repayment Strategies",
        description: "Compare the Snowball vs. Avalanche methods to pay off debt faster.",
        url: "https://www.ramseysolutions.com/debt/debt-snowball-vs-debt-avalanche",
        iconName: "money-off",
        color: "#E33C3C",
        category: "debt",
    },
    {
        title: "Smart Grocery Shopping",
        description: "Tips to save money on your monthly food budget.",
        url: "https://www.thekitchn.com/10-smart-tips-for-grocery-shopping-on-a-budget-229420",
        iconName: "shopping-cart",
        color: "#D7C7EC",
        category: "budgeting",
    },
    {
        title: "Credit Card Management",
        description: "How to use credit cards wisely and avoid debt traps.",
        url: "https://www.nerdwallet.com/article/credit-cards/credit-card-basics",
        iconName: "credit-card",
        color: "#FF6B6B",
        category: "credit",
    },
    {
        title: "Retirement Planning 101",
        description: "Start planning for your retirement early with these essential tips.",
        url: "https://www.investopedia.com/retirement-planning-4689695",
        iconName: "account-balance",
        color: "#4ECDC4",
        category: "retirement",
    },
    {
        title: "Understanding Credit Scores",
        description: "Learn what affects your credit score and how to improve it.",
        url: "https://www.myfico.com/credit-education/credit-scores",
        iconName: "assessment",
        color: "#95E1D3",
        category: "credit",
    },
    {
        title: "Tax Basics for Beginners",
        description: "Essential tax knowledge everyone should know to save money.",
        url: "https://www.irs.gov/individuals/tax-basics-for-students",
        iconName: "receipt",
        color: "#F38181",
        category: "taxes",
    },
    {
        title: "Building Passive Income",
        description: "Explore ways to generate income without active work.",
        url: "https://www.investopedia.com/passive-income-ideas-8608228",
        iconName: "attach-money",
        color: "#AA96DA",
        category: "income",
    },
    {
        title: "Insurance Essentials",
        description: "Understanding different types of insurance and what you need.",
        url: "https://www.nerdwallet.com/article/insurance/insurance-basics",
        iconName: "security",
        color: "#FCBAD3",
        category: "insurance",
    },
    {
        title: "Side Hustle Ideas",
        description: "Discover profitable side hustles to boost your income.",
        url: "https://www.forbes.com/advisor/business/side-hustle-ideas/",
        iconName: "work",
        color: "#FFFFD2",
        category: "income",
    },
    {
        title: "Real Estate Investing",
        description: "Introduction to real estate investment for beginners.",
        url: "https://www.investopedia.com/mortgage/real-estate-investing-guide/",
        iconName: "home",
        color: "#A8D8EA",
        category: "investing",
    },
    {
        title: "Financial Goal Setting",
        description: "How to set and achieve your short-term and long-term financial goals.",
        url: "https://www.nerdwallet.com/article/finance/smart-financial-goals",
        iconName: "flag",
        color: "#FFAAA5",
        category: "planning",
    },
    {
        title: "Cryptocurrency Basics",
        description: "Understanding digital currencies and blockchain technology.",
        url: "https://www.investopedia.com/cryptocurrency-4427699",
        iconName: "currency-bitcoin",
        color: "#FF8B94",
        category: "investing",
    },
];

async function seedArticles() {
    try {
        // Connect to MongoDB
        await mongoose.connect(MONGODB_URI);
        console.log("✅ Connected to MongoDB");

        // Find the first admin user (or create a system user)
        let adminUser = await User.findOne({ role: "admin" });

        if (!adminUser) {
            console.log("⚠️  No admin user found. Please create an admin user first.");
            console.log("You can create one using the /api/auth/admin/create endpoint");
            process.exit(1);
        }

        console.log(`📝 Using admin user: ${adminUser.email}`);

        // Check if articles already exist
        const existingCount = await Article.countDocuments();
        if (existingCount > 0) {
            console.log(`⚠️  Database already has ${existingCount} articles.`);
            console.log("Do you want to continue? This will add more articles.");
            // For now, we'll skip if articles exist
            console.log("Skipping seed. Delete existing articles first if you want to re-seed.");
            process.exit(0);
        }

        // Create articles
        const articlesWithCreator = initialArticles.map((article) => ({
            ...article,
            createdBy: adminUser._id,
        }));

        const createdArticles = await Article.insertMany(articlesWithCreator);
        console.log(`✅ Successfully seeded ${createdArticles.length} articles!`);

        // Display created articles
        createdArticles.forEach((article, index) => {
            console.log(`${index + 1}. ${article.title}`);
        });

        process.exit(0);
    } catch (err) {
        console.error("❌ Error seeding articles:", err);
        process.exit(1);
    }
}

seedArticles();
