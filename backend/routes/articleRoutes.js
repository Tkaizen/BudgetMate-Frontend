// backend/routes/articleRoutes.js
const express = require("express");
const Article = require("../models/Article");
const authMiddleware = require("../middleware/authMiddleware");
const adminMiddleware = require("../middleware/adminMiddleware");

const router = express.Router();

/**
 * GET /api/articles
 * Public endpoint - Fetch all published articles
 * No authentication required
 */
router.get("/", async (req, res) => {
    try {
        const articles = await Article.find({ isPublished: true })
            .sort({ createdAt: -1 })
            .select("-__v");

        return res.json({ articles });
    } catch (err) {
        console.error("Error fetching articles:", err);
        return res.status(500).json({ message: "Failed to fetch articles" });
    }
});

/**
 * POST /api/articles
 * Admin-only endpoint - Create new article
 * Requires admin authentication
 */
router.post("/", adminMiddleware, async (req, res) => {
    try {
        const { title, description, content, url, iconName, color, category } = req.body;

        // Validation
        if (!title || !description) {
            return res.status(400).json({
                message: "Title and description are required"
            });
        }

        // Create article
        const article = await Article.create({
            title,
            description,
            content,
            url,
            iconName: iconName || 'article',
            color: color || '#6C63FF',
            category: category || 'general',
            createdBy: req.user._id,
        });

        return res.status(201).json({
            message: "Article created successfully",
            article
        });
    } catch (err) {
        console.error("Error creating article:", err);
        return res.status(500).json({ message: "Failed to create article" });
    }
});

/**
 * PUT /api/articles/:id
 * Admin-only endpoint - Update existing article
 * Requires admin authentication
 */
router.put("/:id", adminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, content, url, iconName, color, category, isPublished } = req.body;

        // Find and update article
        const article = await Article.findById(id);
        if (!article) {
            return res.status(404).json({ message: "Article not found" });
        }

        // Update fields
        if (title !== undefined) article.title = title;
        if (description !== undefined) article.description = description;
        if (content !== undefined) article.content = content;
        if (url !== undefined) article.url = url;
        if (iconName !== undefined) article.iconName = iconName;
        if (color !== undefined) article.color = color;
        if (category !== undefined) article.category = category;
        if (isPublished !== undefined) article.isPublished = isPublished;

        await article.save();

        return res.json({
            message: "Article updated successfully",
            article
        });
    } catch (err) {
        console.error("Error updating article:", err);
        return res.status(500).json({ message: "Failed to update article" });
    }
});

/**
 * DELETE /api/articles/:id
 * Admin-only endpoint - Delete article
 * Requires admin authentication
 */
router.delete("/:id", adminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;

        const article = await Article.findByIdAndDelete(id);
        if (!article) {
            return res.status(404).json({ message: "Article not found" });
        }

        return res.json({ message: "Article deleted successfully" });
    } catch (err) {
        console.error("Error deleting article:", err);
        return res.status(500).json({ message: "Failed to delete article" });
    }
});

module.exports = router;
