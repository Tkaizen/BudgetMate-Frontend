// backend/routes/jobRoutes.js
const express = require("express");
const Job = require("../models/Job");
const authMiddleware = require("../middleware/authMiddleware");
const adminMiddleware = require("../middleware/adminMiddleware");

const router = express.Router();

/**
 * GET /api/jobs
 * Public endpoint - Fetch all published jobs
 * No authentication required
 */
router.get("/", async (req, res) => {
    try {
        const jobs = await Job.find({ isPublished: true })
            .sort({ createdAt: -1 })
            .select("-__v");

        return res.json({ jobs });
    } catch (err) {
        console.error("Error fetching jobs:", err);
        return res.status(500).json({ message: "Failed to fetch jobs" });
    }
});

/**
 * POST /api/jobs
 * Admin-only endpoint - Create new job
 * Requires admin authentication
 */
router.post("/", adminMiddleware, async (req, res) => {
    try {
        const {
            title,
            description,
            difficulty,
            payRange,
            timeCommitment,
            tags,
            fullDescription,
            requirements,
            howToStart
        } = req.body;

        // Validation
        if (!title || !description || !payRange || !timeCommitment) {
            return res.status(400).json({
                message: "Title, description, pay range, and time commitment are required"
            });
        }

        // Create job
        const job = await Job.create({
            title,
            description,
            difficulty: difficulty || 'Easy',
            payRange,
            timeCommitment,
            tags: tags || [],
            fullDescription,
            requirements: requirements || [],
            howToStart,
            createdBy: req.user._id,
        });

        return res.status(201).json({
            message: "Job created successfully",
            job
        });
    } catch (err) {
        console.error("Error creating job:", err);
        return res.status(500).json({ message: "Failed to create job" });
    }
});

/**
 * PUT /api/jobs/:id
 * Admin-only endpoint - Update existing job
 * Requires admin authentication
 */
router.put("/:id", adminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const {
            title,
            description,
            difficulty,
            payRange,
            timeCommitment,
            tags,
            fullDescription,
            requirements,
            howToStart,
            isPublished
        } = req.body;

        // Find and update job
        const job = await Job.findById(id);
        if (!job) {
            return res.status(404).json({ message: "Job not found" });
        }

        // Update fields
        if (title !== undefined) job.title = title;
        if (description !== undefined) job.description = description;
        if (difficulty !== undefined) job.difficulty = difficulty;
        if (payRange !== undefined) job.payRange = payRange;
        if (timeCommitment !== undefined) job.timeCommitment = timeCommitment;
        if (tags !== undefined) job.tags = tags;
        if (fullDescription !== undefined) job.fullDescription = fullDescription;
        if (requirements !== undefined) job.requirements = requirements;
        if (howToStart !== undefined) job.howToStart = howToStart;
        if (isPublished !== undefined) job.isPublished = isPublished;

        await job.save();

        return res.json({
            message: "Job updated successfully",
            job
        });
    } catch (err) {
        console.error("Error updating job:", err);
        return res.status(500).json({ message: "Failed to update job" });
    }
});

/**
 * DELETE /api/jobs/:id
 * Admin-only endpoint - Delete job
 * Requires admin authentication
 */
router.delete("/:id", adminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;

        const job = await Job.findByIdAndDelete(id);
        if (!job) {
            return res.status(404).json({ message: "Job not found" });
        }

        return res.json({ message: "Job deleted successfully" });
    } catch (err) {
        console.error("Error deleting job:", err);
        return res.status(500).json({ message: "Failed to delete job" });
    }
});

module.exports = router;
