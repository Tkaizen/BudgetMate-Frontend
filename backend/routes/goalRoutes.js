const express = require("express");
const router = express.Router();
const Goal = require("../models/Goal");
const auth = require("../middleware/authMiddleware");
const { validateGoal } = require("../middleware/validationMiddleware");

// @route   GET /api/goals
// @desc    Get all goals for logged-in user
// @access  Private
router.get("/", auth, async (req, res) => {
    try {
        const goals = await Goal.find({ user: req.user.id }).sort({ createdAt: -1 });
        res.json(goals);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// @route   POST /api/goals
// @desc    Create a goal
// @access  Private
router.post("/", [auth, validateGoal], async (req, res) => {
    try {
        const { name, targetAmount, currentAmount, category, targetDate } = req.body;

        const newGoal = new Goal({
            user: req.user.id,
            name,
            targetAmount,
            currentAmount: currentAmount || 0,
            category,
            targetDate,
        });

        const goal = await newGoal.save();
        res.json(goal);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// @route   PUT /api/goals/:id
// @desc    Update goal
// @access  Private
router.put("/:id", [auth, validateGoal], async (req, res) => {
    try {
        const { name, targetAmount, currentAmount, category, targetDate } = req.body;

        let goal = await Goal.findById(req.params.id);

        if (!goal) {
            return res.status(404).json({ msg: "Goal not found" });
        }

        // Make sure user owns goal
        if (goal.user.toString() !== req.user.id) {
            return res.status(401).json({ msg: "Not authorized" });
        }

        goal = await Goal.findByIdAndUpdate(
            req.params.id,
            { name, targetAmount, currentAmount, category, targetDate },
            { new: true }
        );

        res.json(goal);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// @route   DELETE /api/goals/:id
// @desc    Delete goal
// @access  Private
router.delete("/:id", auth, async (req, res) => {
    try {
        const goal = await Goal.findById(req.params.id);

        if (!goal) {
            return res.status(404).json({ msg: "Goal not found" });
        }

        // Make sure user owns goal
        if (goal.user.toString() !== req.user.id) {
            return res.status(401).json({ msg: "Not authorized" });
        }

        await Goal.findByIdAndDelete(req.params.id);

        res.json({ msg: "Goal removed" });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

module.exports = router;
