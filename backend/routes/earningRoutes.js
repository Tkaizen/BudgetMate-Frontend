const express = require("express");
const router = express.Router();
const Earning = require("../models/Earning");
const auth = require("../middleware/authMiddleware");
const { validateEarning } = require("../middleware/validationMiddleware");

// @route   GET /api/earnings
// @desc    Get all earnings for logged-in user
// @access  Private
router.get("/", auth, async (req, res) => {
    try {
        const earnings = await Earning.find({ user: req.user.id }).sort({ date: -1 });
        res.json(earnings);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// @route   POST /api/earnings
// @desc    Add new earning
// @access  Private
router.post("/", [auth, validateEarning], async (req, res) => {
    try {
        const { amount, source, description, date } = req.body;

        const newEarning = new Earning({
            user: req.user.id,
            amount,
            source,
            description,
            date: date || Date.now(),
        });

        const earning = await newEarning.save();
        res.json(earning);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// @route   DELETE /api/earnings/:id
// @desc    Delete earning
// @access  Private
router.delete("/:id", auth, async (req, res) => {
    try {
        const earning = await Earning.findById(req.params.id);

        if (!earning) {
            return res.status(404).json({ msg: "Earning not found" });
        }

        // Make sure user owns earning
        if (earning.user.toString() !== req.user.id) {
            return res.status(401).json({ msg: "Not authorized" });
        }

        await Earning.findByIdAndDelete(req.params.id);

        res.json({ msg: "Earning removed" });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

module.exports = router;
