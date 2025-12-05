const express = require("express");
const router = express.Router();
const Expense = require("../models/Expense");
const auth = require("../middleware/authMiddleware");
const { validateExpense } = require("../middleware/validationMiddleware");

// @route   GET /api/expenses
// @desc    Get all expenses for logged-in user
// @access  Private
router.get("/", auth, async (req, res) => {
    try {
        const expenses = await Expense.find({ user: req.user.id }).sort({ date: -1 });
        res.json(expenses);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// @route   POST /api/expenses
// @desc    Add new expense
// @access  Private
router.post("/", [auth, validateExpense], async (req, res) => {
    try {
        const { amount, category, description, date } = req.body;

        const newExpense = new Expense({
            user: req.user.id,
            amount,
            category,
            description,
            date: date || Date.now(),
        });

        const expense = await newExpense.save();
        res.json(expense);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// @route   PUT /api/expenses/:id
// @desc    Update expense
// @access  Private
router.put("/:id", [auth, validateExpense], async (req, res) => {
    try {
        const { amount, category, description, date } = req.body;

        let expense = await Expense.findById(req.params.id);

        if (!expense) {
            return res.status(404).json({ msg: "Expense not found" });
        }

        // Make sure user owns expense
        if (expense.user.toString() !== req.user.id) {
            return res.status(401).json({ msg: "Not authorized" });
        }

        expense = await Expense.findByIdAndUpdate(
            req.params.id,
            { amount, category, description, date },
            { new: true }
        );

        res.json(expense);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// @route   DELETE /api/expenses/:id
// @desc    Delete expense
// @access  Private
router.delete("/:id", auth, async (req, res) => {
    try {
        const expense = await Expense.findById(req.params.id);

        if (!expense) {
            return res.status(404).json({ msg: "Expense not found" });
        }

        // Make sure user owns expense
        if (expense.user.toString() !== req.user.id) {
            return res.status(401).json({ msg: "Not authorized" });
        }

        await Expense.findByIdAndDelete(req.params.id);

        res.json({ msg: "Expense removed" });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

module.exports = router;
