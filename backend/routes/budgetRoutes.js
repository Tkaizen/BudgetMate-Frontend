const express = require('express');
const router = express.Router();
const User = require('../models/User');
const authMiddleware = require('../middleware/authMiddleware');
const { validateBudget } = require('../middleware/validationMiddleware');

// GET /api/budget - Get current user's budget settings
router.get('/', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('monthlyIncome paymentFrequency spendingCategories targetSavingsRate emergencyFundGoal annualSavingsGoal');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (err) {
        console.error('Error fetching budget:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

// PUT /api/budget - Update user's budget settings
router.put('/', [authMiddleware, validateBudget], async (req, res) => {
    try {
        const {
            monthlyIncome,
            paymentFrequency,
            spendingCategories,
            targetSavingsRate,
            emergencyFundGoal,
            annualSavingsGoal
        } = req.body;

        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (monthlyIncome !== undefined) user.monthlyIncome = monthlyIncome;
        if (paymentFrequency !== undefined) user.paymentFrequency = paymentFrequency;
        if (spendingCategories !== undefined) user.spendingCategories = spendingCategories;
        if (targetSavingsRate !== undefined) user.targetSavingsRate = targetSavingsRate;
        if (emergencyFundGoal !== undefined) user.emergencyFundGoal = emergencyFundGoal;
        if (annualSavingsGoal !== undefined) user.annualSavingsGoal = annualSavingsGoal;

        await user.save();

        res.json({
            message: 'Budget settings updated',
            budget: {
                monthlyIncome: user.monthlyIncome,
                paymentFrequency: user.paymentFrequency,
                spendingCategories: user.spendingCategories,
                targetSavingsRate: user.targetSavingsRate,
                emergencyFundGoal: user.emergencyFundGoal,
                annualSavingsGoal: user.annualSavingsGoal
            }
        });
    } catch (err) {
        console.error('Error updating budget:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
