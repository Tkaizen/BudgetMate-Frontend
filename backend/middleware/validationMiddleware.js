const { body, validationResult } = require('express-validator');

// Middleware to handle validation errors
const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

// Validation rules
const validateSignup = [
    body('email').isEmail().withMessage('Please include a valid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    body('username').not().isEmpty().withMessage('Username is required'),
    validate
];

const validateLogin = [
    body('email').not().isEmpty().withMessage('Email or Username is required'),
    body('password').exists().withMessage('Password is required'),
    validate
];

const validateExpense = [
    body('amount').isNumeric().withMessage('Amount must be a number'),
    body('category').not().isEmpty().withMessage('Category is required'),
    body('date').optional().isISO8601().withMessage('Date must be a valid date'),
    validate
];

const validateBudget = [
    body('amount').isNumeric().withMessage('Amount must be a number'),
    body('category').not().isEmpty().withMessage('Category is required'),
    body('period').isIn(['weekly', 'monthly', 'yearly']).withMessage('Period must be weekly, monthly, or yearly'),
    validate
];

const validateGoal = [
    body('title').not().isEmpty().withMessage('Title is required'),
    body('targetAmount').isNumeric().withMessage('Target amount must be a number'),
    body('currentAmount').optional().isNumeric().withMessage('Current amount must be a number'),
    body('deadline').optional().isISO8601().withMessage('Deadline must be a valid date'),
    validate
];

const validateEarning = [
    body('amount').isNumeric().withMessage('Amount must be a number'),
    body('source').not().isEmpty().withMessage('Source is required'),
    body('date').optional().isISO8601().withMessage('Date must be a valid date'),
    validate
];

const validatePost = [
    body('content').not().isEmpty().withMessage('Content is required'),
    validate
];

module.exports = {
    validateSignup,
    validateLogin,
    validateExpense,
    validateBudget,
    validateGoal,
    validateEarning,
    validatePost
};
