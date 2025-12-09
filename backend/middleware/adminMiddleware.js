// backend/middleware/adminMiddleware.js
const authMiddleware = require("./authMiddleware");

/**
 * Admin Middleware
 * Extends authMiddleware to verify user has admin role
 * Use this middleware on routes that should only be accessible by admins
 */
const adminMiddleware = async (req, res, next) => {
    // First, authenticate the user using the existing auth middleware
    authMiddleware(req, res, (err) => {
        if (err) {
            return next(err);
        }

        // Check if the authenticated user has admin role
        if (!req.user || req.user.role !== 'admin') {
            return res.status(403).json({
                message: "Access denied. Admin privileges required."
            });
        }

        // User is authenticated and is an admin, proceed
        next();
    });
};

module.exports = adminMiddleware;
