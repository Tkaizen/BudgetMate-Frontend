// backend/models/Job.js
const mongoose = require("mongoose");

const jobSchema = new mongoose.Schema(
    {
        title: {
            type: String,
            required: true,
            trim: true
        },
        description: {
            type: String,
            required: true,
            trim: true
        },
        difficulty: {
            type: String,
            enum: ['Easy', 'Medium', 'Hard'],
            default: 'Easy'
        },
        payRange: {
            type: String,
            required: true,
            trim: true
        },
        timeCommitment: {
            type: String,
            required: true,
            trim: true
        },
        tags: {
            type: [String],
            default: []
        },
        fullDescription: {
            type: String,
            trim: true
        },
        requirements: {
            type: [String],
            default: []
        },
        howToStart: {
            type: String,
            trim: true
        },
        isPublished: {
            type: Boolean,
            default: true
        },
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
    },
    { timestamps: true }
);

module.exports = mongoose.model("Job", jobSchema);
