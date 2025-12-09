// backend/models/Article.js
const mongoose = require("mongoose");

const articleSchema = new mongoose.Schema(
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
        content: {
            type: String,
            trim: true
        },
        url: {
            type: String,
            trim: true
        },
        iconName: {
            type: String,
            default: 'article'
        },
        color: {
            type: String,
            default: '#6C63FF'
        },
        category: {
            type: String,
            default: 'general'
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

module.exports = mongoose.model("Article", articleSchema);
