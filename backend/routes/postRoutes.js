const express = require("express");
const router = express.Router();
const Post = require("../models/Post");
const auth = require("../middleware/authMiddleware");
const { validatePost } = require("../middleware/validationMiddleware");

// @route   GET /api/posts
// @desc    Get all posts
// @access  Public
router.get("/", async (req, res) => {
    try {
        const posts = await Post.find()
            .populate("user", "name username")
            .populate("comments.user", "name username")
            .sort({ createdAt: -1 });
        res.json(posts);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// @route   POST /api/posts
// @desc    Create a post
// @access  Private
router.post("/", [auth, validatePost], async (req, res) => {
    try {
        const { title, content, category } = req.body;

        const newPost = new Post({
            user: req.user.id,
            title,
            content,
            category,
        });

        const post = await newPost.save();
        const populatedPost = await Post.findById(post._id).populate("user", "name username");
        res.json(populatedPost);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// @route   POST /api/posts/:id/like
// @desc    Like/Unlike a post
// @access  Private
router.post("/:id/like", auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);

        if (!post) {
            return res.status(404).json({ msg: "Post not found" });
        }

        // Check if post is already liked
        const likeIndex = post.likes.indexOf(req.user.id);

        if (likeIndex > -1) {
            // Unlike
            post.likes.splice(likeIndex, 1);
        } else {
            // Like
            post.likes.push(req.user.id);
        }

        await post.save();
        res.json(post);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// @route   POST /api/posts/:id/comment
// @desc    Add comment to post
// @access  Private
router.post("/:id/comment", auth, async (req, res) => {
    try {
        const { text } = req.body;
        const post = await Post.findById(req.params.id);

        if (!post) {
            return res.status(404).json({ msg: "Post not found" });
        }

        const newComment = {
            user: req.user.id,
            text,
        };

        post.comments.unshift(newComment);
        await post.save();

        const populatedPost = await Post.findById(post._id)
            .populate("user", "name username")
            .populate("comments.user", "name username");

        res.json(populatedPost);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// @route   DELETE /api/posts/:id
// @desc    Delete a post
// @access  Private
router.delete("/:id", auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);

        if (!post) {
            return res.status(404).json({ msg: "Post not found" });
        }

        // Make sure user owns post
        if (post.user.toString() !== req.user.id) {
            return res.status(401).json({ msg: "Not authorized" });
        }

        await Post.findByIdAndDelete(req.params.id);

        res.json({ msg: "Post removed" });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

module.exports = router;
