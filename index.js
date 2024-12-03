


const express = require("express");
const app = express();
const dotenv = require("dotenv");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const UserModel = require("./model/User");

dotenv.config();
app.use(express.json());

const corsOptions = {
    origin: ["http://localhost:5173"],
};
app.use(cors(corsOptions));

const SECRET_KEY = process.env.SECRET_KEY || "secretkey";

// Sign Up Route
app.post("/signup", async (req, res) => {
    const { email, password } = req.body;
    try {
        // Check if user already exists
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        // Hash password and create user
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new UserModel({ email, password: hashedPassword });
        await newUser.save();

        // Generate token
        const token = jwt.sign({ id: newUser._id }, SECRET_KEY, { expiresIn: "1h" });
        res.status(201).json({ token, email: newUser.email });
    } catch (error) {
        console.error("Error during sign-up:", error.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Sign In Route
app.post("/signin", async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: "1h" });
        res.status(200).json({ token, email: user.email });
    } catch (error) {
        console.error("Error during sign-in:", error.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

mongoose
    .connect(process.env.MONGO_URL)
    .then(() => {
        console.log("Connected to MongoDB");
        app.listen(process.env.PORT, () => {
            console.log(`Server is running on http://localhost:${process.env.PORT}`);
        });
    })
    .catch((error) => {
        console.error("Error connecting to MongoDB:", error.message);
    });

