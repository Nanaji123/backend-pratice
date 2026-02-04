import User from "../models/User.model.js";
import crypto from "crypto";
import { sendEmail } from "../utils/email.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export const registerController = async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ message: "All fields are required" })
    }
    try {
        const user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: "User already exists" })
        }
        const newUser = await User.create({
            username,
            email,
            password
        })

        const token = crypto.randomBytes(32).toString("hex");
        newUser.verificationToken = token;
        newUser.verificationTokenExpiry = Date.now() + 60 * 60 * 1000;
        await newUser.save();

        await sendEmail({
            to: newUser.email,
            subject: "Verify your email",
            text: `Click on the link to verify your email: http://localhost:3000/api/v1/auth/verify/${token}`
        })

        res.status(201).json({ "success": true, message: "verification email sent" })

    } catch (error) {
        console.error("Error in registration", error);
        return res.status(500).json({ message: "Internal server error" })
    }
}



export const loginController = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: "All fields are required" })
    }
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(400).json({ message: "User not found" })
    }
    if (!user.isVerified) {
        return res.status(400).json({ message: "User is not verified" })
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ message: "Invalid password" })
    }

    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
    user.refreshToken = refreshToken;
    await user.save();
    res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 60 * 60 * 1000
    })
    res.status(200).json({ success: true, user: { username: user.username, email: user.email, profile_picture: user.profile_picture } });
}
export const logoutController = (req, res) => {
    res.clearCookie("accessToken");
    res.status(200).json({ success: true, message: "Logout is successful" });
}

export const verifyController = async (req, res) => {
    const { token } = req.params;
    try {
        const user = await User.findOne({
            verificationToken: token,
            verificationTokenExpiry: { $gt: Date.now() }
        });
        if (!user) {
            return res.status(400).json({ message: "Invalid or expired verification token" });
        }
        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpiry = undefined;
        await user.save();
        res.status(200).json({ success: true, message: "Email verified successfully" });
    } catch (error) {
        console.error("Error in verification", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const refreshController = async (req, res) => {
    const { refreshToken } = req.cookies;
    if (!refreshToken) {
        return res.status(401).json({ message: "Refresh token not found" });
    }
    try {
        const user = await User.findOne({ refreshToken });
        if (!user) {
            return res.status(401).json({ message: "Invalid refresh token" });
        }
        const decodedToken = jwt.verify(refreshToken, process.env.JWT_SECRET);
        const accessToken = jwt.sign({ id: decodedToken.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 60 * 60 * 1000
        });
        res.status(200).json({ success: true, message: "Access token refreshed successfully" });
    } catch (error) {
        console.error("Error in refreshing token", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}
