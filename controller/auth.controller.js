import User from "../models/User.model.js";
import crypto from "crypto";
import { sendEmail } from "../utils/email.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { hash, compare } from "../utils/hash.js";
import { getClientIp } from "../utils/ip.js";
import Session from "../models/session.model.js";
import Token from "../models/token.model.js";

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
        newUser.save();

        const token = crypto.randomBytes(32).toString("hex");
        await Token.create({
            userId: newUser._id,
            token: await hash(token),
            type: "VERIFICATION",
            expiresAt: Date.now() + 60 * 60 * 1000
        })

        await sendEmail({
            to: newUser.email,
            subject: "Verify your email",
            text: `Click on the link to verify your email: http://localhost:3000/api/v1/auth/verify/${newUser._id}/${token}`
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
    const isPasswordValid = await compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ message: "Invalid password" })
    }

    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    if (user.is2FAEnabled) {
        const twoFACode = Math.floor(100000 + Math.random() * 900000).toString();

        // Delete any existing 2FA tokens for this user first
        await Token.deleteMany({ userId: user._id, type: '2FA' });

        await Token.create({
            userId: user._id,
            token: await hash(twoFACode),
            type: '2FA',
            expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 mins
        });

        await sendEmail({
            to: user.email,
            subject: "Your 2FA Code",
            text: `Your 2FA code is: ${twoFACode}. It will expire in 10 minutes.`
        });

        return res.status(200).json({
            success: true,
            twoFARequired: true,
            message: "2FA code sent to your email."
        });
    }

    // Enforce session limit
    const sessionCount = await Session.countDocuments({ userId: user._id });
    if (sessionCount >= user.maxSessions) {
        // Delete oldest session (FIFO)
        await Session.findOneAndDelete({ userId: user._id }, { sort: { createdAt: 1 } });
    }

    // Create a new session record
    await Session.create({
        userId: user._id,
        refreshToken: await hash(refreshToken),
        ip: getClientIp(req),
        userAgent: req.headers["user-agent"],
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });
    res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 60 * 60 * 1000
    })

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    })
    res.status(200).json({ success: true, user: { username: user.username, email: user.email, profile_picture: user.profile_picture } });
}

export const logoutController = async (req, res) => {
    const { refreshToken } = req.cookies;
    if (refreshToken) {
        try {
            const decodedToken = jwt.verify(refreshToken, process.env.JWT_SECRET);
            const sessions = await Session.find({ userId: decodedToken.id });

            // Find the specific session to delete
            for (const session of sessions) {
                if (await session.compareToken(refreshToken)) {
                    await session.deleteOne();
                    break;
                }
            }
        } catch (error) {
            // Token might be invalid or expired, just proceed to clear cookies
        }
    }
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.status(200).json({ success: true, message: "Logout is successful" });
}

export const verifyController = async (req, res) => {
    const { userId, token } = req.params;
    try {
        const tokenDoc = await Token.findOne({
            userId: userId,
            type: "VERIFICATION",
            expiresAt: { $gt: Date.now() }
        });
        if (!tokenDoc) {
            return res.status(400).json({ message: "Invalid or expired verification token" });
        }
        const isMatch = await tokenDoc.compareToken(token);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid or expired verification token" });
        }
        const user = await User.findById(userId);
        if (!user) {
            return res.status(400).json({ message: "User not found" });
        }
        user.isVerified = true;
        await user.save();

        await tokenDoc.deleteOne();
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
        const decodedToken = jwt.verify(refreshToken, process.env.JWT_SECRET);
        const user = await User.findOne({ _id: decodedToken.id });

        if (!user) {
            return res.status(401).json({ message: "Invalid refresh token" });
        }

        const sessions = await Session.find({ userId: user._id });
        let matchedSession = null;

        for (const session of sessions) {
            if (await session.compareToken(refreshToken)) {
                matchedSession = session;
                break;
            }
        }

        if (!matchedSession) {
            // Potential theft attempt! Revoke ALL sessions for this user for safety
            await Session.deleteMany({ userId: user._id });
            return res.status(401).json({ message: "Invalid refresh token - Potential misuse detected. All sessions revoked." });
        }


        // Generate NEW tokens (Rotation)
        const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        const newRefreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

        // Update the session record with the new hashed token
        matchedSession.refreshToken = await hash(newRefreshToken);
        matchedSession.lastUsedAt = Date.now();
        await matchedSession.save();

        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 60 * 60 * 1000
        });
        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.status(200).json({ success: true, message: "Access token refreshed successfully" });
    } catch (error) {
        console.error("Error in refreshing token", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const toggle2FAController = async (req, res) => {
    const { userId } = req.user;
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        user.is2FAEnabled = !user.is2FAEnabled;
        await user.save();
        res.status(200).json({ success: true, message: `2FA ${user.is2FAEnabled ? "enabled" : "disabled"} successfully` });
    } catch (error) {
        console.error("Error in toggling 2FA", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const verify2FAController = async (req, res) => {
    const { email, password, code } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // // Check if account is locked
        // if (user.lockUntil && user.lockUntil > Date.now()) {
        //     const remainingMinutes = Math.ceil((user.lockUntil - Date.now()) / (60 * 1000));
        //     return res.status(403).json({
        //         success: false,
        //         message: `Account is temporarily locked. Try again in ${remainingMinutes} minutes.`
        //     });
        // }

        const isPasswordMatch = await compare(password, user.password);
        if (!isPasswordMatch) {
            // Increment login attempts
            // user.loginAttempts += 1;
            // if (user.loginAttempts >= 5) {
            //     user.lockUntil = Date.now() + 15 * 60 * 1000; // Lock for 15 mins
            // }
            // await user.save();

            return res.status(400).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        // Reset attempts on successful login
        // user.loginAttempts = 0;
        // user.lockUntil = undefined;
        // await user.save();

        if (!user.isVerified) {
            return res.status(400).json({ message: "Invalid or expired 2FA code." });
        }

        const tokenDoc = await Token.findOne({
            userId: user._id,
            type: '2FA',
            expiresAt: { $gt: Date.now() }
        });

        if (!tokenDoc) {
            return res.status(400).json({ message: "Invalid or expired 2FA code." });
        }

        const isTokenMatch = await tokenDoc.compareToken(code);
        if (!isTokenMatch) {
            return res.status(400).json({ message: "Invalid 2FA code." });
        }

        // Clear 2FA token
        await tokenDoc.deleteOne();

        // Issue tokens and create session
        const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

        const sessionCount = await Session.countDocuments({ userId: user._id });
        if (sessionCount >= user.maxSessions) {
            await Session.findOneAndDelete({ userId: user._id }, { sort: { createdAt: 1 } });
        }

        await Session.create({
            userId: user._id,
            refreshToken: await hash(refreshToken),
            ip: getClientIp(req),
            userAgent: req.headers["user-agent"],
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        });

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 60 * 60 * 1000
        });

        res.status(200).json({ success: true, user: { username: user.username, email: user.email, profile_picture: user.profile_picture } });
    } catch (error) {
        console.error("Error in 2FA verification", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}
