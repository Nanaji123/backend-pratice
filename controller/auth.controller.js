import User from "../models/User.model.js";
import crypto from "crypto";
import { sendEmail } from "../utils/email.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { hash, compare } from "../utils/hash.js";
import { getClientIp } from "../utils/ip.js";
import Session from "../models/session.model.js";
import Token from "../models/token.model.js";
import { validateUsername, validatePassword } from "../utils/validation.js";
import Password from "../models/password.model.js";
import cloudinary from "../config/cloudinary.js";
import { verificationEmailTemplate, passwordResetEmailTemplate } from "../utils/emailTemplates.js";
import Chat from "../models/chat.model.js";



export const registerController = async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ message: "All fields are required" })
    }
    if (!validateUsername(username)) {
        return res.status(400).json({ message: "Invalid username" })
    }
    if (!validatePassword(password)) {
        return res.status(400).json({ message: "Invalid password" })
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
        new Password({
            userId: newUser._id,
            password: await hash(password)
        }).save();

        const token = crypto.randomBytes(32).toString("hex");
        await Token.create({
            userId: newUser._id,
            token: await hash(token),
            type: "VERIFICATION",
            expiresAt: Date.now() + 60 * 60 * 1000
        })
        const verifyLink = `http://localhost:3001/verify/${newUser._id}/${token}`;


        await sendEmail({
            to: newUser.email,
            subject: "Verify your email",
            html: verificationEmailTemplate(newUser.username, verifyLink),
        });

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

    if (user.lockUntil && user.lockUntil > Date.now()) {
        const remainingMinutes = Math.ceil((user.lockUntil - Date.now()) / (60 * 1000));
        return res.status(403).json({
            success: false,
            message: `Account is temporarily locked. Try again in ${remainingMinutes} minutes.`
        });
    }

    const isPasswordValid = await compare(password, user.password);
    if (!isPasswordValid) {

        // Increment login attempts
        user.loginAttempts += 1;
        if (user.loginAttempts >= 5) {
            user.lockUntil = Date.now() + 15 * 60 * 1000; // Lock for 15 mins
        }
        await user.save();

        return res.status(400).json({ message: "Invalid password" })
    }

    // Reset attempts on successful login
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();


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
    const { _id: userId } = req.user;
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

        // Check if account is locked
        if (user.lockUntil && user.lockUntil > Date.now()) {
            const remainingMinutes = Math.ceil((user.lockUntil - Date.now()) / (60 * 1000));
            return res.status(403).json({
                success: false,
                message: `Account is temporarily locked. Try again in ${remainingMinutes} minutes.`
            });
        }

        const isPasswordMatch = await compare(password, user.password);
        if (!isPasswordMatch) {
            // Increment login attempts
            user.loginAttempts += 1;
            if (user.loginAttempts >= 5) {
                user.lockUntil = Date.now() + 15 * 60 * 1000; // Lock for 15 mins
            }
            await user.save();

            return res.status(400).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        // Reset attempts on successful login
        user.loginAttempts = 0;
        user.lockUntil = undefined;
        await user.save();

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

export const forgetPasswordController = async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const resetTokenRaw = crypto.randomBytes(32).toString("hex");
        await Token.deleteMany({ userId: user._id, type: 'PASSWORD_RESET' });

        await Token.create({
            userId: user._id,
            token: await hash(resetTokenRaw),
            type: 'PASSWORD_RESET',
            expiresAt: new Date(Date.now() + 15 * 60 * 1000) // 15 mins
        });

        console.log("Reset token created", resetTokenRaw);

        const resetLink = `http://localhost:3001/reset-password/${user._id}/${resetTokenRaw}`;

        await sendEmail({
            to: user.email,
            subject: "Reset your password",
            html: passwordResetEmailTemplate(user.username, resetLink),
        });

        console.log("Password reset email sent");

        res.status(200).json({ success: true, message: "Password reset email sent" });
    } catch (error) {
        console.error("Error in password reset", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const resetPasswordController = async (req, res) => {
    const { userId, token } = req.params;
    const { newPassword } = req.body;

    if (!newPassword) {
        return res.status(400).json({ message: "Password is required" })
    }

    if (!validatePassword(newPassword)) {
        return res.status(400).json({ message: "Invalid password" })
    }

    try {
        const tokenDoc = await Token.findOne({
            userId,
            type: 'PASSWORD_RESET',
            expiresAt: { $gt: Date.now() }
        });

        if (!tokenDoc) {
            return res.status(400).json({ message: "Invalid or expired reset token" });
        }

        const isMatch = await tokenDoc.compareToken(token);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid reset token" });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const passwordHistory = await Password.find({ userId: userId });
        for (const password of passwordHistory) {
            const isSame = await password.comparePassword(newPassword);
            if (isSame) {
                return res.status(400).json({ message: "Password already used" });
            }
        }

        user.password = newPassword;
        await user.save();
        new Password({
            userId: user._id,
            password: newPassword
        }).save();

        // Delete the token and revoke sessions
        await tokenDoc.deleteOne();
        await Session.deleteMany({ userId: user._id });

        res.status(200).json({ success: true, message: "Password reset successful. All active sessions logged out." });
    } catch (error) {
        console.error("Error in reset password", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const changePasswordController = async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    try {
        const user = await User.findById(req.user._id);

        const isMatch = await user.comparePassword(currentPassword);
        if (!isMatch) {
            return res.status(400).json({ message: "Current password is incorrect" });
        }

        if (!validatePassword(newPassword)) {
            return res.status(400).json({ message: "New password does not meet complexity requirements" });
        }

        const passwordHistory = await Password.find({ userId: user._id });
        for (const password of passwordHistory) {
            const isSame = await password.comparePassword(newPassword);
            if (isSame) {
                return res.status(400).json({ message: "Password already used" });
            }
        }

        user.password = newPassword;
        await user.save();
        new Password({
            userId: user._id,
            password: newPassword
        }).save();

        // Security requirement: Revoke all other sessions after password change
        const currentRefreshToken = req.cookies.refreshToken;
        const sessions = await Session.find({ userId: user._id });

        for (const session of sessions) {
            const isCurrent = await session.compareToken(currentRefreshToken);
            if (!isCurrent) {
                await session.deleteOne();
            }
        }

        res.status(200).json({ success: true, message: "Password updated successfully. Other devices logged out." });
    } catch (error) {
        console.error("Error in changing password", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}



export const meController = async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json({ success: true, user: { username: user.username, email: user.email, profile_picture: user.profile_picture } });
    } catch (error) {
        console.error("Error in getting user", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const changeUsernameController = async (req, res) => {
    const { newUsername } = req.body;
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        if (user.usernamechangeCount <= 0) {
            return res.status(400).json({ message: "Username change limit reached" });
        }

        if (!validateUsername(newUsername)) {
            return res.status(400).json({ message: "Invalid username" });
        }

        if (user.lastUsernameChangeAt) {
            const lastChanged = new Date(user.lastUsernameChangeAt);
            const now = new Date();
            const diffInDays = (now - lastChanged) / (1000 * 60 * 60 * 24);
            if (diffInDays < 7) {
                return res.status(400).json({ message: "Username can only be changed once every 7 days" });
            }
        }

        const existingUser = await User.findOne({ username: newUsername });
        if (existingUser) {
            return res.status(400).json({ message: "Username is already taken." });
        }

        user.username = newUsername;
        user.usernamechangeCount -= 1;
        user.lastUsernameChangeAt = Date.now();
        await user.save();

        res.status(200).json({ success: true, message: "Username changed successfully" });
    } catch (error) {
        console.error("Error in changing username", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const updateProfilePictureController = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: "Please upload an image." });
        }

        const user = await User.findById(req.user._id);

        // If user already has a custom profile picture (not the default one), delete it from Cloudinary
        if (user.profile_picture && !user.profile_picture.includes("dicebear.com")) {
            try {
                // Extract public ID from the URL (Cloudinary URLs have the public ID before the extension)
                const publicId = user.profile_picture.split('/').pop().split('.')[0];
                await cloudinary.uploader.destroy(`profile_pictures/${publicId}`);
            } catch (err) {
                console.error("Error deleting old profile picture from Cloudinary", err);
                // We proceed even if deletion fails to ensure the new one is set
            }
        }

        user.profile_picture = req.file.path; // Cloudinary URL from multer-storage-cloudinary
        await user.save();

        res.status(200).json({
            success: true,
            message: "Profile picture updated successfully.",
            profile_picture: user.profile_picture
        });
    } catch (error) {
        console.error("Error in updating profile picture", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const getSessionsController = async (req, res) => {
    try {
        const sessions = await Session.find({ userId: req.user._id }).sort({ lastUsedAt: -1 });
        const currentRefreshToken = req.cookies.refreshToken;

        const sessionList = await Promise.all(sessions.map(async (s) => {
            const isCurrent = await s.compareToken(currentRefreshToken);
            return {
                id: s._id,
                ip: s.ip,
                userAgent: s.userAgent,
                lastUsedAt: s.lastUsedAt,
                isCurrentDevice: isCurrent
            };
        }));

        res.status(200).json({ success: true, sessions: sessionList });
    } catch (error) {
        console.error("Error in fetching sessions", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}






export const listUsersController = async (req, res) => {
    try {
        const page = Number(req.query.page) || 1;
        const limit = Number(req.query.limit) || 20;

        const keyword = req.query.search
            ? {
                $or: [
                    { username: { $regex: req.query.search, $options: "i" } },
                    { email: { $regex: req.query.search, $options: "i" } },
                ],
            }
            : {};

        const query = {
            ...keyword,
            _id: { $ne: req.user._id }
        };

        const users = await User.find(query)
            .select("username email profile_picture")
            .limit(limit)
            .skip((page - 1) * limit)
            .sort({ createdAt: -1 });

        const total = await User.countDocuments(query);

        res.status(200).json({
            success: true,
            users,
            total,
            page,
            pages: Math.ceil(total / limit)
        });

    } catch (error) {
        console.error("Error in fetching users", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

export const getChatsController = async (req, res) => {
    try {
        const chats = await Chat.find({
            users: { $elemMatch: { $eq: req.user._id } }
        })
            .populate("users", "-password")  // get all user info except password
            .populate("groupAdmin", "-password")
            .populate({
                path: "latestMessage",
                populate: {
                    path: "sender",
                    select: "username email profile_picture"
                }
            })
            .sort({ updatedAt: -1 });

        res.status(200).json({
            success: true,
            chats
        });

    } catch (error) {
        console.error("Error fetching chats:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

export const createChatController = async (req, res) => {
    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({ message: "userId is required" });
        }

        // check other user exists
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // check if chat already exists between these 2 users
        let chat = await Chat.findOne({
            isGroupChat: false,
            users: { $all: [req.user._id, userId] }
        })
            .populate("users", "-password")
            .populate("latestMessage");

        if (chat) {
            return res.status(200).json({
                success: true,
                chat
            });
        }

        // create new chat
        chat = await Chat.create({
            users: [req.user._id, userId],
            chatName: user.username,
            isGroupChat: false
        });

        const fullChat = await Chat.findById(chat._id)
            .populate("users", "-password");

        res.status(201).json({
            success: true,
            chat: fullChat
        });

    } catch (error) {
        console.error("Error creating chat:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

export const updateChatController = async (req, res) => {
    try {
        const { chatId, chatName } = req.body;

        const chat = await Chat.findById(chatId);

        if (!chat) {
            return res.status(404).json({ message: "Chat not found" });
        }

        // optional: allow only group admin to update
        if (chat.isGroupChat && chat.groupAdmin.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: "Not authorized" });
        }

        chat.chatName = chatName;
        await chat.save();

        res.status(200).json({
            success: true,
            chat
        });

    } catch (error) {
        console.error("Error updating chat:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

export const deleteChatController = async (req, res) => {
    try {
        const { chatId } = req.body;

        const chat = await Chat.findById(chatId);

        if (!chat) {
            return res.status(404).json({ message: "Chat not found" });
        }

        // allow only participants to delete
        if (!chat.users.includes(req.user._id)) {
            return res.status(403).json({ message: "Not authorized" });
        }

        await chat.deleteOne();

        res.status(200).json({
            success: true,
            message: "Chat deleted"
        });

    } catch (error) {
        console.error("Error deleting chat:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

export const getMessagesController = async (req, res) => {
    try {
        const { chatId } = req.params;

        const page = Number(req.query.page) || 1;
        const limit = Number(req.query.limit) || 30;

        const messages = await Message.find({ chat: chatId })
            .populate("sender", "username email profile_picture")
            .sort({ createdAt: -1 })
            .limit(limit)
            .skip((page - 1) * limit);

        res.status(200).json({
            success: true,
            messages
        });

    } catch (error) {
        console.error("Error fetching messages:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

    ;