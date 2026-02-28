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
import Message from "../models/message.model.js";


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
        const loggedUserId = req.user._id;

        // 1️⃣ Fetch chats where current user is participant
        const chats = await Chat.find({
            users: loggedUserId
        })
            .populate("users", "-password")
            .populate("groupAdmin", "-password")
            .populate({
                path: "latestMessage",
                populate: {
                    path: "sender",
                    select: "username email profile_picture"
                }
            })
            .sort({ updatedAt: -1 });

        // 2️⃣ Format chats (extract other user for private chats)
        const formattedChats = chats.map(chat => {

            // for one-to-one chat
            if (!chat.isGroupChat) {
                const otherUser = chat.users.find(
                    u => u._id.toString() !== loggedUserId.toString()
                );

                return {
                    _id: chat._id,
                    chatName: otherUser?.username || chat.chatName,
                    isGroupChat: false,
                    otherUser: {
                        _id: otherUser?._id,
                        username: otherUser?.username,
                        email: otherUser?.email,
                        profile_picture: otherUser?.profile_picture
                    },
                    latestMessage: chat.latestMessage,
                    createdAt: chat.createdAt,
                    updatedAt: chat.updatedAt
                };
            }

            // for group chat
            return {
                _id: chat._id,
                chatName: chat.chatName,
                isGroupChat: true,
                users: chat.users,
                groupAdmin: chat.groupAdmin,
                latestMessage: chat.latestMessage,
                createdAt: chat.createdAt,
                updatedAt: chat.updatedAt
            };
        });

        // 3️⃣ Send response
        res.status(200).json({
            success: true,
            count: formattedChats.length,
            chats: formattedChats
        });

    } catch (error) {
        console.error("Error fetching chats:", error);
        res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

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
