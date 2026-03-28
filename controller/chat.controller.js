import User from "../models/User.model.js";
import cloudinary from "../config/cloudinary.js";
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
            .select("username email profile_picture isOnline lastSeen")
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
                        profile_picture: otherUser?.profile_picture,
                        isOnline: otherUser?.isOnline,
                        lastSeen: otherUser?.lastSeen
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
                updatedAt: chat.updatedAt,
                chat_profile_picture: chat.chat_profile_picture,
                groupDescription: chat.groupDescription || ""
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
        const { chatId, chatName, groupDescription } = req.body;

        const chat = await Chat.findById(chatId);

        if (!chat) {
            return res.status(404).json({ message: "Chat not found" });
        }

        // optional: allow only group admin to update
        if (chat.isGroupChat && chat.groupAdmin.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: "Not authorized" });
        }

        if (chatName) chat.chatName = chatName;
        if (groupDescription !== undefined) chat.groupDescription = groupDescription;
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

        // Mark each message with isMine so the frontend can render easily
        const formattedMessages = messages.map(msg => ({
            _id: msg._id,
            content: msg.content,
            chat: msg.chat,
            sender: msg.sender,
            readBy: msg.readBy,
            createdAt: msg.createdAt,
            updatedAt: msg.updatedAt,
            isMine: msg.sender._id.toString() === req.user._id.toString()
        }));

        res.status(200).json({
            success: true,
            messages: formattedMessages
        });

    } catch (error) {
        console.error("Error fetching messages:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

export const createGroupChatController = async (req, res) => {
    try {
        // 1. Parse users if sent as string (common with FormData)
        let { users, groupName, groupDescription } = req.body;
        if (typeof users === 'string') users = JSON.parse(users);

        if (!users || !groupName) {
            return res.status(400).json({ message: "Users and group name are required" });
        }

        if (!Array.isArray(users) || users.length < 2) {
            return res.status(400).json({ message: "Group chat requires at least 3 members" });
        }

        let chat_profile_picture = req.body.chat_profile_picture || "";

        // 2. Handle Device Upload via Cloudinary Stream
        if (req.file) {
            const uploadToCloudinary = (fileBuffer) => {
                return new Promise((resolve, reject) => {
                    const uploadStream = cloudinary.uploader.upload_stream(
                        { folder: "chat_profile_pictures" },
                        (error, result) => {
                            if (error) return reject(error);
                            resolve(result);
                        }
                    );
                    uploadStream.end(fileBuffer);
                });
            };

            const result = await uploadToCloudinary(req.file.buffer);
            chat_profile_picture = result.secure_url;
        }

        // 3. Normalize User list
        const uniqueUsers = [...new Set(users.map(u => u.toString()))];
        if (!uniqueUsers.includes(req.user._id.toString())) {
            uniqueUsers.push(req.user._id.toString());
        }

        // 4. Create Chat
        const chat = await Chat.create({
            chatName: groupName,
            users: uniqueUsers,
            isGroupChat: true,
            groupAdmin: req.user._id,
            chat_profile_picture,
            groupDescription: groupDescription || ""
        });

        const fullChat = await Chat.findById(chat._id)
            .populate("users", "-password")
            .populate("groupAdmin", "-password");

        res.status(201).json({ success: true, chat: fullChat });

    } catch (error) {
        console.error("Error creating group chat:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

export const getChatDetailsController = async (req, res) => {
    try {
        const { chatId } = req.params;

        const chat = await Chat.findById(chatId)
            .populate({
                path: "users",
                select: "username profile_picture isOnline lastSeen"
            })
            .populate({
                path: "groupAdmin",
                select: "username profile_picture"
            });

        if (!chat) {
            return res.status(404).json({
                message: "Chat not found"
            });
        }

        let responseData = {
            _id: chat._id,
            isGroupChat: chat.isGroupChat,
            chatName: chat.chatName,
            chat_profile_picture: chat.chat_profile_picture,
            createdAt: chat.createdAt,
            groupDescription: chat.groupDescription || ""
        };

        // Group Chat Details
        if (chat.isGroupChat) {
            responseData.totalMembers = chat.users.length;
            responseData.groupAdmin = chat.groupAdmin;
            responseData.members = chat.users;
        }
        // Private Chat Details
        else {
            const otherUser = chat.users.find(
                user => user._id.toString() !== req.user._id.toString()
            );
            responseData.user = otherUser;
        }

        res.status(200).json({
            success: true,
            chat: responseData
        });

    } catch (error) {
        console.error("Error fetching chat details:", error);
        res.status(500).json({
            message: "Internal server error"
        });
    }
};

export const getGlobalChatController = async (req, res) => {
    try {
        let globalChat = await Chat.findOne({ chatName: "Global Chat", isGroupChat: true });

        if (!globalChat) {
            // Create the first Global Chat
            globalChat = await Chat.create({
                chatName: "Global Chat",
                isGroupChat: true,
                users: [req.user._id],
                groupDescription: "The official communication channel for all hunters."
            });
        } else {
            // If user not in global chat, add them
            if (!globalChat.users.includes(req.user._id)) {
                globalChat.users.push(req.user._id);
                await globalChat.save();
            }
        }

        const fullChat = await Chat.findById(globalChat._id)
            .populate("users", "username profile_picture isOnline")
            .populate({
                path: "latestMessage",
                populate: {
                    path: "sender",
                    select: "username profile_picture"
                }
            });

        res.status(200).json({ success: true, chat: fullChat });
    } catch (error) {
        console.error("Error fetching global chat:", error);
        res.status(500).json({ message: "Global communication channel is offline." });
    }
};
