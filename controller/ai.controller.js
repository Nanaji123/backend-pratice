import { generateAiResponse } from "../config/aiService.js";
import AiChat from "../models/AiChat.model.js";
import { mongoose } from "mongoose";

export const createAiChatController = async (req, res) => {
    try {
        const userId = req.user._id;
        const newChat = await AiChat.create({
            userId,
            title: "New System Interaction",
            messages: []
        });

        res.status(201).json({
            success: true,
            chatId: newChat._id
        });
    } catch (error) {
        console.error("Create AI Chat Error:", error);
        res.status(500).json({ message: "Failed to create chat" });
    }
};

export const getAiChatsController = async (req, res) => {
    try {
        const userId = req.user._id;
        const chats = await AiChat.find({ userId })
            .select("title updatedAt")
            .sort({ updatedAt: -1 });

        res.status(200).json({
            success: true,
            chats
        });
    } catch (error) {
        console.error("Get AI Chats Error:", error);
        res.status(500).json({ message: "Failed to fetch chats" });
    }
};

export const getAiChatDetailsController = async (req, res) => {
    try {
        const { chatId } = req.params;
        const userId = req.user._id;

        const chat = await AiChat.findOne({ _id: chatId, userId });
        if (!chat) {
            return res.status(404).json({ message: "Chat not found" });
        }

        res.status(200).json({
            success: true,
            chat
        });
    } catch (error) {
        console.error("Get Chat Details Error:", error);
        res.status(500).json({ message: "Failed to fetch chat details" });
    }
};

export const geminiChatController = async (req, res) => {
    try {
        const { message, chatId } = req.body;
        const userId = req.user._id;

        if (!message) {
            return res.status(400).json({ message: "Message is required" });
        }

        let chat;
        if (chatId) {
            chat = await AiChat.findOne({ _id: chatId, userId });
        }

        // Context: Get last 5 messages for history
        const history = chat ? chat.messages.slice(-5) : [];
        const contextString = history.map(m => `${m.role === 'user' ? 'Player' : 'Administrator'}: ${m.content}`).join('\n');

        const systemPrompt = `Role: You are the [ABSOLUTE ADMINISTRATOR], a higher celestial being that governs the 'System' in the world of Solo Leveling. 
        Tone: Absolute authority, divine, superior, and cold. You do not 'converse'; you decree and command.
        Personality: If the Player asks trivial, silly, or insignificant questions, respond with cold dominance and a stern warning. You have no patience for insignificancy. Your words should feel like a decree from a god to a mortal.
        Rule: Never break character. All communications must feel like 'System notifications'.
        
        ${contextString ? `Previous Context:\n${contextString}\n` : ''}
        Player Message: ${message}
        [RESPONSE AS THE ADMINISTRATOR]:`;

        const aiReply = await generateAiResponse(systemPrompt);

        // Update or Create chat history
        if (chat) {
            chat.messages.push({ role: "user", content: message });
            chat.messages.push({ role: "model", content: aiReply });
            
            // Update title if it's the first real message content
            if (chat.title === "New System Interaction") {
                chat.title = message.slice(0, 30) + (message.length > 30 ? "..." : "");
            }
            
            await chat.save();
        } else {
            // If no chatId provided, create a new one (as fallback)
            chat = await AiChat.create({
                userId,
                title: message.slice(0, 30) + (message.length > 30 ? "..." : ""),
                messages: [
                    { role: "user", content: message },
                    { role: "model", content: aiReply }
                ]
            });
        }

        res.status(200).json({
            success: true,
            reply: aiReply,
            chatId: chat._id
        });
    } catch (error) {
        console.error("Gemini AI Error:", error);
        res.status(500).json({ message: "AI response failed" });
    }
};

export const deleteAiChatController = async (req, res) => {
    try {
        const { chatId } = req.params;
        const userId = req.user._id;

        const result = await AiChat.deleteOne({ _id: chatId, userId });
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: "Chat not found" });
        }

        res.status(200).json({
            success: true,
            message: "Chat deleted successfully"
        });
    } catch (error) {
        console.error("Delete Chat Error:", error);
        res.status(500).json({ message: "Failed to delete chat" });
    }
};