import { generateGeminiResponse } from "../config/geminiService.js";

export const geminiChatController = async (req, res) => {

    try {

        const { message } = req.body;

        if (!message) {
            return res.status(400).json({
                message: "Message is required"
            });
        }

        const aiReply = await generateGeminiResponse(message);

        res.status(200).json({
            success: true,
            reply: aiReply
        });

    } catch (error) {

        console.error("Gemini AI Error:", error);

        res.status(500).json({
            message: "AI response failed"
        });
    }
};