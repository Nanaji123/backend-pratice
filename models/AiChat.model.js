import mongoose from "mongoose";

const aiChatSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    },
    title: {
        type: String,
        default: "New System Interaction"
    },
    messages: [
        {
            role: {
                type: String, // 'user' or 'model'
                required: true
            },
            content: {
                type: String,
                required: true
            },
            timestamp: {
                type: Date,
                default: Date.now
            }
        }
    ],
    persona: {
        type: String,
        default: "Absolute Administrator"
    }
}, { timestamps: true });

// Index for faster queries
aiChatSchema.index({ userId: 1, updatedAt: -1 });

const AiChat = mongoose.model("AiChat", aiChatSchema);
export default AiChat;
