import mongoose from "mongoose";

const questSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    },
    title: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    objectives: [
        {
            text: { type: String, required: true },
            target: { type: Number, default: 1 },
            current: { type: Number, default: 0 },
            isCompleted: { type: Boolean, default: false }
        }
    ],
    rewards: {
        exp: { type: Number, default: 0 },
        coins: { type: Number, default: 0 },
        statPoints: { type: Number, default: 0 },
        stats: {
            strength: { type: Number, default: 0 },
            stamina: { type: Number, default: 0 },
            agility: { type: Number, default: 0 },
            intelligence: { type: Number, default: 0 },
            sense: { type: Number, default: 0 },
            mana: { type: Number, default: 0 }
        },
        items: [{ type: String }]
    },
    penalty: {
        hpLoss: { type: Number, default: 0 },
        expLoss: { type: Number, default: 0 },
        stats: {
            strength: { type: Number, default: 0 },
            stamina: { type: Number, default: 0 },
            agility: { type: Number, default: 0 },
            intelligence: { type: Number, default: 0 },
            sense: { type: Number, default: 0 },
            mana: { type: Number, default: 0 }
        }
    },
    status: {
        type: String,
        enum: ["active", "completed", "failed"],
        default: "active"
    },
    type: {
        type: String,
        enum: ["daily", "urgent", "story"],
        default: "daily"
    },
    verificationQuestions: [
        {
            question: { type: String, required: true },
        }
    ],
    expiresAt: {
        type: Date
    },
    timeLimit: {
        type: Number, // in minutes
        default: 1440 // 24 hours default
    },
    startedAt: {
        type: Date,
        default: Date.now
    },
    isClaimed: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

const Quest = mongoose.model("Quest", questSchema);
export default Quest;
