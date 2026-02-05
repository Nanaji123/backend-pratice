import mongoose from "mongoose";
import { compare } from "../utils/hash.js";

const sessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    refreshToken: {
        type: String,
        required: true
    },
    ip: {
        type: String
    },
    userAgent: {
        type: String
    },
    lastUsedAt: {
        type: Date,
        default: Date.now
    },
    expiresAt: {
        type: Date,
        required: true
    }
}, {
    timestamps: true
});

// Instance method to compare token
sessionSchema.methods.compareToken = async function (token) {
    return await compare(token, this.refreshToken);
};

const Session = mongoose.model("Session", sessionSchema);
export default Session;
