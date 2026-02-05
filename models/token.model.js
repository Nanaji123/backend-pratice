import mongoose from "mongoose";
import { compare } from "../utils/hash.js";

const tokenSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    token: {
        type: String,
        required: true
    },
    type: {
        type: String,
        enum: ['VERIFICATION', 'PASSWORD_RESET', '2FA'],
        required: true
    },
    expiresAt: {
        type: Date,
        required: true,
        index: { expires: 0 } // Document expires at this specific date/time
    }
}, {
    timestamps: true
});

// Instance method to compare token
tokenSchema.methods.compareToken = async function (rawToken) {
    return await compare(rawToken, this.token);
};

const Token = mongoose.model("Token", tokenSchema);
export default Token;
