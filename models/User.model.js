import mongoose from "mongoose";
import dotenv from "dotenv";
import { hash, compare } from "../utils/hash.js";
dotenv.config();

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    usernamechangeCount: {
        type: Number,
        default: 5
    },
    lastUsernameChangeAt: {
        type: Date
    },
    password: {
        type: String,
        minlength: 6,
        required: true
    },
    profile_picture: {
        type: String,
        default: `https://api.dicebear.com/7.x/avataaars/svg?seed=default`
    },

    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: {
        type: Date
    },

    isVerified: {
        type: Boolean,
        default: false
    },
    is2FAEnabled: {
        type: Boolean,
        default: false
    },
    isOnline: {
        type: Boolean,
        default: false
    },

    // --- System / Gaming Stats ---
    level: {
        type: Number,
        default: 1
    },
    exp: {
        type: Number,
        default: 0
    },
    maxExp: {
        type: Number,
        default: 100
    },
    coins: {
        type: Number,
        default: 100 // Starting bonus
    },
    hp: {
        type: Number,
        default: 100
    },
    maxHp: {
        type: Number,
        default: 100
    },
    mp: {
        type: Number,
        default: 50
    },
    maxMp: {
        type: Number,
        default: 50
    },
    // Attributes (Solo Leveling inspired)
    strength: {
        type: Number,
        default: 1
    },
    stamina: {
        type: Number,
        default: 1
    },
    agility: {
        type: Number,
        default: 1
    },
    intelligence: {
        type: Number,
        default: 1
    },
    sense: {
        type: Number,
        default: 1
    },
    mana: {
        type: Number,
        default: 1
    },
    availableStatPoints: {
        type: Number,
        default: 0
    },
    dailyQuestCompleted: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
})

userSchema.pre("save", async function () {
    if (this.isModified("password")) {
        this.password = await hash(this.password);
    }
});

userSchema.methods.comparePassword = async function (candidatePassword) {
    return await compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema)
export default User