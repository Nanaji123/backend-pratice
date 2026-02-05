import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import { hash } from "../utils/hash.js";
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
    password: {
        type: String,
        minlength: 6,
        required: true
    },
    profile_picture: {
        type: String,

    },
    isVerified: {
        type: Boolean,
        default: false
    },
    is2FAEnabled: {
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

const User = mongoose.model("User", userSchema)
export default User