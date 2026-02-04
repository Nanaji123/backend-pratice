import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
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
    refreshToken: {
        type: String,
    },
    verificationToken: {
        type: String,
    },
    verificationTokenExpiry: {
        type: Date,
    },
    resetPasswordToken: {
        type: String,
    },
    resetPasswordTokenExpiry: {
        type: Date,
    },
}, {
    timestamps: true
})

userSchema.pre("save", async function () {
    if (this.isModified("password")) {
        this.password = await bcrypt.hash(this.password, 10);
    }
});

const User = mongoose.model("User", userSchema)
export default User