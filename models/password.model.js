import mongoose from "mongoose";
import { hash, compare } from "../utils/hash.js";

const passwordSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    },
    password: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
})

passwordSchema.pre("save", async function () {
    if (this.isModified("password")) {
        this.password = await hash(this.password);
    }
});

passwordSchema.methods.comparePassword = async function (candidatePassword) {
    return await compare(candidatePassword, this.password);
};

const Password = mongoose.model("Password", passwordSchema)
export default Password