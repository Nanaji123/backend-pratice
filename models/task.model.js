import mongoose from "mongoose";

const taskSchema = new mongoose.Schema({

    title: String,
    description: String,

    priority: {
        type: String,
        enum: ["low", "medium", "high"]
    },

    category: String,

    status: {
        type: String,
        enum: ["pending", "in_progress", "completed"],
        default: "pending"
    },

    due_date: Date,

    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    }

}, { timestamps: true });

export default mongoose.model("Task", taskSchema);