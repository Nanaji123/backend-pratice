import mongoose from "mongoose";

const chatSchema = new mongoose.Schema({
  chatName: {
    type: String,
    default: ""
  },
  isGroupChat: {
    type: Boolean,
    default: false
  },
  chat_profile_picture: {
    type: String,
  },
  users: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User"
    }
  ],
  latestMessage: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Message"
  },
  groupAdmin: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },
  groupDescription: {
    type: String,
    default: ""
  }
}, { timestamps: true });

export default mongoose.model("Chat", chatSchema);