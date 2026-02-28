import Message from "../models/message.model.js";
import Chat from "../models/chat.model.js";
import jwt from "jsonwebtoken";
import User from "../models/User.model.js";

export const socketHandler = (io) => {

    console.log("Socket server initialized");

    // 🔐 AUTH MIDDLEWARE
    io.use(async (socket, next) => {
        try {
            console.log("Socket auth middleware");
            const cookies = socket.handshake.headers.cookie;

            const token = cookies
                ?.split("; ")
                .find(row => row.startsWith("accessToken="))
                ?.split("=")[1];

            console.log("token", token);

            if (!token) {
                return next(new Error("No token provided"));
            }

            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            const user = await User.findById(decoded.id).select("-password");

            if (!user) {
                return next(new Error("User not found"));
            }

            socket.user = user;
            next();

        } catch (err) {
            console.log("Socket auth error:", err.message);
            next(new Error("Authentication error"));
        }
    });


    io.on("connection", (socket) => {
        console.log("User connected:", socket.user._id);

        // join personal room
        socket.join(socket.user._id.toString());

        // join chat room
        socket.on("join_chat", (chatId) => {
            socket.join(chatId);
        });


        // 💬 SEND MESSAGE
        socket.on("send_message", async (data) => {
            try {
                const { chatId, content } = data;

                // create message
                const message = new Message({
                    chat: chatId,
                    sender: socket.user._id,
                    content
                });

                const savedMessage = await message.save();

                // update latest message
                await Chat.findByIdAndUpdate(chatId, {
                    latestMessage: savedMessage._id
                });

                // populate sender
                const fullMessage = await savedMessage.populate("sender");

                // 🔥 send to chat room
                io.to(chatId).emit("receive_message", fullMessage);

                // 🔔 notify individual users (optional notification system)
                const chat = await Chat.findById(chatId).populate("users");

                chat.users.forEach(user => {
                    if (user._id.toString() !== socket.user._id.toString()) {
                        io.to(user._id.toString()).emit("message_notification", fullMessage);
                    }
                });

            } catch (err) {
                console.error("Socket send_message error:", err);
            }
        });


        // ✍️ TYPING
        socket.on("typing", (chatId) => {
            socket.to(chatId).emit("typing", {
                userId: socket.user._id,
                username: socket.user.username
            });
        });

        socket.on("stop_typing", (chatId) => {
            socket.to(chatId).emit("stop_typing", socket.user._id);
        });


        // ❌ DISCONNECT
        socket.on("disconnect", () => {
            console.log("User disconnected:", socket.user._id);
        });
    });
};