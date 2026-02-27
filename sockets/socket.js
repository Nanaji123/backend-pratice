import Message from "../models/message.model.js";
import Chat from "../models/chat.model.js";
import jwt from "jsonwebtoken";
import User from "../models/User.model.js";


export const socketHandler = (io) => {

    // 🔐 AUTH MIDDLEWARE
    io.use(async (socket, next) => {
        try {
            const token = socket.handshake.auth.token;

            if (!token) {
                return next(new Error("No token provided"));
            }

            // verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            // get user from DB
            const user = await User.findById(decoded.id).select("-password");

            if (!user) {
                return next(new Error("User not found"));
            }

            // attach user to socket
            socket.user = user;

            next(); // allow connection

        } catch (err) {
            console.log("Socket auth error:", err.message);
            next(new Error("Authentication error"));
        }
    });


    io.on("connection", (socket) => {
        console.log("User connected:", socket.user._id);
        socket.join(socket.user._id.toString());

        socket.on("join_chat", (chatId) => {
            socket.join(chatId);
        });


        // receive message from client
        socket.on("send_message", async (data) => {

            const { chatId, content } = data;

            // save message to DB
            const message = new Message({
                chat: chatId,
                sender: socket.user._id,
                content
            });

            const savedMessage = await message.save();

            const chat = await Chat.findByIdAndUpdate(chatId, {
                latestMessage: savedMessage._id
            });


            // populate sender info
            const fullMessage = await savedMessage.populate("sender");


            // send to all users in that chat room
            io.to(chatId).emit("receive_message", fullMessage);




        });

        socket.on("typing", (chatId) => {
            socket.to(chatId).emit("typing");
        });
        // disconnect
        socket.on("disconnect", () => {
            console.log("User disconnected:", socket.id);
        });
    });
}