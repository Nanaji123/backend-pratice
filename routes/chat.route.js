import express from "express";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { getChatsController, listUsersController, createChatController, updateChatController, deleteChatController, getMessagesController } from "../controller/chat.controller.js";
const router = express.Router();


router.get("/list-users", authMiddleware, listUsersController);
router.get("/get-chats", authMiddleware, getChatsController);
router.post("/create-chat", authMiddleware, createChatController);
router.post("/update-chat", authMiddleware, updateChatController);
router.post("/delete-chat", authMiddleware, deleteChatController);
router.get("/messages/:chatId", authMiddleware, getMessagesController);



export default router;
