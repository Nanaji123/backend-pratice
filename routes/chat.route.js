import express from "express";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { memoryUpload } from "../middleware/upload.middleware.js";
import { getChatsController, listUsersController, createChatController, updateChatController, deleteChatController, getMessagesController, createGroupChatController, getChatDetailsController } from "../controller/chat.controller.js";
const router = express.Router();


router.get("/list-users", authMiddleware, listUsersController);
router.get("/get-chats", authMiddleware, getChatsController);
router.post("/create-chat", authMiddleware, createChatController);
router.post("/create-group-chat", authMiddleware, memoryUpload.single("image"), createGroupChatController);
router.post("/update-chat", authMiddleware, updateChatController);
router.post("/delete-chat", authMiddleware, deleteChatController);
router.get("/messages/:chatId", authMiddleware, getMessagesController);
router.get("/get-chat-details/:chatId", authMiddleware, getChatDetailsController);



export default router;
