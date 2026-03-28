import express from "express";
import { 
    geminiChatController, 
    createAiChatController, 
    getAiChatsController, 
    getAiChatDetailsController,
    deleteAiChatController
} from "../controller/ai.controller.js";
import { authMiddleware } from "../middleware/auth.middleware.js";

const router = express.Router();

// All AI routes require authentication
router.use(authMiddleware);

router.post("/create", createAiChatController);
router.get("/chats", getAiChatsController);
router.get("/chat/:chatId", getAiChatDetailsController);
router.post("/chat", geminiChatController);
router.delete("/chat/:chatId", deleteAiChatController);

export default router;
