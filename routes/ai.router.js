import express from "express";
import { geminiChatController } from "../controller/ai.controller.js";
const router = express.Router();

router.post("/ai-chat", geminiChatController);

export default router;