import express from "express";
import { 
    generateDailyQuest, 
    getActiveQuests, 
    getCompletedQuests,
    getFailedQuests,
    completeQuest, 
    failQuest,
    claimQuestReward,
    assignStatPoint,
    getAdminStatusMessage
} from "../controller/Quest.controller.js";
import { authMiddleware } from "../middleware/auth.middleware.js";

const router = express.Router();

router.use(authMiddleware);

router.get("/active", getActiveQuests);
router.get("/completed", getCompletedQuests);
router.get("/failed", getFailedQuests);
router.post("/generate", generateDailyQuest);
router.post("/complete/:questId", completeQuest);
router.post("/fail/:questId", failQuest);
router.post("/claim/:questId", claimQuestReward);
router.post("/assign-stat", assignStatPoint);
router.get("/admin-message", getAdminStatusMessage);

export default router;
