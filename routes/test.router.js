import express from "express";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { addTaskController, getAllTasksController, updateTaskController, deleteTaskController, markAsCompletedController } from "../controller/task.controller.js";
const router = express.Router();


router.post("/add-task", authMiddleware, addTaskController);
router.get("/get-tasks", authMiddleware, getAllTasksController);
router.post("/update-task", authMiddleware, updateTaskController);
router.post("/delete-task", authMiddleware, deleteTaskController);
router.post("/mark-as-completed", authMiddleware, markAsCompletedController);


export default router;
