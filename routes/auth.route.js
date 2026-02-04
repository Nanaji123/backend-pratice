import express from "express";
import { registerController, loginController, logoutController, verifyController, refreshController } from "../controller/auth.controller.js";
const router = express.Router();


router.post("/register", registerController);
router.post("/login", loginController);
router.post("/logout", logoutController);
router.get("/verify/:token", verifyController);
router.post("/refresh", refreshController);

export default router;

