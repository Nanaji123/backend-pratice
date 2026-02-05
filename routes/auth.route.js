import express from "express";
import { registerController, loginController, logoutController, verifyController, refreshController, toggle2FAController, verify2FAController } from "../controller/auth.controller.js";
import { authMiddleware } from "../middleware/auth.middleware.js";
const router = express.Router();


router.post("/register", registerController);
router.post("/login", loginController);
router.post("/logout", logoutController);
router.get("/verify/:token", verifyController);
router.post("/refresh", refreshController);
router.post("/toggle-2fa", authMiddleware, toggle2FAController);
router.post("/verify-2fa", verify2FAController);


export default router;

