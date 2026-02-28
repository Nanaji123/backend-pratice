import express from "express";
import { registerController, loginController, logoutController, verifyController, refreshController, toggle2FAController, verify2FAController, forgetPasswordController, resetPasswordController, changePasswordController, changeUsernameController, updateProfilePictureController, getSessionsController, listUsersController } from "../controller/auth.controller.js";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { meController } from "../controller/auth.controller.js";
import { upload } from "../middleware/upload.middleware.js";
const router = express.Router();


router.post("/register", registerController);
router.post("/login", loginController);
router.post("/logout", logoutController);
router.get("/verify/:userId/:token", verifyController);
router.post("/refresh", refreshController);
router.post("/toggle-2fa", authMiddleware, toggle2FAController);
router.post("/verify-2fa", verify2FAController);
router.post("/forgetpassword", forgetPasswordController)
router.post("/reset-password/:userId/:token", resetPasswordController);
router.post("/change-password", authMiddleware, changePasswordController);


router.get("/me", authMiddleware, meController);
router.post("/change-username", authMiddleware, changeUsernameController);
router.post("/update-profile-picture", authMiddleware, upload.single("image"), updateProfilePictureController);
router.get("/sessions", authMiddleware, getSessionsController);








export default router;

