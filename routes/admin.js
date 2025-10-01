// server/routes/admin.js
import express from "express";
import { requireAuth, requireRole } from "../middleware/auth.js";
import User from "../models/User.js";
import path from "path";
import fs from "fs";

const router = express.Router();

/**
 * GET /api/admin/stats
 * Protected: requireAuth + requireRole('admin')
 * Trả về một số thống kê cơ bản
 */
router.get("/stats", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const adminsCount = await User.countDocuments({ role: "admin" });
    const usersWithAvatar = await User.countDocuments({ avatar: { $exists: true, $ne: "" } });

    let avatarsFiles = 0;
    const UPLOAD_DIR = path.join(process.cwd(), "uploads");
    if (fs.existsSync(UPLOAD_DIR)) {
      avatarsFiles = fs.readdirSync(UPLOAD_DIR).filter(f => !f.startsWith(".")).length;
    }

    res.json({
      userCount,
      adminsCount,
      usersWithAvatar,
      avatarsFiles
    });
  } catch (err) {
    console.error("Admin stats error:", err);
    res.status(500).json({ message: "Failed to fetch stats" });
  }
});

export default router;
