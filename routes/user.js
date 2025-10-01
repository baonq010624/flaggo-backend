// server/routes/user.js
import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import { requireAuth } from "../middleware/auth.js";
import User from "../models/User.js";

const router = express.Router();

// ensure uploads folder exists
const UPLOAD_DIR = path.join(process.cwd(), "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/\s+/g, "-").replace(/[^a-zA-Z0-9.\-_]/g, "");
    const fileName = `${Date.now()}-${Math.round(Math.random()*1e9)}-${safeName}`;
    cb(null, fileName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) return cb(new Error("Only images allowed"));
    cb(null, true);
  }
});

// POST /api/user/avatar
// Note: requireAuth before upload.single — so multer won't store file if auth fails.
router.post("/avatar", requireAuth, upload.single("avatar"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No file uploaded" });

    const user = await User.findById(req.user.sub);
    if (!user) {
      // Remove file we just stored
      try { if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path); } catch(e){ console.warn("Failed remove file for missing user", e); }
      return res.status(404).json({ message: "User not found" });
    }

    // delete old avatar file if present (optional)
    if (user.avatar) {
      const oldPath = path.join(UPLOAD_DIR, path.basename(user.avatar));
      try { if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath); } catch (e) { console.warn("Failed to remove old avatar", e); }
    }

    // Save new avatar (store filename or public path)
    user.avatar = req.file.filename; // store filename
    await user.save();

    // Return public url to frontend
    const publicUrl = `/uploads/${req.file.filename}`;
    return res.json({ message: "Avatar updated", avatar: publicUrl });
  } catch (err) {
    console.error(err);
    // if a file was written but an exception happened, remove it to avoid leftover files
    if (req.file && req.file.path) {
      try { if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path); } catch (e) { console.warn("Failed to cleanup uploaded file after error", e); }
    }
    return res.status(500).json({ message: "Upload failed" });
  }
});

export default router;
