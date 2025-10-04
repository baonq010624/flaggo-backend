// server/server.js
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import multer from "multer";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import streamifier from "streamifier";
import { v2 as cloudinary } from "cloudinary";

import User from "./models/User.js";
import Visit from "./models/Visit.js";
import Favorite from "./models/Favorite.js";
import FavoriteVote from "./models/FavoriteVote.js";

dotenv.config();

// ============== Cloudinary config ==============
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key:    process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Helper: upload buffer -> Cloudinary (stream)
function uploadBufferToCloudinary(buffer, folder = "flaggo/avatars") {
    return new Promise((resolve, reject) => {
        const cldStream = cloudinary.uploader.upload_stream(
            {
                folder,
                resource_type: "image",
                transformation: [{ width: 512, height: 512, crop: "limit", quality: "auto" }],
            },
            (err, result) => (err ? reject(err) : resolve(result))
        );
        streamifier.createReadStream(buffer).pipe(cldStream);
    });
}

const app = express();
app.use(express.json());
app.use(cookieParser());

// Tin cậy proxy khi deploy (giúp set cookie Secure chuẩn)
if (process.env.NODE_ENV === "production") {
    app.set("trust proxy", 1);
}

// ================= CORS =================
const allowedOrigins = (
    process.env.ALLOWED_ORIGINS ||
    process.env.CLIENT_URL ||
    "http://localhost:3000"
)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

console.log("[CORS] allowedOrigins:", allowedOrigins);

const corsOptionsDelegate = function (origin, callback) {
    if (!origin) return callback(null, true); // Cho phép Postman/SSR
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Not allowed by CORS"));
};

app.use(cors({ origin: corsOptionsDelegate, credentials: true }));

// ================= DB =================
mongoose
    .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(async () => {
        console.log("MongoDB connected");
        await ensureAdmin();
    })
    .catch((err) => console.error("MongoDB error:", err));

// ================= JWT helpers =================
function generateAccessToken(user) {
    return jwt.sign(
        { sub: user._id, email: user.email },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "15m" }
    );
}
function generateRefreshToken(user) {
    return jwt.sign({ sub: user._id }, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: "7d",
    });
}

// Cookie options theo môi trường
const isProd = process.env.NODE_ENV === "production";
const cookieOpts = () => ({
    httpOnly: true,
    secure: isProd,                 // prod: true, dev: false
    sameSite: isProd ? "none" : "lax", // prod: none, dev: lax
    maxAge: 7 * 24 * 3600 * 1000,
    path: "/",
});
const clearCookieOpts = () => ({
    path: "/",
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
});

// ================= middleware =================
function requireAuth(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ message: "Missing token" });

    const token = authHeader.split(" ")[1];
    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.user = decoded;
        next();
    } catch {
        return res.status(403).json({ message: "Invalid token" });
    }
}

// ================= multer (upload) =================
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 2 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith("image/")) return cb(new Error("Only images allowed"));
        cb(null, true);
    },
});

// ================= AUTH ROUTES =================

// Register (auto-login)
app.post("/api/auth/register", async (req, res) => {
    try {
        const { email, password, name = "", phone = "" } = req.body;
        if (!email || !password) return res.status(400).json({ message: "Missing email or password" });

        const emailTrim = String(email).trim().toLowerCase();
        if (password.length < 6) return res.status(400).json({ message: "Password must be >= 6 chars" });

        const existing = await User.findOne({ email: emailTrim });
        if (existing) return res.status(409).json({ message: "Email already registered" });

        const passwordHash = await bcrypt.hash(password, 12);
        const user = new User({ email: emailTrim, passwordHash, name: String(name).trim(), phone: String(phone).trim() });
        await user.save();

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        user.refreshTokens.push(refreshToken);
        await user.save();

        res.cookie("refreshToken", refreshToken, cookieOpts());

        return res.status(201).json({
            accessToken,
            user: { id: user._id, email: user.email, name: user.name, phone: user.phone, role: user.role || "user" },
            message: "Đăng ký thành công",
        });
    } catch (err) {
        console.error("Register error:", err);
        if (err.code === 11000) return res.status(409).json({ message: "Email already in use" });
        res.status(500).json({ message: "Failed to register" });
    }
});

// Login
app.post("/api/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: "Missing credentials" });

        const user = await User.findOne({ email: String(email).trim().toLowerCase() });
        if (!user) return res.status(401).json({ message: "Invalid email or password" });

        const valid = await bcrypt.compare(password, user.passwordHash);
        if (!valid) return res.status(401).json({ message: "Invalid email or password" });

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        user.refreshTokens.push(refreshToken);
        await user.save();

        res.cookie("refreshToken", refreshToken, cookieOpts());

        res.json({
            accessToken,
            user: { id: user._id, email: user.email, name: user.name, phone: user.phone, role: user.role || "user" },
        });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Failed to login" });
    }
});

// Refresh (ưu tiên cookie)
app.post("/api/auth/refresh", async (req, res) => {
    try {
        const token = req.cookies?.refreshToken || req.body?.refreshToken;
        if (!token) return res.status(401).json({ message: "Missing refresh token" });

        let payload;
        try {
            payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
        } catch {
            return res.status(401).json({ message: "Invalid refresh token" });
        }

        const user = await User.findById(payload.sub);
        if (!user) return res.status(401).json({ message: "User not found" });

        if (!user.refreshTokens.includes(token)) {
            user.refreshTokens = [];
            await user.save();
            return res.status(401).json({ message: "Refresh token not recognized" });
        }

        // rotate
        user.refreshTokens = user.refreshTokens.filter((t) => t !== token);
        const newRefresh = generateRefreshToken(user);
        user.refreshTokens.push(newRefresh);
        await user.save();

        const accessToken = generateAccessToken(user);

        res.cookie("refreshToken", newRefresh, cookieOpts());

        res.json({
            accessToken,
            user: { id: user._id, email: user.email, name: user.name, phone: user.phone, role: user.role || "user" },
        });
    } catch (err) {
        console.error("Refresh error:", err);
        res.status(500).json({ message: "Failed to refresh token" });
    }
});

// Logout
app.post("/api/auth/logout", async (req, res) => {
    try {
        const token = req.cookies?.refreshToken || req.body?.refreshToken;
        if (token) {
            const payload = (() => {
                try { return jwt.verify(token, process.env.REFRESH_TOKEN_SECRET); } catch { return null; }
            })();
            if (payload) {
                const user = await User.findById(payload.sub);
                if (user) {
                    user.refreshTokens = user.refreshTokens.filter((t) => t !== token);
                    await user.save();
                }
            }
        }
        res.clearCookie("refreshToken", clearCookieOpts());
        res.json({ message: "Logged out" });
    } catch (err) {
        console.error("Logout error:", err);
        res.status(500).json({ message: "Failed to logout" });
    }
});

// ================= USER routes =================
app.get("/api/me", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.sub).select("-passwordHash -refreshTokens");
        if (!user) return res.status(404).json({ message: "User not found" });

        res.json({
            id: user._id,
            email: user.email,
            name: user.name,
            phone: user.phone,
            createdAt: user.createdAt,
            role: user.role || "user",
            avatar: user.avatar || "",
        });
    } catch (err) {
        console.error("Error fetching user:", err);
        res.status(500).json({ message: "Failed to fetch user" });
    }
});

// Upload avatar -> Cloudinary
app.post("/api/user/avatar", requireAuth, upload.single("avatar"), async (req, res) => {
    try {
        if (!req.file || !req.file.buffer) {
            return res.status(400).json({ message: "No file uploaded" });
        }
        const user = await User.findById(req.user.sub);
        if (!user) return res.status(404).json({ message: "User not found" });

        const result = await uploadBufferToCloudinary(req.file.buffer, "flaggo/avatars");
        const secureUrl = result.secure_url;

        user.avatar = secureUrl;
        await user.save();

        res.json({ message: "Avatar updated", avatar: secureUrl });
    } catch (err) {
        console.error("Avatar upload error:", err);
        res.status(500).json({ message: "Failed to update avatar" });
    }
});

// ================= TRACK VISITS =================
function startOfDayUTC(date = new Date()) {
    return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}
app.post("/api/track/visit", async (req, res) => {
    try {
        const today = startOfDayUTC(new Date());
        await Visit.updateOne(
            { date: today },
            { $setOnInsert: { date: today }, $inc: { count: 1 } },
            { upsert: true }
        );
        res.json({ ok: true });
    } catch (err) {
        console.error("track visit error:", err);
        res.status(500).json({ ok: false });
    }
});

// ================= ADMIN =================
app.get("/api/admin/stats", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.sub).select("role");
        if (!user) return res.status(404).json({ message: "User not found" });
        if (user.role !== "admin") return res.status(403).json({ message: "Access denied: insufficient role" });

        const userCount = await User.countDocuments();
        res.json({ userCount });
    } catch (err) {
        console.error("Admin stats error:", err);
        res.status(500).json({ message: "Failed to fetch stats" });
    }
});

app.get("/api/admin/visits", requireAuth, async (req, res) => {
    try {
        const me = await User.findById(req.user.sub).select("role");
        if (!me) return res.status(404).json({ message: "User not found" });
        if (me.role !== "admin") return res.status(403).json({ message: "Access denied" });

        const mode = (req.query.mode || "day").toLowerCase(); // day | month | year
        const limit = Math.max(1, Math.min(parseInt(req.query.limit || "30", 10), 365));

        let pipeline = [];
        if (mode === "day") {
            pipeline = [
                { $sort: { date: 1 } },
                { $project: { date: 1, count: 1 } },
                { $project: { label: { $dateToString: { date: "$date", format: "%Y-%m-%d" } }, value: "$count" } },
                { $sort: { label: -1 } },
                { $limit: limit },
                { $sort: { label: 1 } },
            ];
        } else if (mode === "month") {
            pipeline = [
                { $group: { _id: { y: { $year: "$date" }, m: { $month: "$date" } }, value: { $sum: "$count" } } },
                { $project: { _id: 0, y: "$_id.y", m: "$_id.m", value: 1 } },
                { $addFields: { label: { $concat: [{ $toString: "$y" }, "-", { $toString: { $cond: [{ $lt: ["$m", 10] }, { $concat: ["0", { $toString: "$m" }] }, { $toString: "$m" }] } }] } } },
                { $sort: { y: -1, m: -1 } },
                { $limit: Math.min(limit, 60) },
                { $sort: { y: 1, m: 1 } },
            ];
        } else {
            pipeline = [
                { $group: { _id: { y: { $year: "$date" } }, value: { $sum: "$count" } } },
                { $project: { _id: 0, y: "$_id.y", label: { $toString: "$_id.y" }, value: 1 } },
                { $sort: { y: -1 } },
                { $limit: Math.min(limit, 20) },
                { $sort: { y: 1 } },
            ];
        }

        const rows = await Visit.aggregate(pipeline);
        return res.json({ mode, rows });
    } catch (err) {
        console.error("admin visits error:", err);
        res.status(500).json({ message: "Failed to fetch visits" });
    }
});

// TOP favorites (giữ nguyên)
app.get("/api/admin/favorites", requireAuth, async (req, res) => {
    try {
        const me = await User.findById(req.user.sub).select("role");
        if (!me) return res.status(404).json({ message: "User not found" });
        if (me.role !== "admin") return res.status(403).json({ message: "Access denied" });

        const limit = Math.max(1, Math.min(parseInt(req.query.limit || "20", 10), 100));
        const docs = await Favorite.find({}).sort({ count: -1, updatedAt: -1 }).limit(limit).lean();

        const rows = docs.map((d) => ({ label: d.name, value: d.count }));
        res.json({ rows });
    } catch (err) {
        console.error("admin favorites error:", err);
        res.status(500).json({ message: "Failed to fetch favorites" });
    }
});

// ================= START SERVER =================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// ================= helper: ensureAdmin =================
async function ensureAdmin() {
    const { ADMIN_EMAIL, ADMIN_PASS } = process.env;
    if (!ADMIN_EMAIL || !ADMIN_PASS) return;
    try {
        const emailTrim = String(ADMIN_EMAIL).trim().toLowerCase();
        const existing = await User.findOne({ email: emailTrim });
        if (existing) {
            if (existing.role !== "admin") {
                existing.role = "admin";
                await existing.save();
                console.log("Upgraded existing user to admin:", emailTrim);
            } else {
                console.log("Admin already exists:", emailTrim);
            }
            return;
        }

        const passwordHash = await bcrypt.hash(String(ADMIN_PASS), 12);
        const admin = new User({ email: emailTrim, passwordHash, name: "Administrator", role: "admin" });
        await admin.save();
        console.log("Created admin user:", emailTrim);
    } catch (e) {
        console.error("ensureAdmin error:", e);
    }
}
