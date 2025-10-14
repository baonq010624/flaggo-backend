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
import UserFavorite from "./models/UserFavorite.js";

import User from "./models/User.js";
import Visit from "./models/Visit.js";
import Favorite from "./models/Favorite.js";
import FavoriteVote from "./models/FavoriteVote.js";

dotenv.config();

// ============== Cloudinary config ==============
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
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
            (err, result) => {
                if (err) return reject(err);
                resolve(result);
            }
        );
        streamifier.createReadStream(buffer).pipe(cldStream);
    });
}

const app = express();
app.use(express.json());
app.use(cookieParser());

// ================= CORS (multi-origin) =================
const allowedOrigins = (
    process.env.ALLOWED_ORIGINS ||
    process.env.CLIENT_URL ||
    // mặc định đa môi trường (prod + preview + local)
    "https://flaggo.online,https://flaggo-frontend.vercel.app, https://flaggoweb.netlify.app, http://localhost:3000"
)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

console.log("[CORS] allowedOrigins:", allowedOrigins);

const corsOptionsDelegate = function (origin, callback) {
    if (!origin) return callback(null, true); // Postman/SSR
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Not allowed by CORS"));
};

// cors toàn cục (bao gồm preflight)
app.use(
    cors({
        origin: corsOptionsDelegate,
        credentials: true,
    })
);

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
    return jwt.sign({ sub: user._id, email: user.email }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "15m",
    });
}

function generateRefreshToken(user) {
    return jwt.sign({ sub: user._id }, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: "7d",
    });
}

// ================= middleware =================
function requireAuth(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ message: "Thiếu token truy cập." });

    const token = authHeader.split(" ")[1];
    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ message: "Token không hợp lệ hoặc đã hết hạn." });
    }
}

// ================= multer (upload) =================
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith("image/")) return cb(new Error("Chỉ cho phép tải lên tệp ảnh."));
        cb(null, true);
    },
});

// ================= cookie opts (prod vs dev) =================
const isProd = process.env.NODE_ENV === "production";
const cookieOpts = {
    httpOnly: true,
    secure: isProd,                     // prod: true (HTTPS), dev: false
    sameSite: isProd ? "none" : "lax",  // prod cross-site cần None; dev để Lax
    maxAge: 7 * 24 * 3600 * 1000,
    path: "/",
};
const clearCookieOpts = {
    path: "/",
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
};

// ================= AUTH ROUTES =================

// Register (auto-login)
app.post("/api/auth/register", async (req, res) => {
    try {
        const { email, password, name = "", phone = "" } = req.body;
        if (!email || !password) return res.status(400).json({ message: "Vui lòng nhập email và mật khẩu." });

        const emailTrim = String(email).trim().toLowerCase();
        if (password.length < 6) return res.status(400).json({ message: "Mật khẩu phải có ít nhất 6 ký tự." });

        const existing = await User.findOne({ email: emailTrim });
        if (existing) return res.status(409).json({ message: "Email đã được đăng ký." });

        const passwordHash = await bcrypt.hash(password, 12);
        const user = new User({
            email: emailTrim,
            passwordHash,
            name: String(name).trim(),
            phone: String(phone).trim(),
        });
        await user.save();

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        user.refreshTokens.push(refreshToken);
        await user.save();

        res.cookie("refreshToken", refreshToken, cookieOpts);

        return res.status(201).json({
            accessToken,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                phone: user.phone,
                role: user.role || "user",
                avatar: user.avatar || "",
            },
            message: "Đăng ký thành công.",
        });
    } catch (err) {
        console.error("Register error:", err);
        if (err.code === 11000) return res.status(409).json({ message: "Email đã được sử dụng." });
        res.status(500).json({ message: "Lỗi máy chủ khi đăng ký." });
    }
});

// Login
app.post("/api/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: "Vui lòng nhập đầy đủ email và mật khẩu." });

        const user = await User.findOne({ email: String(email).trim().toLowerCase() });
        if (!user) return res.status(401).json({ message: "Email hoặc mật khẩu không đúng." });

        const valid = await bcrypt.compare(password, user.passwordHash);
        if (!valid) return res.status(401).json({ message: "Email hoặc mật khẩu không đúng." });

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        user.refreshTokens.push(refreshToken);
        await user.save();

        res.cookie("refreshToken", refreshToken, cookieOpts);

        res.json({
            accessToken,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                phone: user.phone,
                role: user.role || "user",
                avatar: user.avatar || "",
            },
        });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Lỗi máy chủ khi đăng nhập." });
    }
});

// Refresh token (cookie hoặc body)
app.post("/api/auth/refresh", async (req, res) => {
    try {
        const token = req.cookies?.refreshToken || req.body?.refreshToken;
        if (!token) return res.status(401).json({ message: "Thiếu refresh token." });

        let payload;
        try {
            payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
        } catch (e) {
            return res.status(401).json({ message: "Refresh token không hợp lệ." });
        }

        const user = await User.findById(payload.sub);
        if (!user) return res.status(401).json({ message: "Không tìm thấy người dùng." });

        if (!user.refreshTokens.includes(token)) {
            user.refreshTokens = [];
            await user.save();
            return res.status(401).json({ message: "Refresh token không được hệ thống ghi nhận." });
        }

        // rotate refresh tokens
        user.refreshTokens = user.refreshTokens.filter((t) => t !== token);
        const newRefresh = generateRefreshToken(user);
        user.refreshTokens.push(newRefresh);
        await user.save();

        const accessToken = generateAccessToken(user);

        res.cookie("refreshToken", newRefresh, cookieOpts);

        res.json({
            accessToken,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                phone: user.phone,
                role: user.role || "user",
                avatar: user.avatar || "",
            },
        });
    } catch (err) {
        console.error("Refresh error:", err);
        res.status(500).json({ message: "Lỗi máy chủ khi làm mới phiên đăng nhập." });
    }
});

// Logout
app.post("/api/auth/logout", async (req, res) => {
    try {
        const token = req.cookies?.refreshToken || req.body?.refreshToken;
        if (token) {
            const payload = (() => {
                try {
                    return jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
                } catch {
                    return null;
                }
            })();
            if (payload) {
                const user = await User.findById(payload.sub);
                if (user) {
                    user.refreshTokens = user.refreshTokens.filter((t) => t !== token);
                    await user.save();
                }
            }
        }

        res.clearCookie("refreshToken", clearCookieOpts);
        res.json({ message: "Đã đăng xuất." });
    } catch (err) {
        console.error("Logout error:", err);
        res.status(500).json({ message: "Lỗi máy chủ khi đăng xuất." });
    }
});

// ================= USER routes =================

// Get profile
app.get("/api/me", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.sub).select("-passwordHash -refreshTokens");
        if (!user) return res.status(404).json({ message: "Không tìm thấy người dùng." });

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
        console.error("Get /me error:", err);
        res.status(500).json({ message: "Lỗi máy chủ khi lấy thông tin người dùng." });
    }
});

// Upload avatar -> Cloudinary
app.post("/api/user/avatar", requireAuth, upload.single("avatar"), async (req, res) => {
    try {
        if (!req.file || !req.file.buffer) {
            return res.status(400).json({ message: "Không có tệp nào được tải lên." });
        }

        const user = await User.findById(req.user.sub);
        if (!user) return res.status(404).json({ message: "Không tìm thấy người dùng." });

        const result = await uploadBufferToCloudinary(req.file.buffer, "flaggo/avatars");
        const secureUrl = result.secure_url;

        user.avatar = secureUrl;
        await user.save();

        res.json({ message: "Cập nhật ảnh đại diện thành công.", avatar: secureUrl });
    } catch (err) {
        console.error("Avatar upload error:", err);
        res.status(500).json({ message: "Lỗi máy chủ khi cập nhật ảnh đại diện." });
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

// ================= ADMIN: basic stats =================
app.get("/api/admin/stats", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.sub).select("role");
        if (!user) return res.status(404).json({ message: "Không tìm thấy người dùng." });
        if (user.role !== "admin") return res.status(403).json({ message: "Truy cập bị từ chối: không đủ quyền." });

        const userCount = await User.countDocuments();
        res.json({ userCount });
    } catch (err) {
        console.error("Admin stats error:", err);
        res.status(500).json({ message: "Lỗi máy chủ khi lấy thống kê." });
    }
});

// ================= ADMIN: visits chart =================
app.get("/api/admin/visits", requireAuth, async (req, res) => {
    try {
        const me = await User.findById(req.user.sub).select("role");
        if (!me) return res.status(404).json({ message: "Không tìm thấy người dùng." });
        if (me.role !== "admin") return res.status(403).json({ message: "Truy cập bị từ chối." });

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
                {
                    $addFields: {
                        label: {
                            $concat: [
                                { $toString: "$y" },
                                "-",
                                {
                                    $toString: {
                                        $cond: [{ $lt: ["$m", 10] }, { $concat: ["0", { $toString: "$m" }] }, { $toString: "$m" }],
                                    },
                                },
                            ],
                        },
                    },
                },
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
        res.status(500).json({ message: "Lỗi máy chủ khi lấy thống kê lượt truy cập." });
    }
});

// ================= FAVORITES =================
// Log helper
function logFav(msg, extra = {}) {
    try {
        console.log(`[FAV] ${msg}`, extra);
    } catch {}
}

// Preflight riêng cho 2 endpoint (có path cụ thể — OK)
app.options("/api/track/favorite/state", cors({ origin: corsOptionsDelegate, credentials: true }));
app.options("/api/track/favorite/toggle", cors({ origin: corsOptionsDelegate, credentials: true }));
app.options("/api/favorite/state", cors({ origin: corsOptionsDelegate, credentials: true }));
app.options("/api/favorite/toggle", cors({ origin: corsOptionsDelegate, credentials: true }));

// (legacy still available: /api/track/favorite — tăng đếm đơn thuần)
app.post("/api/track/favorite", async (req, res) => {
    try {
        const { heritageId, name } = req.body || {};
        const id = String(heritageId || "").trim();
        const nm = String(name || "").trim();
        if (!id || !nm) return res.status(400).json({ ok: false, message: "Thiếu 'heritageId' hoặc 'name'." });

        await Favorite.updateOne(
            { heritageId: id },
            { $setOnInsert: { heritageId: id }, $set: { name: nm }, $inc: { count: 1 } },
            { upsert: true }
        );

        res.json({ ok: true });
    } catch (err) {
        console.error("track favorite error:", err);
        res.status(500).json({ ok: false, message: "Lỗi máy chủ khi ghi nhận yêu thích." });
    }
});

/**
 * NEW: Kiểm tra trạng thái vote của 1 client với 1 heritage
 * GET  /api/track/favorite/state?heritageId=...&clientId=...
 * ALIAS: /api/favorite/state
 */
async function handleFavoriteState(req, res) {
    try {
        const heritageId = String(req.query.heritageId || "").trim();
        const clientId = String(req.query.clientId || "").trim();
        if (!heritageId || !clientId) {
            logFav("state missing params", { heritageId, clientId });
            return res.status(400).json({ voted: false });
        }
        const vote = await FavoriteVote.findOne({ heritageId, clientId }).lean();
        logFav("state ok", { heritageId, clientId, voted: !!(vote && vote.voted) });
        res.json({ voted: !!(vote && vote.voted) });
    } catch (err) {
        console.error("favorite state error:", err);
        res.status(200).json({ voted: false });
    }
}
app.get("/api/track/favorite/state", handleFavoriteState);
app.get("/api/favorite/state", handleFavoriteState); // alias

/**
 * NEW: Toggle favorite
 * POST /api/track/favorite/toggle
 * ALIAS: /api/favorite/toggle
 * body: { heritageId, name, clientId, vote }
 */
async function handleFavoriteToggle(req, res) {
    try {
        const { heritageId, name, clientId, vote } = req.body || {};
        const id = String(heritageId || "").trim();
        const nm = String(name || "").trim();
        const cid = String(clientId || "").trim();
        const want = !!vote;

        if (!id || !nm || !cid) {
            logFav("toggle missing params", { id, nm, cid });
            return res.status(400).json({ ok: false, message: "Thiếu tham số bắt buộc." });
        }

        const existing = await FavoriteVote.findOne({ heritageId: id, clientId: cid });

        const favDoc = await Favorite.findOneAndUpdate(
            { heritageId: id },
            { $setOnInsert: { heritageId: id, name: nm } },
            { new: true, upsert: true }
        );

        let delta = 0;
        if (!existing) {
            if (want) delta = 1;
            await FavoriteVote.create({ heritageId: id, clientId: cid, voted: want, name: nm });
        } else {
            if (existing.voted !== want) {
                delta = want ? 1 : -1;
                existing.voted = want;
                existing.name = nm || existing.name;
                await existing.save();
            } else {
                delta = 0;
            }
        }

        if (delta !== 0) {
            const newCount = Math.max(0, (favDoc.count || 0) + delta);
            favDoc.count = newCount;
            favDoc.name = nm || favDoc.name;
            await favDoc.save();
        }

        logFav("toggle ok", { id, cid, want, delta });
        return res.json({ ok: true, voted: want });
    } catch (err) {
        console.error("favorite toggle error:", err);
        res.status(500).json({ ok: false, message: "Lỗi máy chủ khi cập nhật yêu thích." });
    }
}
app.post("/api/track/favorite/toggle", handleFavoriteToggle);
app.post("/api/favorite/toggle", handleFavoriteToggle); // alias

/**
 * ADMIN: Top favorites
 * GET /api/admin/favorites?limit=20
 */
app.get("/api/admin/favorites", requireAuth, async (req, res) => {
    try {
        const me = await User.findById(req.user.sub).select("role");
        if (!me) return res.status(404).json({ message: "Không tìm thấy người dùng." });
        if (me.role !== "admin") return res.status(403).json({ message: "Truy cập bị từ chối." });

        const limit = Math.max(1, Math.min(parseInt(req.query.limit || "20", 10), 100));
        const docs = await Favorite.find({}).sort({ count: -1, updatedAt: -1 }).limit(limit).lean();

        const rows = docs.map((d) => ({ label: d.name, value: d.count }));
        res.json({ rows });
    } catch (err) {
        console.error("admin favorites error:", err);
        res.status(500).json({ message: "Lỗi máy chủ khi lấy thống kê yêu thích." });
    }
});

// ================= USER PERSONAL FAVORITES (per-user) =================
app.get("/api/user/favorites", requireAuth, async (req, res) => {
    try {
        const userId = req.user.sub;
        const rows = await UserFavorite.find({ userId }).sort({ createdAt: -1 }).lean();

        res.json({
            items: rows.map((r) => ({
                heritageId: r.heritageId,
                name: r.name || "",
                createdAt: r.createdAt,
            })),
        });
    } catch (err) {
        console.error("get /api/user/favorites error:", err);
        res.status(500).json({ message: "Lỗi máy chủ khi lấy danh sách đã lưu." });
    }
});

app.post("/api/user/favorites/toggle", requireAuth, async (req, res) => {
    try {
        const userId = req.user.sub;
        const { heritageId, name, vote } = req.body || {};
        const id = String(heritageId || "").trim();
        if (!id) return res.status(400).json({ ok: false, message: "Thiếu 'heritageId'." });

        if (vote) {
            await UserFavorite.updateOne(
                { userId, heritageId: id },
                { $set: { name: String(name || "") } },
                { upsert: true }
            );
            return res.json({ ok: true, saved: true });
        } else {
            await UserFavorite.deleteOne({ userId, heritageId: id });
            return res.json({ ok: true, saved: false });
        }
    } catch (err) {
        console.error("post /api/user/favorites/toggle error:", err);
        res.status(500).json({ ok: false, message: "Lỗi máy chủ khi lưu/bỏ lưu." });
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
