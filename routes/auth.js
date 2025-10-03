// server/routes/auth.js
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import PendingUser from "../models/PendingUser.js";
import { requireAuth } from "../middleware/auth.js";
import { sendOtpEmail, generateOtp } from "../utils/mailer.js";

const router = express.Router();
const SALT_ROUNDS = 12;

const cookieOpts = () => ({
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // bắt buộc true khi SameSite=None
    sameSite: "none", // **QUAN TRỌNG** để gửi cookie qua cross-site fetch
    maxAge: 7 * 24 * 3600 * 1000,
    path: "/",
});

const clearCookieOpts = () => ({
    path: "/",
    secure: process.env.NODE_ENV === "production",
    sameSite: "none",
});

const createAccessToken = (user) => {
    return jwt.sign(
        { sub: user._id, email: user.email },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "15m" }
    );
};

const createRefreshToken = (user) => {
    return jwt.sign({ sub: user._id }, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: "7d",
    });
};

/**
 * ===========================
 *  REGISTER WITH OTP
 * ===========================
 */
router.post("/register-start", async (req, res) => {
    try {
        const { email, password, name = "", phone = "" } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: "Email và mật khẩu bắt buộc." });
        }
        if (password.length < 6) {
            return res.status(400).json({ message: "Mật khẩu phải có ít nhất 6 ký tự." });
        }

        const emailTrim = String(email).trim().toLowerCase();
        const exist = await User.findOne({ email: emailTrim });
        if (exist) return res.status(409).json({ message: "Email đã được sử dụng." });

        const otp = generateOtp();
        const otpHash = await bcrypt.hash(otp, 10);
        const expiresMin = Number(process.env.OTP_EXPIRES_MIN || 10);
        const otpExpiresAt = new Date(Date.now() + expiresMin * 60 * 1000);
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        const pending = await PendingUser.findOne({ email: emailTrim });
        if (pending) {
            pending.name = String(name).trim();
            pending.phone = String(phone).trim();
            pending.passwordHash = passwordHash;
            pending.otpHash = otpHash;
            pending.otpExpiresAt = otpExpiresAt;
            pending.attempts = 0;
            await pending.save();
        } else {
            await PendingUser.create({
                email: emailTrim,
                name: String(name).trim(),
                phone: String(phone).trim(),
                passwordHash,
                otpHash,
                otpExpiresAt,
            });
        }

        await sendOtpEmail({ to: emailTrim, code: otp });

        return res.status(200).json({
            ok: true,
            message: `Đã gửi mã OTP tới ${emailTrim}. Vui lòng kiểm tra email.`,
        });
    } catch (err) {
        console.error("register-start error:", err);
        res.status(500).json({ message: "Lỗi máy chủ khi bắt đầu đăng ký" });
    }
});

router.post("/register-verify", async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) return res.status(400).json({ message: "Thiếu email hoặc OTP." });

        const emailTrim = String(email).trim().toLowerCase();
        const pending = await PendingUser.findOne({ email: emailTrim });
        if (!pending) {
            return res.status(404).json({ message: "Không tìm thấy đăng ký chờ xác minh." });
        }

        if (!pending.otpExpiresAt || pending.otpExpiresAt.getTime() < Date.now()) {
            await PendingUser.deleteOne({ _id: pending._id });
            return res.status(410).json({ message: "OTP đã hết hạn. Vui lòng đăng ký lại." });
        }

        if (pending.attempts >= 5) {
            await PendingUser.deleteOne({ _id: pending._id });
            return res.status(429).json({ message: "Nhập sai OTP quá số lần cho phép. Đăng ký lại." });
        }

        const ok = await bcrypt.compare(String(otp), pending.otpHash);
        if (!ok) {
            pending.attempts += 1;
            await pending.save();
            return res.status(401).json({ message: "OTP không đúng." });
        }

        const user = await User.create({
            email: emailTrim,
            passwordHash: pending.passwordHash,
            name: pending.name || "",
            phone: pending.phone || "",
        });

        await PendingUser.deleteOne({ _id: pending._id });

        const accessToken = createAccessToken(user);
        const refreshToken = createRefreshToken(user);
        user.refreshTokens.push(refreshToken);
        await user.save();

        res.cookie("refreshToken", refreshToken, cookieOpts());

        return res.status(201).json({
            ok: true,
            accessToken,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                phone: user.phone,
                role: user.role || "user",
            },
            message: "Xác minh thành công. Tài khoản đã được tạo.",
        });
    } catch (err) {
        console.error("register-verify error:", err);
        res.status(500).json({ message: "Lỗi máy chủ khi xác minh OTP" });
    }
});

router.post("/register-resend", async (req, res) => {
    try {
        const { email } = req.body;
        const emailTrim = String(email || "").trim().toLowerCase();
        if (!emailTrim) return res.status(400).json({ message: "Thiếu email." });

        const pending = await PendingUser.findOne({ email: emailTrim });
        if (!pending) {
            return res.status(404).json({ message: "Không có đăng ký chờ xác minh cho email này." });
        }

        const otp = generateOtp();
        pending.otpHash = await bcrypt.hash(otp, 10);
        pending.otpExpiresAt = new Date(Date.now() + (Number(process.env.OTP_EXPIRES_MIN || 10) * 60 * 1000));
        pending.attempts = 0;
        await pending.save();

        await sendOtpEmail({ to: emailTrim, code: otp });

        return res.json({ ok: true, message: "Đã gửi lại OTP. Vui lòng kiểm tra email." });
    } catch (err) {
        console.error("register-resend error:", err);
        res.status(500).json({ message: "Lỗi máy chủ khi gửi lại OTP" });
    }
});

/**
 * ==============
 *  LOGIN / REFRESH / LOGOUT / ME
 * ==============
 */
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: "Thiếu thông tin" });

        const user = await User.findOne({ email: String(email).trim().toLowerCase() });
        if (!user) return res.status(401).json({ message: "Email hoặc mật khẩu không đúng" });

        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) return res.status(401).json({ message: "Email hoặc mật khẩu không đúng" });

        const accessToken = createAccessToken(user);
        const refreshToken = createRefreshToken(user);

        user.refreshTokens.push(refreshToken);
        await user.save();

        res.cookie("refreshToken", refreshToken, cookieOpts());

        res.json({
            accessToken,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                phone: user.phone,
                role: user.role || "user"
            }
        });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

router.post("/refresh", async (req, res) => {
    try {
        const token = req.cookies?.refreshToken || req.body?.refreshToken;
        if (!token) return res.status(401).json({ message: "No token" });

        let payload;
        try {
            payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
        } catch (e) {
            return res.status(401).json({ message: "Invalid refresh token" });
        }

        const user = await User.findById(payload.sub);
        if (!user) return res.status(401).json({ message: "User not found" });

        if (!user.refreshTokens.includes(token)) {
            user.refreshTokens = [];
            await user.save();
            return res.status(401).json({ message: "Invalid token (not recognized)" });
        }

        user.refreshTokens = user.refreshTokens.filter((t) => t !== token);
        const newRefreshToken = createRefreshToken(user);
        user.refreshTokens.push(newRefreshToken);
        await user.save();

        const accessToken = createAccessToken(user);

        res.cookie("refreshToken", newRefreshToken, cookieOpts());

        res.json({
            accessToken,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                phone: user.phone,
                role: user.role || "user"
            }
        });
    } catch (err) {
        console.error("Refresh error:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

router.post("/logout", async (req, res) => {
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
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

router.get("/me", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.sub).select("-passwordHash -refreshTokens");
        if (!user) return res.status(404).json({ message: "User not found" });
        res.json(user);
    } catch (err) {
        console.error("Get /me error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

export default router;
