// server/middleware/auth.js
import jwt from "jsonwebtoken";

/**
 * requireAuth: kiểm tra access token (Bearer <token>) và gắn payload vào req.user
 */
export const requireAuth = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // "Bearer <token>"

  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = payload; // gắn user info vào req (payload.sub là userId)
    next();
  } catch (err) {
    console.error("requireAuth error:", err);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

/**
 * requireRole(role): middleware trả về hàm kiểm tra role trong DB
 * Sử dụng req.user.sub (userId) từ requireAuth trước đó.
 */
export const requireRole = (role) => {
  return async (req, res, next) => {
    try {
      const userId = req.user?.sub;
      if (!userId) return res.status(403).json({ message: "Forbidden" });

      // lazy import để tránh vòng lồng nếu cần
      const User = (await import("../models/User.js")).default;
      const user = await User.findById(userId).select("role");
      if (!user) return res.status(404).json({ message: "User not found" });

      if (user.role !== role) {
        return res.status(403).json({ message: "Access denied: insufficient role" });
      }

      next();
    } catch (err) {
      console.error("requireRole error:", err);
      return res.status(500).json({ message: "Server error" });
    }
  };
};
