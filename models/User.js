// server/models/User.js
import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    name: { type: String },
    phone: { type: String },
    avatar: { type: String }, // file name trong /uploads
    refreshTokens: [String],
    role: { type: String, enum: ["user", "admin"], default: "user" } // <-- thêm field role
  },
  { timestamps: true }
);

export default mongoose.model("User", userSchema);
