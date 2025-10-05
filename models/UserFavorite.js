import mongoose from "mongoose";

const userFavoriteSchema = new mongoose.Schema(
    {
        userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
        heritageId: { type: String, required: true },
        name: { type: String, default: "" }, // tên heritage để hiển thị nhanh
    },
    { timestamps: true }
);

// Mỗi user chỉ lưu 1 lần / heritage
userFavoriteSchema.index({ userId: 1, heritageId: 1 }, { unique: true });

export default mongoose.model("UserFavorite", userFavoriteSchema);
