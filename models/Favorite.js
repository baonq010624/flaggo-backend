// server/models/Favorite.js
import mongoose from "mongoose";

const favoriteSchema = new mongoose.Schema(
  {
    heritageId: { type: String, required: true, unique: true },
    name: { type: String, required: true }, // lưu tên mới nhất để hiển thị
    count: { type: Number, default: 0 },
  },
  { timestamps: true }
);

favoriteSchema.index({ heritageId: 1 }, { unique: true });

export default mongoose.model("Favorite", favoriteSchema);
