// server/models/FavoriteVote.js
import mongoose from "mongoose";

const favoriteVoteSchema = new mongoose.Schema(
  {
    heritageId: { type: String, required: true },
    clientId: { type: String, required: true }, // định danh trình duyệt
    voted: { type: Boolean, default: true },
    name: { type: String, default: "" }, // tiện hiển thị/đồng bộ tên mới nhất
  },
  { timestamps: true }
);

// Mỗi client chỉ được 1 phiếu trên 1 heritage
favoriteVoteSchema.index({ heritageId: 1, clientId: 1 }, { unique: true });

export default mongoose.model("FavoriteVote", favoriteVoteSchema);
