import mongoose from "mongoose";

const userFavoriteSchema = new mongoose.Schema(
    {
        userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
        heritageId: { type: String, required: true },
        name: { type: String, default: "" },
    },
    { timestamps: true }
);

// unique per userId + heritageId
userFavoriteSchema.index({ userId: 1, heritageId: 1 }, { unique: true });

export default mongoose.model("UserFavorite", userFavoriteSchema);
