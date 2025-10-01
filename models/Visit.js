// server/models/Visit.js
import mongoose from "mongoose";

const visitSchema = new mongoose.Schema(
  {
    // Ngày UTC, luôn set về 00:00:00.000 để gom theo ngày
    date: { type: Date, required: true, unique: true },
    count: { type: Number, default: 0 },
  },
  { timestamps: true }
);

// Index để truy vấn nhanh theo ngày
visitSchema.index({ date: 1 }, { unique: true });

export default mongoose.model("Visit", visitSchema);
