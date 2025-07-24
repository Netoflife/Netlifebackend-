require('dotenv').config(); // Load .env
const mongoose = require('mongoose');

// Load your Question model
const Question = require('./models/Question'); // adjust path if needed

// Connect to Atlas
mongoose.connect(process.env.MONGO_URI)
  .then(async () => {
    // ⚠️ Delete all questions
    const result = await Question.deleteMany({});
    console.log(`✅ Deleted ${result.deletedCount} questions`);
    mongoose.disconnect();
  })
  .catch(err => {
    console.error("❌ Failed to delete questions:", err);
  });
