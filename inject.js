require("dotenv").config();
const mongoose = require("mongoose");
const Question = require("./models/Question");

// ⛓️ Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log("✅ MongoDB connected");
  injectQuestions();
}).catch(err => {
  console.error("❌ MongoDB connection error:", err);
});

// 📦 Your questions
const questions = [
  {
    question: "What is the powerhouse of the cell?",
    options: ["Nucleus", "Ribosome", "Mitochondria", "Golgi body"],
    answer: "Mitochondria",
    difficulty: "easy",
    subject: "biology"
  },
  {
    question: "Who is the author of 'Things Fall Apart'?",
    options: ["Chinua Achebe", "Wole Soyinka", "Ngugi wa Thiong’o", "Chimamanda Adichie"],
    answer: "Chinua Achebe",
    difficulty: "medium",
    subject: "english"
  },
  // ⬅️ Add more here
];

async function injectQuestions() {
  for (let q of questions) {
    try {
      const result = await Question.findOneAndUpdate(
        { question: q.question },
        {
          $set: {
            options: q.options,
            answer: q.answer,
            difficulty: q.difficulty,
            subject: q.subject
          }
        },
        { upsert: true, new: true }
      );

      if (result) {
        console.log(`✅ Upserted: "${q.question}"`);
      }
    } catch (err) {
      console.error(`❌ Failed: "${q.question}" - ${err.message}`);
    }
  }

  mongoose.disconnect();
}
