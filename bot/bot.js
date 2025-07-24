// =======================
// 📦 NETEDU TELEGRAM BOT (FINAL)
// =======================

const TelegramBot = require('node-telegram-bot-api');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config();

const bot = new TelegramBot(process.env.BOT_TOKEN, { polling: true });

// Connect to Mongo
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("Mongo connected"))
  .catch(err => console.log(err));

// SCHEMAS
const userSchema = new mongoose.Schema({
  telegramId: String,
  name: String,
  fullName: String,
  email: String,
  dob: String,
  expertise: String,
  points: { type: Number, default: 0 },
  isPremium: { type: Boolean, default: false },
  questionCountToday: { type: Number, default: 0 },
  lastQuestionDate: String,
  lastQuestion: Object,
  referralCode: String,
  referredBy: String,
  virtualId: String
});

const questionSchema = new mongoose.Schema({
  question: String,
  answer: String,
  points: Number,
  difficulty: String
});

const withdrawalSchema = new mongoose.Schema({
  telegramId: String,
  bankName: String,
  accountName: String,
  amount: Number,
  status: { type: String, default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Question = mongoose.model('Question', questionSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

const ADMINS = ['7626745891', '6451217413'];
const depositSessions = {};
const userTimers = {};
const askedQuestions = {};

const generateVirtualId = async () => {
  const count = await User.countDocuments();
  return `NET${2101 + count}`;
};

const getToday = () => new Date().toISOString().split("T")[0];

// /start
bot.onText(/\/start/, (msg) => {
  bot.sendMessage(msg.chat.id, `👋 Welcome to NetEdu! Use /register to begin.`);
});

// /register
bot.onText(/\/register/, async (msg) => {
  const telegramId = String(msg.from.id);
  const existing = await User.findOne({ telegramId });
  if (existing) return bot.sendMessage(msg.chat.id, "✅ You're already registered.");

  const askFullName = async () => {
    bot.sendMessage(msg.chat.id, "📛 Enter your full name:");
    bot.once("message", async (msg1) => {
      const fullName = msg1.text;
      bot.sendMessage(msg.chat.id, "📧 Enter your email:");
      bot.once("message", async (msg2) => {
        const email = msg2.text;
        bot.sendMessage(msg.chat.id, "🎂 Enter your date of birth (YYYY-MM-DD):");
        bot.once("message", async (msg3) => {
          const dob = msg3.text;
          bot.sendMessage(msg.chat.id, "🎓 Enter your area of expertise:");
          bot.once("message", async (msg4) => {
            const expertise = msg4.text;
            const referredBy = msg.text.split(" ")[1] || null;
            const virtualId = await generateVirtualId();

            const newUser = new User({
              telegramId,
              name: msg.from.first_name,
              fullName,
              email,
              dob,
              expertise,
              referralCode: telegramId,
              referredBy,
              virtualId
            });

            await newUser.save();

            if (referredBy) {
              const referrer = await User.findOne({ telegramId: referredBy });
              if (referrer) {
                const pointsEarned = referrer.isPremium ? 40 : 20;
                referrer.points += pointsEarned;
                await referrer.save();
                bot.sendMessage(referredBy, `🎉 You earned ${pointsEarned} points for referring ${fullName}`);
              }
            }

            bot.sendMessage(msg.chat.id, `✅ Registered successfully as ${fullName}`);
          });
        });
      });
    });
  };

  askFullName();
});

// /deposit
bot.onText(/\/deposit/, (msg) => {
  const userName = msg.from.first_name;
  const depositInfo = `
------------------------------------------------------------
                    💰 NETEDU WALLET FUNDING
------------------------------------------------------------

Dear ${userName},

To top up your NetEdu wallet, kindly transfer funds to the
PalmPay account below:

    Bank Name      : PalmPay
    Account Number : 8055519522
    Account Name   : Usman Aregbesola
    Min. Deposit   : ₦2,000
    Transfer Note  : Your NetEdu Email

⚠️ Please ensure the amount is ₦2,000 or more.
Transactions below this amount will not be processed.

Once the transfer is complete, your wallet will be credited
automatically or shortly after confirmation.

Need help? Our support team is always ready to assist you.

Happy Learning!  
— The NetEdu Team ✨
------------------------------------------------------------
`;

  bot.sendMessage(msg.chat.id, depositInfo);
});
const depositSessions = {};
const userTimers = {};
const askedQuestions = {};

const generateVirtualId = async () => {
  const count = await User.countDocuments();
  return `NET${2101 + count}`;
};

const getToday = () => new Date().toISOString().split("T")[0];

// /start
bot.onText(/\/start/, (msg) => {
  bot.sendMessage(msg.chat.id, `👋 Welcome to NetEdu! Use /register to begin.`);
});

// /register
bot.onText(/\/register/, async (msg) => {
  const telegramId = String(msg.from.id);
  const existing = await User.findOne({ telegramId });
  if (existing) return bot.sendMessage(msg.chat.id, "✅ You're already registered.");

  const askFullName = async () => {
    bot.sendMessage(msg.chat.id, "📛 Enter your full name:");
    bot.once("message", async (msg1) => {
      const fullName = msg1.text;
      bot.sendMessage(msg.chat.id, "📧 Enter your email:");
      bot.once("message", async (msg2) => {
        const email = msg2.text;
        bot.sendMessage(msg.chat.id, "🎂 Enter your date of birth (YYYY-MM-DD):");
        bot.once("message", async (msg3) => {
          const dob = msg3.text;
          bot.sendMessage(msg.chat.id, "🎓 Enter your area of expertise:");
          bot.once("message", async (msg4) => {
            const expertise = msg4.text;
            const referredBy = msg.text.split(" ")[1] || null;
            const virtualId = await generateVirtualId();

            const newUser = new User({
              telegramId,
              name: msg.from.first_name,
              fullName,
              email,
              dob,
              expertise,
              referralCode: telegramId,
              referredBy,
              virtualId
            });

            await newUser.save();

            if (referredBy) {
              const referrer = await User.findOne({ telegramId: referredBy });
              if (referrer) {
                const pointsEarned = referrer.isPremium ? 40 : 20;
                referrer.points += pointsEarned;
                await referrer.save();
                bot.sendMessage(referredBy, `🎉 You earned ${pointsEarned} points for referring ${fullName}`);
              }
            }

            bot.sendMessage(msg.chat.id, `✅ Registered successfully as ${fullName}`);
          });
        });
      });
    });
  };

  askFullName();
});

// /deposit
bot.onText(/\/deposit/, (msg) => {
  const userName = msg.from.first_name;
  
------------------------------------------------------------
                    💰 NETEDU WALLET FUNDING
------------------------------------------------------------

Dear ${userName},

To top up your NetEdu wallet, kindly transfer funds to the
PalmPay account below:

    Bank Name      : PalmPay
    Account Number : 8055519522
    Account Name   : Usman Aregbesola
    Min. Deposit   : ₦2,000
    Transfer Note  : Your NetEdu Email

⚠️ Please ensure the amount is ₦2,000 or more.
Transactions below this amount will not be processed.

Once the transfer is complete, your wallet will be credited
automatically or shortly after confirmation.

Need help? Our support team is always ready to assist you.

Happy Learning!  
— The NetEdu Team ✨
------------------------------------------------------------
`;

  bot.sendMessage(msg.chat.id, depositInfo);
});
// Difficulty-based points and timers
const DIFFICULTY_CONFIG = {
  easy: { seconds: 40, points: 5 },
  medium: { seconds: 50, points: 10 },
  hard: { seconds: 60, points: 15 }
};

// /question
bot.onText(/\/question/, async (msg) => {
  const user = await User.findOne({ telegramId: msg.from.id });
  if (!user) return bot.sendMessage(msg.chat.id, "❗ Register first with /register.");

  const today = getToday();
  if (user.lastQuestionDate !== today) {
    user.questionCountToday = 0;
    user.lastQuestionDate = today;
  }

  const limit = user.isPremium ? Infinity : 5;
  if (user.questionCountToday >= limit) {
    return bot.sendMessage(msg.chat.id, "🚫 Daily limit reached. Upgrade with /upgrade for unlimited questions.");
  }

  const answered = askedQuestions[user.telegramId] || [];
  const question = await Question.findOne({
    _id: { $nin: answered },
    difficulty: { $in: Object.keys(DIFFICULTY_CONFIG) }
  });

  if (!question) return bot.sendMessage(msg.chat.id, "📭 No questions available.");

  user.lastQuestion = {
    id: question._id,
    question: question.question,
    answer: question.answer,
    difficulty: question.difficulty,
    askedAt: new Date()
  };

  user.questionCountToday += 1;
  await user.save();

  if (!askedQuestions[user.telegramId]) askedQuestions[user.telegramId] = [];
  askedQuestions[user.telegramId].push(question._id);

  const timeLimit = DIFFICULTY_CONFIG[question.difficulty].seconds * 1000;
  const timer = setTimeout(async () => {
    const userNow = await User.findOne({ telegramId: msg.from.id });
    if (userNow?.lastQuestion?.id == question._id.toString()) {
      bot.sendMessage(msg.chat.id, `⏰ Time’s up! Correct answer was: ${question.answer}`);
      userNow.lastQuestion = null;
      await userNow.save();
    }
  }, timeLimit);

  userTimers[msg.from.id] = timer;

  const fixedScore = `${user.points} pts ${user.isPremium ? "⭐" : ""} (${user.virtualId || ""})`;
  bot.sendMessage(msg.chat.id,
    `🧠 Question (${question.difficulty.toUpperCase()}):\n${question.question}\n\n💡 Reply using /answer <your answer>\n⏱ Time: ${DIFFICULTY_CONFIG[question.difficulty].seconds}s\n🏅 Points: ${user.isPremium ? DIFFICULTY_CONFIG[question.difficulty].points * 2 : DIFFICULTY_CONFIG[question.difficulty].points}\n📊 Total: ${fixedScore}`
  );
});

// /answer
bot.onText(/\/answer (.+)/, async (msg, match) => {
  const answer = match[1].trim().toLowerCase();
  const user = await User.findOne({ telegramId: msg.from.id });
  if (!user?.lastQuestion) return bot.sendMessage(msg.chat.id, "❗ You have no active question.");

  clearTimeout(userTimers[msg.from.id]);
  const correct = user.lastQuestion.answer.toLowerCase() === answer;
  let reward = DIFFICULTY_CONFIG[user.lastQuestion.difficulty].points;
  if (user.isPremium) reward *= 2;

  if (correct) {
    user.points += reward;
    bot.sendMessage(msg.chat.id, `✅ Correct! You earned ${reward} points.`);
  } else {
    bot.sendMessage(msg.chat.id, `❌ Incorrect. Correct answer: ${user.lastQuestion.answer}`);
  }

  user.lastQuestion = null;
  await user.save();
});

// /next
bot.onText(/\/next/, async (msg) => {
  const user = await User.findOne({ telegramId: msg.from.id });
  if (!user) return;
  user.lastQuestion = null;
  await user.save();
  bot.sendMessage(msg.chat.id, `➡️ Moving to next question. Use /question`);
});
// /upgrade
bot.onText(/\/upgrade/, async (msg) => {
  const user = await User.findOne({ telegramId: msg.from.id });
  if (!user) return bot.sendMessage(msg.chat.id, "❗ Register first with /register.");
  if (user.isPremium) return bot.sendMessage(msg.chat.id, "🌟 You are already a Premium user!");

  bot.sendMessage(msg.chat.id, "💡 To upgrade, fund your wallet with ₦2,000 or more using /deposit. Then an admin will upgrade your account manually.");
});

// /withdraw
bot.onText(/\/withdraw/, async (msg) => {
  const user = await User.findOne({ telegramId: msg.from.id });
  if (!user) return bot.sendMessage(msg.chat.id, "❗ Register first with /register.");
  if (user.points < 5000) return bot.sendMessage(msg.chat.id, "🚫 Minimum withdrawal is 5,000 points (₦5,000).");

  bot.sendMessage(msg.chat.id, "🏦 Enter your bank name:");
  bot.once("message", async (msg1) => {
    const bankName = msg1.text;
    bot.sendMessage(msg.chat.id, "👤 Enter account name:");
    bot.once("message", async (msg2) => {
      const accountName = msg2.text;
      bot.sendMessage(msg.chat.id, "💵 Enter amount to withdraw:");
      bot.once("message", async (msg3) => {
        const amount = parseInt(msg3.text);
        if (isNaN(amount) || amount < 5000) {
          return bot.sendMessage(msg.chat.id, "❗ Amount must be 5,000 or more.");
        }

        const newWithdraw = new Withdrawal({
          telegramId: msg.from.id,
          name: user.fullName,
          amount,
          status: "pending",
          bankName,
          accountName,
          date: new Date()
        });

        await newWithdraw.save();
        bot.sendMessage(msg.chat.id, "✅ Withdrawal request submitted. Status: Pending.");
      });
    });
  });
});

// Admin approves or completes withdrawal
bot.onText(/\/approve (.+)/, async (msg, match) => {
  if (!admins.includes(msg.from.id)) return;
  const id = match[1].trim();
  await Withdrawal.findByIdAndUpdate(id, { status: "approved" });
  bot.sendMessage(msg.chat.id, `✅ Withdrawal ${id} approved.`);
});

bot.onText(/\/complete (.+)/, async (msg, match) => {
  if (!admins.includes(msg.from.id)) return;
  const id = match[1].trim();
  await Withdrawal.findByIdAndUpdate(id, { status: "complete" });
  bot.sendMessage(msg.chat.id, `✅ Withdrawal ${id} marked as complete.`);
});

// Admin manual funding
bot.onText(/\/fund (.+) (\d+)/, async (msg, match) => {
  if (!admins.includes(msg.from.id)) return;
  const telegramId = match[1];
  const amount = parseInt(match[2]);
  const user = await User.findOne({ telegramId });
  if (!user) return bot.sendMessage(msg.chat.id, "❗ User not found.");
  user.points += amount;
  await user.save();
  bot.sendMessage(msg.chat.id, `💸 Funded ${amount} points to ${user.fullName}.`);
});
