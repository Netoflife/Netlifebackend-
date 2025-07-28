// Load environment variables require('dotenv').config(); const { Bot, InlineKeyboard, Keyboard } = require('grammy'); const mongoose = require('mongoose'); const cron = require('node-cron');

// MongoDB Connection const connectDb = async () => { try { await mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true, }); console.log('MongoDB connected successfully'); } catch (error) { console.error('MongoDB connection failed:', error.message); process.exit(1); } };

// MongoDB Schemas const userSchema = new mongoose.Schema({ telegramId: { type: String, required: true, unique: true }, netEduUsername: { type: String }, points: { type: Number, default: 0 }, registered: { type: Boolean, default: false }, notifications: { type: Boolean, default: true }, });

const sessionSchema = new mongoose.Schema({ telegramId: { type: String, required: true }, state: { type: String }, data: { type: Object }, });

const User = mongoose.model('User', userSchema, 'users'); const Session = mongoose.model('Session', sessionSchema, 'sessions');

// Initialize Telegram Bot const bot = new Bot(process.env.BOT_TOKEN);

// Simulated API Functions (replace with real ones) async function fetchQuestion(category) { return { text: What is the capital of France?, options: ['Paris', 'London', 'Berlin', 'Madrid'], correctAnswer: 'Paris', points: 10, }; }

async function saveSession(telegramId, state, data = {}) { await Session.findOneAndUpdate( { telegramId }, { telegramId, state, data }, { upsert: true } ); }

async function getSession(telegramId) { return await Session.findOne({ telegramId }); }

async function getMainMenu() { return new Keyboard() .text('Answer Questions') .text('My Points') .row() .text('Redeem Rewards') .text('How It Works') .row() .text('Settings') .resized(); }

// Start Bot bot.command('start', async (ctx) => { const telegramId = ctx.from.id.toString(); let user = await User.findOne({ telegramId });

if (!user) { user = new User({ telegramId }); await user.save(); await ctx.reply( 'Welcome to NetEdu Rewards Bot! To begin, link your NetEdu account with your email:', { reply_markup: { force_reply: true } } ); await saveSession(telegramId, 'AWAITING_NETEDU_USERNAME'); } else { await ctx.reply('Welcome back!', { reply_markup: await getMainMenu(), }); } });

// Handle user answers bot.on('callback_query:data', async (ctx) => { const telegramId = ctx.from.id.toString(); const session = await getSession(telegramId); const user = await User.findOne({ telegramId }); const data = ctx.callbackQuery.data;

if (session?.state === 'AWAITING_ANSWER' && data.startsWith('answer_')) { const answerIndex = parseInt(data.replace('answer_', '')); const { question, category } = session.data; const userAnswer = question.options[answerIndex];

if (userAnswer === question.correctAnswer) {
  user.points += question.points;
  await ctx.reply(`✅ Correct! You earned ${question.points} points.`);
} else {
  await ctx.reply(`❌ Incorrect. Correct answer: ${question.correctAnswer}`);
}

await user.save();
await saveSession(telegramId, 'IDLE');
await ctx.reply('Use /start or wait for the next question.');
await ctx.answerCallbackQuery();

} });

// Automatic Question Push (Every 30 min) cron.schedule('*/30 * * * *', async () => { const users = await User.find({ registered: true, notifications: true }); for (const user of users) { const question = await fetchQuestion('General Knowledge'); const keyboard = new InlineKeyboard(); question.options.forEach((opt, i) => keyboard.text(opt, answer_${i}).row());

await saveSession(user.telegramId, 'AWAITING_ANSWER', {
  question,
  category: 'General Knowledge',
});

await bot.api.sendMessage(
  user.telegramId,
  `🧠 Time for a new question!\n${question.text}`,
  { reply_markup: keyboard }
);

} });

// Run async function start() { await connectDb(); await bot.start(); console.log('Bot is running...'); }

start().catch(console.error);

