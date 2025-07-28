const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const { body, validationResult } = require('express-validator');
const fs = require('fs');

// ✅ Only needed for local dev — not in Railway
if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

const app = express();

// --- CORS Configuration ---
// This allows your frontend (running on a different origin) to communicate with this backend.
const corsOptions = {
  origin: '*', // Allow all origins for development
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  allowedHeaders: ['Content-Type', 'Authorization'],
  preflightContinue: false,
  optionsSuccessStatus: 204
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

if (!process.env.MONGO_URI || !process.env.JWT_SECRET) {
  console.error('FATAL ERROR: Missing environment variables. Please set MONGO_URI and JWT_SECRET in a .env file.');
  process.exit(1);
}

// --- FILE UPLOADS & STATIC ASSETS ---
// This section handles file uploads for profile pictures, post media, and book files.
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir)); // Serve uploaded files statically

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedImageTypes = /\.(jpeg|jpg|png|gif)$/i;
    const allowedVideoTypes = /\.(mp4|mov|avi|wmv)$/i;
    const allowedDocTypes = /\.(pdf|txt)$/i;
    const fileExt = path.extname(file.originalname).toLowerCase();
    
    if (['profilePicture', 'coverImage'].includes(file.fieldname) && allowedImageTypes.test(fileExt)) return cb(null, true);
    if (file.fieldname === 'media' && (allowedImageTypes.test(fileExt) || allowedVideoTypes.test(fileExt))) return cb(null, true);
    if (file.fieldname === 'bookFile' && allowedDocTypes.test(fileExt)) return cb(null, true);
    
    cb(new Error('Error: File type not supported.'));
  }
});

// --- DATABASE SCHEMAS ---

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  dob: { type: Date, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  expertise: { type: String, required: true },
  password: { type: String, required: true },
  virtualNumber: String,
  isPremium: { type: Boolean, default: false },
  depositBalance: { type: Number, default: 0 },
  earningBalance: { type: Number, default: 0 },
  questionsAnsweredToday: { type: Number, default: 0 },
  pointsEarnedToday: { type: Number, default: 0 },
  totalPoints: { type: Number, default: 0 },
  level: { type: Number, default: 1 },
  streak: { type: Number, default: 0 },
  timeSpentToday: { type: Number, default: 0 },
  lastQuestionReset: { type: Date, default: Date.now },
  educationLevel: { type: String, default: 'High School' },
  profilePicture: { type: String, default: null },
  ownedBooks: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Book' }],
  answeredQuestions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Question' }],
  currentQuestionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Question', default: null },
  currentQuestionTimeLeft: { type: Number, default: 0 },
  lastActive: { type: Date, default: Date.now },
  consecutiveCorrectAnswers: { type: Number, default: 0 },
  consecutiveCorrectAnswersDate: { type: Date, default: null },
  // --- ALIGNMENT: These two fields handle the 10 incorrect answers penalty ---
  consecutiveIncorrectAnswers: { type: Number, default: 0 },
  lastIncorrectPenaltyTime: { type: Date, default: null },
  weeklyPoints: {type: Number, default: 0}
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const questionSchema = new mongoose.Schema({
  question: { type: String, required: true },
  options: { type: [String], default: [] }, // For multiple-choice questions
  answer: { type: String, required: true },
  difficulty: { type: String, enum: ['easy', 'medium', 'hard'], required: true }
});
const Question = mongoose.model('Question', questionSchema);

// --- ALIGNMENT: This schema supports the Dashboard's Activity Chart ---
const dailyActivitySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    date: { type: Date, required: true },
    points: { type: Number, default: 0 },
    questionsAnswered: { type: Number, default: 0 }
});
dailyActivitySchema.index({ userId: 1, date: 1 }, { unique: true });
const DailyActivity = mongoose.model('DailyActivity', dailyActivitySchema);


const commentSchema = new mongoose.Schema({
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
}, { timestamps: true });
const Comment = mongoose.model('Comment', commentSchema);

const postSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  description: { type: String, trim: true },
  mediaUrl: String,
  likes: { type: Number, default: 0 },
  likedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { timestamps: true });
const Post = mongoose.model('Post', postSchema);

const bookSchema = new mongoose.Schema({
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fileUrl: { type: String, required: true },
  title: { type: String, required: true },
  author: { type: String, required: true },
  tags: String,
  description: String,
  coverImage: String,
  price: { type: String, enum: ['free', 'paid'], default: 'free' },
  priceCredits: { type: Number, default: 0 },
  priceNaira: { type: Number, default: 0 },
  status: { type: String, default: 'Pending Approval', enum: ['Pending Approval', 'Approved', 'Rejected'] }
}, { timestamps: true });
const Book = mongoose.model('Book', bookSchema);

// --- ALIGNMENT: This schema stores withdrawal requests for admin processing ---
const withdrawalRequestSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    bankName: { type: String, required: true },
    accountNumber: { type: String, required: true },
    status: { type: String, enum: ['Pending', 'Completed', 'Failed'], default: 'Pending' }
}, { timestamps: true });
const WithdrawalRequest = mongoose.model('WithdrawalRequest', withdrawalRequestSchema);

// --- HELPERS & MIDDLEWARE ---

const seedQuestions = async () => {
    try {
        if (await Question.countDocuments() > 0) return;
        const questionsToSeed = [
            { question: "What is the capital of France?", options: ["Berlin", "Madrid", "Paris", "Rome"], answer: "Paris", difficulty: "easy" },
            { question: "Which planet is known as the Red Planet?", options: ["Earth", "Mars", "Jupiter", "Venus"], answer: "Mars", difficulty: "easy" },
            { question: "What is the powerhouse of the cell?", options: ["Nucleus", "Ribosome", "Mitochondrion", "Golgi apparatus"], answer: "Mitochondrion", difficulty: "medium" },
            { question: "In what year did the Titanic sink?", options: ["1905", "1912", "1918", "1923"], answer: "1912", difficulty: "medium" },
            { question: "What is the value of 'c' in Einstein's equation E=mc^2?", options: ["Speed of sound", "Speed of light", "Mass of the sun", "Avogadro's constant"], answer: "Speed of light", difficulty: "hard" },
            { question: "What element has the chemical symbol 'O'?", answer: "Oxygen", difficulty: "easy" },
            { question: "Who wrote 'Romeo and Juliet'?", answer: "William Shakespeare", difficulty: "medium" },
            { question: "What is the hardest natural substance on Earth?", answer: "Diamond", difficulty: "hard" },
        ];
        await Question.insertMany(questionsToSeed);
        console.log('✅ Database seeded with sample questions.');
    } catch (error) { console.error('Error seeding database:', error); }
};

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
      console.log('MongoDB connected successfully. NetEdu is ready! 🚀');
      seedQuestions();
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

const authMiddleware = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    if (!user) return res.status(401).json({ error: 'User not found.' });
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token.' });
  }
};

const validateRegister = [
  body('fullName', 'Full name is required').notEmpty().trim().escape(),
  body('dob', 'Valid date of birth is required').isISO8601().toDate(),
  body('email', 'Please include a valid email').isEmail().normalizeEmail(),
  body('expertise', 'Expertise is required').notEmpty().trim().escape(),
  body('password', 'Password must be at least 6 characters').isLength({ min: 6 })
];

const DIFFICULTY_SETTINGS = {
    easy: { time: 40, points: 5 },
    medium: { time: 50, points: 10 },
    hard: { time: 60, points: 15 },
};

// --- API ROUTES ---

// ## User & Auth Routes ##
app.post('/api/register', validateRegister, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
    try {
      const { fullName, dob, email, expertise, password } = req.body;
      if (await User.findOne({ email })) return res.status(400).json({ error: 'Email already exists' });
      const user = new User({ fullName, dob, email, expertise, password: await bcrypt.hash(password, 10), virtualNumber: `NET${Math.floor(1000 + Math.random() * 9000)}` });
      await user.save();
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
      const userResponse = user.toObject();
      delete userResponse.password;
      res.status(201).json({ token, user: userResponse });
    } catch (err) { res.status(500).json({ error: 'Server error during registration' }); }
});

app.post('/api/login', [body('email').isEmail().normalizeEmail(), body('password').notEmpty()], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: "Invalid input" });
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
      
      user.lastActive = new Date();
      await user.save();

      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
      const userResponse = user.toObject();
      delete userResponse.password;
      res.json({ token, user: userResponse });
    } catch (err) { res.status(500).json({ error: 'Server error during login' }); }
});

app.get('/api/profile', authMiddleware, (req, res) => {
    res.json({ user: req.user });
});

app.get('/api/user/:userId', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId).select('virtualNumber expertise level profilePicture isPremium _id');
        if (!user) return res.status(404).json({ error: 'User not found.' });
        res.json({ user });
    } catch (err) { res.status(500).json({ error: 'Server error fetching user profile.' }); }
});

app.put('/api/profile', authMiddleware, async (req, res) => {
    try {
        const { fullName, dob, expertise, educationLevel } = req.body;
        const user = await User.findByIdAndUpdate(req.user._id, { fullName, dob, expertise, educationLevel }, { new: true }).select('-password');
        res.json({ message: 'Profile updated successfully!', user });
    } catch (err) { res.status(500).json({ error: 'Server error updating profile.' }); }
});

app.post('/api/profile/picture', authMiddleware, upload.single('profilePicture'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No profile picture file provided.' });
    req.user.profilePicture = `/uploads/${req.file.filename}`;
    await req.user.save();
    res.json({ message: 'Profile picture updated!', profilePicture: req.user.profilePicture });
});

app.post('/api/customize-virtual-number', authMiddleware, [body('customName').notEmpty()], async (req, res) => {
    if (!req.user.isPremium) return res.status(403).json({ error: 'This is a premium feature.' });
    const { customName } = req.body;
    req.user.virtualNumber = `${customName.replace(/\s/g, '').substring(0, 10)}${Math.floor(10 + Math.random() * 90)}`;
    await req.user.save();
    res.json({ message: 'Virtual number customized!', virtualNumber: req.user.virtualNumber });
});

app.post('/api/user/upgrade', authMiddleware, async (req, res) => {
    const upgradeCost = 2000;
    const user = req.user;
    if (user.isPremium) return res.status(400).json({ error: 'You are already a premium user.' });
    if (user.depositBalance + user.earningBalance < upgradeCost) return res.status(402).json({ error: 'Insufficient funds across both balances. Please deposit to upgrade.' });
    let remainingCost = upgradeCost;
    if (user.depositBalance > 0) {
        const deduction = Math.min(user.depositBalance, remainingCost);
        user.depositBalance -= deduction;
        remainingCost -= deduction;
    }
    if (remainingCost > 0) user.earningBalance -= remainingCost;
    user.isPremium = true;
    const updatedUser = await user.save();
    res.json({ message: 'Upgrade successful!', user: updatedUser.toObject() });
});

// ## Balance & Transactions Routes ##
// --- ALIGNMENT: This route receives the bank info from the frontend for admin processing ---
app.post('/api/withdraw', authMiddleware, [
    body('amount').isFloat({ gt: 0 }),
    body('bankName').notEmpty().trim().escape(),
    body('accountNumber').isNumeric().isLength({ min: 10, max: 10 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: "Invalid data provided. Please check your inputs." });
    try {
        const { amount, bankName, accountNumber } = req.body;
        const MINIMUM_WITHDRAWAL = 5000;
        const user = req.user;
        if (user.earningBalance < amount || amount < MINIMUM_WITHDRAWAL) {
            return res.status(400).json({ error: 'Withdrawal amount is invalid or exceeds your earning balance.' });
        }
        user.earningBalance -= amount;
        const withdrawalRequest = new WithdrawalRequest({ userId: user._id, amount, bankName, accountNumber, status: 'Pending' });
        await user.save();
        await withdrawalRequest.save();
        res.json({ message: 'Withdrawal request submitted!', earningBalance: user.earningBalance });
    } catch (err) { res.status(500).json({ error: 'Server error processing withdrawal request.' }); }
});

app.get('/api/withdrawals/history', authMiddleware, async (req, res) => {
    const history = await WithdrawalRequest.find({ userId: req.user._id }).sort({ createdAt: -1 });
    res.json({ history });
});

// --- ALIGNMENT: This route provides the data for the Dashboard Activity Chart ---
app.get('/api/user/activity', authMiddleware, async (req, res) => {
    try {
        const today = new Date(); today.setUTCHours(23, 59, 59, 999);
        const sevenDaysAgo = new Date(); sevenDaysAgo.setUTCDate(today.getUTCDate() - 6); sevenDaysAgo.setUTCHours(0, 0, 0, 0);
        const activities = await DailyActivity.find({ userId: req.user._id, date: { $gte: sevenDaysAgo, $lte: today } }).sort({ date: 'asc' });
        const activityMap = new Map(activities.map(act => [act.date.toISOString().split('T')[0], act.points]));
        const result = Array.from({ length: 7 }, (_, i) => {
            const day = new Date(sevenDaysAgo); day.setUTCDate(sevenDaysAgo.getUTCDate() + i);
            const dateString = day.toISOString().split('T')[0];
            return { date: dateString, points: activityMap.get(dateString) || 0 };
        });
        res.json(result);
    } catch (error) { res.status(500).json({ error: "Could not fetch activity data." }); }
});

// ## Question Feed Routes ##
// --- ALIGNMENT: This route handles the penalty logic for 10 incorrect answers ---
app.get('/api/questions/start', authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        const today = new Date(); today.setHours(0, 0, 0, 0);
        if (user.lastIncorrectPenaltyTime) {
            const penaltyEndTime = new Date(user.lastIncorrectPenaltyTime).getTime() + (10 * 60 * 1000);
            if (Date.now() < penaltyEndTime) {
                return res.json({ penaltyActive: true, penaltyRemainingTime: Math.ceil((penaltyEndTime - Date.now()) / 1000) });
            } else {
                user.consecutiveIncorrectAnswers = 0;
                user.lastIncorrectPenaltyTime = null;
            }
        }
        if (new Date(user.lastQuestionReset) < today) {
            user.questionsAnsweredToday = 0; user.pointsEarnedToday = 0; user.timeSpentToday = 0;
            user.lastQuestionReset = new Date(); user.consecutiveCorrectAnswers = 0; user.consecutiveCorrectAnswersDate = null;
        }
        user.lastActive = new Date();

        const FREE_USER_QUESTION_LIMIT = 5;
        if (!user.isPremium && user.questionsAnsweredToday >= FREE_USER_QUESTION_LIMIT) {
            await user.save();
            return res.json({ noQuestionsAvailable: true, message: "Daily limit reached.", user });
        }

        const question = await Question.findOne({ _id: { $nin: user.answeredQuestions } });
        if (!question) {
            await user.save();
            return res.json({ noQuestionsAvailable: true, message: "No new questions available.", user });
        }
        user.currentQuestionId = question._id;
        user.currentQuestionTimeLeft = DIFFICULTY_SETTINGS[question.difficulty].time;
        await user.save();
        res.json({ question, timeLeft: user.currentQuestionTimeLeft, questionsAnsweredToday: user.questionsAnsweredToday, user });
    } catch (err) { res.status(500).json({ error: 'Server error starting question feed.' }); }
});

app.get('/api/questions/next', authMiddleware, async (req, res) => {
     try {
        const user = req.user;
        if (user.lastIncorrectPenaltyTime) {
            const penaltyEndTime = new Date(user.lastIncorrectPenaltyTime).getTime() + (10 * 60 * 1000);
            if (Date.now() < penaltyEndTime) {
                return res.json({ penaltyActive: true, penaltyRemainingTime: Math.ceil((penaltyEndTime - Date.now()) / 1000) });
            } else {
                user.consecutiveIncorrectAnswers = 0;
                user.lastIncorrectPenaltyTime = null;
            }
        }
        const question = await Question.findOne({ _id: { $nin: user.answeredQuestions } });
        if (!question) return res.json({ noQuestionsAvailable: true, message: "You've answered all questions!" });
        const timeLeft = DIFFICULTY_SETTINGS[question.difficulty].time;
        user.currentQuestionId = question._id;
        user.currentQuestionTimeLeft = timeLeft;
        await user.save();
        res.json({ question, timeLeft, questionsAnsweredToday: user.questionsAnsweredToday });
    } catch (err) { res.status(500).json({ error: 'Server error getting next question.' }); }
});

// --- ALIGNMENT: This route updates earning balance and applies penalties ---
app.post('/api/submit-answer', authMiddleware, async (req, res) => {
  try {
    const { questionId, selectedAnswer, timedOut } = req.body;
    const user = req.user;
    const question = await Question.findById(questionId);
    if (!question || (user.currentQuestionId && user.currentQuestionId.toString() !== questionId)) {
        return res.status(400).json({ error: 'Invalid or out-of-sync question.' });
    }
    const isCorrect = !timedOut && selectedAnswer.toLowerCase().trim() === question.answer.toLowerCase().trim();
    let pointsAwarded = 0;
    const today = new Date(); today.setHours(0, 0, 0, 0);
    
    if (isCorrect) {
      pointsAwarded = DIFFICULTY_SETTINGS[question.difficulty].points * (user.isPremium ? 2 : 1);
      user.totalPoints += pointsAwarded;
      user.pointsEarnedToday += pointsAwarded;
      user.earningBalance += pointsAwarded; // Points convert directly to earning balance
      user.consecutiveIncorrectAnswers = 0;
      user.lastIncorrectPenaltyTime = null;
    } else {
      user.consecutiveIncorrectAnswers += 1;
      if (user.consecutiveIncorrectAnswers >= 10) {
          user.lastIncorrectPenaltyTime = new Date();
      }
    }
    
    user.questionsAnsweredToday += 1;
    user.level = Math.floor(user.totalPoints / 100) + 1;
    user.answeredQuestions.push(question._id);
    user.currentQuestionId = null;
    
    await DailyActivity.findOneAndUpdate(
        { userId: user._id, date: today },
        { $inc: { points: pointsAwarded, questionsAnswered: 1 } },
        { upsert: true }
    );
    const updatedUser = await user.save();
    res.json({ isCorrect, pointsAwarded, correctAnswer: question.answer, updatedUser: updatedUser.toObject() });
  } catch (err) { res.status(500).json({ error: 'Server error submitting answer.' }); }
});

// ## Other Feature Routes ##

app.get('/api/leaderboard', authMiddleware, async (req, res) => {
    try {
        const leaderboard = await User.find({})
            .sort({ totalPoints: -1 }) // Leaderboard based on all-time points
            .limit(5)
            .select('virtualNumber profilePicture totalPoints isPremium _id');
        res.json({ leaderboard });
    } catch (err) { res.status(500).json({ error: 'Server error fetching leaderboard.' }); }
});

app.get('/api/posts', authMiddleware, async (req, res) => {
    const posts = await Post.find().populate('userId', 'virtualNumber isPremium _id profilePicture').sort({ createdAt: -1 });
    res.json(posts);
});

app.post('/api/posts', authMiddleware, upload.single('media'), async (req, res) => {
    const { description } = req.body;
    if (!description && !req.file) return res.status(400).json({ error: 'Post must have content.' });
    const post = new Post({ userId: req.user._id, description, mediaUrl: req.file ? `/uploads/${req.file.filename}` : '' });
    await post.save();
    res.status(201).json(await post.populate('userId', 'virtualNumber isPremium _id profilePicture'));
});

app.post('/api/posts/:postId/like', authMiddleware, async (req, res) => {
    const post = await Post.findById(req.params.postId);
    const userIdStr = req.user._id.toString();
    const userIndex = post.likedBy.map(id => id.toString()).indexOf(userIdStr);
    if (userIndex > -1) post.likedBy.splice(userIndex, 1);
    else post.likedBy.push(req.user._id);
    post.likes = post.likedBy.length;
    await post.save();
    res.json({ likes: post.likes });
});

app.get('/api/posts/:postId/comments', authMiddleware, async (req, res) => {
    const comments = await Comment.find({ postId: req.params.postId }).populate('userId', 'virtualNumber _id').sort({ createdAt: 'asc' });
    res.json({ comments });
});

app.post('/api/posts/:postId/comments', authMiddleware, [body('text').notEmpty()], async (req, res) => {
    const newComment = new Comment({ postId: req.params.postId, userId: req.user._id, text: req.body.text });
    await newComment.save();
    res.status(201).json({ comment: await newComment.populate('userId', 'virtualNumber _id') });
});

app.get('/api/books', authMiddleware, async (req, res) => {
    if (!req.user.isPremium) return res.status(403).json({ error: 'Premium required.' });
    const books = await Book.find({ status: 'Approved' }).populate('sellerId', 'virtualNumber _id').sort({ createdAt: -1 });
    res.json(books);
});

app.post('/api/books', authMiddleware, upload.fields([{ name: 'bookFile', maxCount: 1 }, { name: 'coverImage', maxCount: 1 }]), async (req, res) => {
    if (!req.user.isPremium) return res.status(403).json({ error: 'Premium required.' });
    const { title, author, tags, description, price, priceNaira } = req.body;
    if (!req.files?.bookFile?.[0] || !title || !author) return res.status(400).json({ error: 'Missing required fields.' });
    const newBook = new Book({ sellerId: req.user._id, fileUrl: `/uploads/${req.files.bookFile[0].filename}`, title, author, tags, description, price, priceNaira: parseFloat(priceNaira) || 0, coverImage: req.files.coverImage?.[0] ? `/uploads/${req.files.coverImage[0].filename}` : '' });
    await newBook.save();
    res.status(201).json({ message: 'Book submitted for approval.' });
});

app.get('/api/books/:bookId/buy', authMiddleware, async (req, res) => {
    if (!req.user.isPremium) return res.status(403).json({ error: 'Premium required.' });
    const book = await Book.findById(req.params.bookId);
    if (!book) return res.status(404).json({ error: 'Book not found.' });
    const user = req.user;
    if (user.ownedBooks.includes(book._id) || book.sellerId.equals(user._id)) {
        return res.json({ message: 'Access granted.', fileUrl: book.fileUrl, title: book.title });
    }
    if (book.price === 'free') {
        user.ownedBooks.push(book._id);
        await user.save();
        return res.json({ message: 'Free book added to library.', fileUrl: book.fileUrl, title: book.title });
    }
    if (book.price === 'paid' && user.depositBalance >= book.priceNaira) {
       user.depositBalance -= book.priceNaira;
       user.ownedBooks.push(book._id);
       await user.save();
       return res.json({ message: `Book purchased for ₦${book.priceNaira}.`, fileUrl: book.fileUrl, title: book.title, depositBalance: user.depositBalance });
    }
    res.status(402).json({error: 'Insufficient deposit balance.'});
});

app.get('/api/users/me/library', authMiddleware, async (req, res) => {
    const user = await User.findById(req.user._id).populate('ownedBooks');
    res.json({ books: user.ownedBooks });
});

app.post('/api/books/:bookId/report', authMiddleware, (req, res) => {
    console.log(`Book ${req.params.bookId} reported by ${req.user.email} for: ${req.body.reason}`);
    res.json({ message: 'Book reported for review.' });
});

// --- SERVER START ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
