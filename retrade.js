'use strict';

require('dotenv').config();

const express      = require('express');
const mongoose     = require('mongoose');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const multer       = require('multer');
const cors         = require('cors');
const http         = require('http');
const { Server }   = require('socket.io');
const { body, param, query, validationResult } = require('express-validator');
const path         = require('path');
const fs           = require('fs');
const { v4: uuid } = require('uuid');
const morgan       = require('morgan');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const crypto       = require('crypto');
const { Resend }   = require('resend');
const webpush      = require('web-push');
const speakeasy    = require('speakeasy');
const QRCode       = require('qrcode');
const passport     = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');

['JWT_SECRET','JWT_REFRESH_SECRET','TOTP_ENCRYPTION_KEY'].forEach(k => {
  if (!process.env[k] || process.env[k].length < 32)
    { console.error(`FATAL: ${k} missing or < 32 chars`); process.exit(1); }
});

const PORT               = parseInt(process.env.PORT)  || 5000;
const MONGO_URI          = process.env.MONGO_URI       || 'mongodb://localhost:27017/rawflip';
const JWT_SECRET         = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const CLIENT_ORIGIN      = process.env.CLIENT_ORIGIN   || 'https://rawflip.netlify.app';
const APP_URL            = process.env.APP_URL          || 'http://localhost:5000';
const IS_PROD            = process.env.NODE_ENV         === 'production';
const VAPID_PUBLIC_KEY   = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIVATE_KEY  = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL        = process.env.VAPID_EMAIL       || 'mailto:admin@rawflip.com';
const UPLOADS_DIR        = path.join(__dirname, 'uploads');

if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
  console.log('[Push] VAPID configured ✓');
} else {
  console.warn('[Push] VAPID keys missing — web push disabled. Set VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_EMAIL');
}
const OFFER_EXPIRY_DAYS  = 7;
const AUTO_RELEASE_HOURS = 48;
const DISPATCH_WINDOW_DAYS = 3;
const TOTP_ENC_KEY = crypto.pbkdf2Sync(
  process.env.TOTP_ENCRYPTION_KEY, 'rawflip-aes-salt', 100000, 32, 'sha256'
);

const MIN_DEPOSIT         = parseInt(process.env.MIN_DEPOSIT)    || 5000;
const MIN_WITHDRAWAL      = parseInt(process.env.MIN_WITHDRAWAL)  || 5000;

const CURRENT_TERMS_VERSION = process.env.TERMS_VERSION || '1.0';

const PLANS = {
  free: {
    id: 'free', name: 'Free', costNGN: 0,
    escrowFeePercent: 20, listingLimit: 3, minWithdrawal: 5000,
    features: ['Basic support','Standard search visibility'],
  },
  basic: {
    id: 'basic', name: 'Basic', costNGN: 1500,
    escrowFeePercent: 15, listingLimit: 10, minWithdrawal: 2000,
    features: ['Verified seller badge','Priority search ranking','Search boost','Priority support'],
  },
  pro: {
    id: 'pro', name: 'Pro', costNGN: 4500,
    escrowFeePercent: 10, listingLimit: Infinity, minWithdrawal: 0,
    features: ['Large verified badge','Highest search priority','Pro analytics dashboard','All Basic benefits'],
  },
};
const PLAN_IDS = Object.keys(PLANS);
const EARLY_ADOPTER_LIMIT = 200;
const EARLY_ADOPTER_PERK_MONTHS = 6;
const FOUNDING_MEMBER_LIMIT = 200;
const FOUNDING_MEMBER_PERK_DAYS = 180;
const LEGACY_PLAN_IDS = ['legacy_basic','legacy_pro'];
const LEGACY_PLANS = {
  legacy_basic: {
    id:'legacy_basic', name:'Legacy Basic', costNGN:750,
    escrowFeePercent:12, listingLimit:20, minWithdrawal:1000,
    features:['Raw Industrial Badge','LIFETIME PRICE LOCK','12% Escrow Fee','20 Listings','₦1,000 Min Withdrawal'],
  },
  legacy_pro: {
    id:'legacy_pro', name:'Legacy Pro', costNGN:2250,
    escrowFeePercent:7.5, listingLimit:Infinity, minWithdrawal:0,
    features:['Raw Industrial Badge (Legacy)','LIFETIME PRICE LOCK','7.5% Escrow Fee','Unlimited Listings','₦0 Min Withdrawal'],
  },
};

const REFERRAL_REWARDS = {
  referrer_email_verify:              500,
  referrer_first_purchase:            500,
  referee_welcome:                    500,
  referee_first_purchase_discount:    0.05,
  subscription_commission:            0.08,
  subscription_commission_pro:        0.12,
};
const REFERRAL_MILESTONES = [
  { count: 3,  reward_type: 'plan',    plan: 'basic', duration_days: 30 },
  { count: 5,  reward_type: 'plan',    plan: 'pro',   duration_days: 30 },
  { count: 10, reward_type: 'cash',    amount: 3000 },
];

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const currencyConfig = { rate: parseFloat(process.env.NGN_USD_RATE) || 1600 };
const convertNGNtoUSD = (ngn) => +(ngn / currencyConfig.rate).toFixed(2);
const convertUSDtoNGN = (usd) => Math.round(usd * currencyConfig.rate);
const fmtNGN = (ngn) => `₦${Number(ngn||0).toLocaleString('en-NG')} ($${convertNGNtoUSD(ngn||0).toFixed(2)})`;

function calcBlockFee(amount) {
  if (!amount || amount <= 0) return 0;
  return Math.ceil(amount / 5000) * 100;
}

function aesEncrypt(text) {
  const iv = crypto.randomBytes(16);
  const c  = crypto.createCipheriv('aes-256-cbc', TOTP_ENC_KEY, iv);
  return iv.toString('hex') + ':' + c.update(text,'utf8','hex') + c.final('hex');
}
function aesDecrypt(enc) {
  const [ivHex, data] = enc.split(':');
  const d = crypto.createDecipheriv('aes-256-cbc', TOTP_ENC_KEY, Buffer.from(ivHex,'hex'));
  return d.update(data,'hex','utf8') + d.final('utf8');
}

const en = {
  'auth.register.success':  'Welcome to RawFlip! Please verify your email.',
  'auth.login.invalid':     'Invalid credentials.',
  'auth.login.unverified':  'Please verify your email before logging in.',
  'auth.login.suspended':   'Account suspended.',
  'auth.2fa.invalid':       'Invalid 2FA code.',
  'not_found':     'Not found.',
  'unauthorized':  'Unauthorized.',
  'forbidden':     'Forbidden.',
  'rate_limited':  'Too many requests. Try again later.',
  'server_error':  'Internal server error.',
};
const t = k => en[k] || k;

const TX_STATES = {
  PENDING_OFFER:     'PENDING_OFFER',
  ACCEPTED:          'ACCEPTED',
  ESCROW_FUNDED:     'ESCROW_FUNDED',
  SHIPPED:           'SHIPPED',
  DELIVERED:         'DELIVERED',
  RECEIVED_CONFIRMED:'RECEIVED_CONFIRMED',
  COMPLETED:         'COMPLETED',
  DISPUTED:          'DISPUTED',
  CANCELLED:         'CANCELLED',
  REFUNDED:          'REFUNDED',
};

const WALLET_TX_STATES = {
  PENDING:          'pending',
  PROOF_SUBMITTED:  'proof_submitted',
  APPROVED:         'approved',
  REJECTED:         'rejected',
  COMPLETED:        'completed',
};

const WALLET_TX_TRANSITIONS = {
  pending:          ['proof_submitted', 'rejected'],
  proof_submitted:  ['approved', 'rejected'],
  approved:         ['completed'],
  rejected:         [],
  completed:        [],
};

function canWalletTransition(from, to) {
  return (WALLET_TX_TRANSITIONS[from] || []).includes(to);
}

const TX_TRANSITIONS = {
  PENDING_OFFER:     ['ACCEPTED','CANCELLED'],
  ACCEPTED:          ['ESCROW_FUNDED','CANCELLED'],
  ESCROW_FUNDED:     ['SHIPPED','CANCELLED','DISPUTED'],
  SHIPPED:           ['DELIVERED','DISPUTED'],
  DELIVERED:         ['RECEIVED_CONFIRMED','COMPLETED','DISPUTED'],
  RECEIVED_CONFIRMED:['COMPLETED'],
  COMPLETED:         [],
  DISPUTED:          ['COMPLETED','REFUNDED'],
  CANCELLED:         [],
  REFUNDED:          [],
};

function canTransition(from, to) {
  return (TX_TRANSITIONS[from] || []).includes(to);
}

const emailBase = (body) => `<!DOCTYPE html><html><head><meta charset="UTF-8"/><style>
  body{font-family:'DM Sans',Arial,sans-serif;background:#0a0a0f;color:#eeeef8;margin:0;padding:0}
  .wrap{max-width:560px;margin:32px auto;background:#111118;border-radius:12px;border:1px solid #252535;overflow:hidden}
  .hdr{background:#ff4e1f;padding:20px 32px;text-align:center}
  .hdr h1{margin:0;font-size:1.4rem;color:#fff;font-weight:800}
  .body{padding:32px}.meta{background:#18181f;border-radius:8px;padding:16px;margin:16px 0;border:1px solid #252535}
  h2{color:#ff4e1f;font-size:1.15rem;margin-top:0}p{color:#aaaacc;line-height:1.7;font-size:.9rem}
  .btn{display:inline-block;background:#ff4e1f;color:#fff;padding:12px 28px;border-radius:8px;font-weight:700;text-decoration:none;margin-top:16px}
  .ftr{text-align:center;padding:20px;font-size:.75rem;color:#4a4a6a;border-top:1px solid #252535}
  strong{color:#eeeef8}
</style></head><body><div class="wrap">
  <div class="hdr"><h1>RawFlip</h1></div>
  <div class="body">${body}</div>
  <div class="ftr">© ${new Date().getFullYear()} RawFlip Marketplace · Nigeria's Trusted P2P Platform</div>
</div></body></html>`;

const emailTemplates = {
  welcome: (u) => ({ subject:'Welcome to RawFlip! 🎉', html: emailBase(`
    <h2>Welcome, ${u}!</h2><p>Your account is ready. Start exploring the marketplace.</p>
    <a href="${CLIENT_ORIGIN}" class="btn">Explore Listings</a>`) }),

  verifyEmail: (u,code) => ({ subject:'Your RawFlip verification code', html: emailBase(`
    <h2>Verify Your Email</h2>
    <p>Hi <strong>${u}</strong>, your verification code is:</p>
    <div style='text-align:center;margin:24px 0'>
      <div style='display:inline-block;background:#f4f6ff;border:2px solid #c7d0ff;border-radius:14px;padding:16px 32px'>
        <span style='font-size:2.2rem;font-weight:800;letter-spacing:.25em;color:#3a3aff;font-family:monospace'>${code}</span>
      </div>
    </div>
    <p style='text-align:center;font-size:.88rem;color:#4a4a6a'>⏱ Expires in <strong>30 minutes</strong>. Do not share this code.</p>`) }),

  depositApproved: (u, amt, fee) => ({ subject:'Deposit Approved ✅', html: emailBase(`
    <h2>Deposit Approved!</h2>
    <p>Hi ${u}, your deposit has been approved and credited to your wallet.</p>
    <div class="meta">
      <p><strong>Amount:</strong> ${fmtNGN(amt)}</p>
      <p><strong>Fee:</strong> ${fmtNGN(fee)}</p>
      <p><strong>Credited:</strong> ${fmtNGN(amt - fee)}</p>
    </div>
    <a href="${CLIENT_ORIGIN}" class="btn">View Wallet</a>`) }),

  depositRejected: (u, reason) => ({ subject:'Deposit Rejected', html: emailBase(`
    <h2>Deposit Rejected</h2>
    <p>Hi ${u}, your deposit request was rejected.</p>
    <div class="meta"><p><strong>Reason:</strong> ${reason||'Admin review'}</p></div>
    <p>Please contact support if you believe this is an error.</p>`) }),

  withdrawalApproved: (u, amt, fee) => ({ subject:'Withdrawal Approved ✅', html: emailBase(`
    <h2>Withdrawal Approved!</h2>
    <p>Hi ${u}, your withdrawal has been processed.</p>
    <div class="meta">
      <p><strong>Amount:</strong> ${fmtNGN(amt)}</p>
      <p><strong>Fee:</strong> ${fmtNGN(fee)}</p>
      <p><strong>Net payout:</strong> ${fmtNGN(amt - fee)}</p>
    </div>`) }),

  withdrawalRejected: (u, reason) => ({ subject:'Withdrawal Rejected', html: emailBase(`
    <h2>Withdrawal Rejected</h2><p>Hi ${u}, your withdrawal was rejected.</p>
    <div class="meta"><p><strong>Reason:</strong> ${reason||'Admin review'}</p></div>`) }),

  subscriptionConfirmed: (u, plan, expiry) => ({ subject:`RawFlip ${plan.name} Plan Activated`, html: emailBase(`
    <h2>${plan.name} Plan Activated! 🎉</h2>
    <p>Hi ${u}, you are now on the <strong>${plan.name}</strong> plan.</p>
    <div class="meta">
      <p><strong>Escrow fee:</strong> ${plan.escrowFeePercent}%</p>
      <p><strong>Listing limit:</strong> ${plan.listingLimit === Infinity ? 'Unlimited' : plan.listingLimit}</p>
      <p><strong>Valid until:</strong> ${new Date(expiry).toLocaleDateString('en-NG')}</p>
    </div>
    <a href="${CLIENT_ORIGIN}" class="btn">View Dashboard</a>`) }),

  subscriptionExpiringSoon: (u, plan, expiry) => ({ subject:`Your ${plan} plan expires in 5 days`, html: emailBase(`
    <h2>Subscription Expiring Soon ⚠️</h2>
    <p>Hi ${u}, your <strong>${plan}</strong> plan expires on <strong>${new Date(expiry).toLocaleDateString('en-NG')}</strong>.</p>
    <p>Renew now to keep your benefits — verified badge, lower escrow fees, and priority ranking.</p>
    <a href="${CLIENT_ORIGIN}" class="btn">Renew Now</a>`) }),

  referralBonus: (u, amount, reason) => ({ subject:'Referral Bonus Earned! 🎁', html: emailBase(`
    <h2>You earned a referral bonus!</h2>
    <p>Hi ${u}, <strong>${fmtNGN(amount)}</strong> has been added to your earnings wallet.</p>
    <div class="meta"><p><strong>Reason:</strong> ${reason}</p></div>
    <a href="${CLIENT_ORIGIN}" class="btn">View Wallet</a>`) }),

  offerAccepted: (u, tx) => ({ subject:'Your offer was accepted — Funds in Escrow', html: emailBase(`
    <h2>Offer Accepted! 🎉</h2><p>Hi ${u}, funds are secured in escrow.</p>
    <div class="meta"><p><strong>Amount:</strong> ${fmtNGN(tx.amount)}</p></div>
    <a href="${CLIENT_ORIGIN}" class="btn">View Transaction</a>`) }),

  escrowFunded: (u, tx) => ({ subject:'Escrow funded — Awaiting dispatch', html: emailBase(`
    <h2>Escrow Funded ✅</h2><p>Hi ${u}, buyer funds are secured. Dispatch within 3 days.</p>
    <div class="meta"><p><strong>Amount:</strong> ${fmtNGN(tx.amount)}</p></div>
    <a href="${CLIENT_ORIGIN}" class="btn">Mark as Dispatched</a>`) }),

  newOrderReceived: (u, tx, itemTitle) => ({ subject:'New Order Received – Dispatch Required Within 3 Days', html: emailBase(`
    <h2>You Have a New Order! 🎉</h2>
    <p>Hello ${u},</p>
    <p>A buyer has successfully purchased your listing. Your item payment is <strong>securely held in escrow</strong> and will be released to you after the buyer confirms delivery.</p>
    <div class="meta">
      <p><strong>Item:</strong> ${itemTitle||tx.itemTitle||'Your listing'}</p>
      <p><strong>Amount:</strong> ${fmtNGN(tx.amount)}</p>
      <p><strong>Order ID:</strong> ${tx._id}</p>
      <p><strong>Dispatch Deadline:</strong> Within 3 days of this notification</p>
    </div>
    <p style="background:rgba(255,78,31,.08);border:1px solid rgba(255,78,31,.3);border-radius:8px;padding:12px 16px;font-size:.85rem;color:#fca5a5">
      ⚠️ <strong>Action Required:</strong> You are required to dispatch the item within <strong>3 days</strong>. Failure to dispatch may trigger automatic cancellation and a full refund to the buyer.
    </p>
    <p style="font-size:.85rem;color:#8888aa;margin-top:16px">All payments must remain inside the RawFlip platform. Do not request or accept payment outside RawFlip under any circumstances.</p>
    <a href="${CLIENT_ORIGIN}" class="btn" style="margin-top:8px">👉 Login to Dashboard &amp; Confirm Dispatch</a>`) }),

  itemShipped: (u, tx) => ({ subject:'Your item has been shipped! 🚚', html: emailBase(`
    <h2>Item Shipped!</h2><p>Hi ${u}, your item is on the way.</p>
    <div class="meta">
      <p><strong>Carrier:</strong> ${tx.shippingCarrier||'N/A'}</p>
      <p><strong>Tracking:</strong> ${tx.trackingNumber||'Not provided'}</p>
    </div>
    <a href="${CLIENT_ORIGIN}" class="btn">Confirm Receipt</a>`) }),

  autoReleaseWarning: (u, tx) => ({ subject:'Payment auto-releases in 24 hours ⏰', html: emailBase(`
    <h2>Action Required</h2><p>Hi ${u}, payment auto-releases in 24 hours. Confirm receipt or open a dispute.</p>
    <a href="${CLIENT_ORIGIN}" class="btn">Confirm Receipt</a>`) }),

  paymentReleased: (u, tx) => ({ subject:'Payment Released ✅', html: emailBase(`
    <h2>Payment Released!</h2><p>Hi ${u}, ${fmtNGN(tx.amount)} added to your withdrawable balance.</p>
    <a href="${CLIENT_ORIGIN}" class="btn">View Wallet</a>`) }),

  disputeOpened: (u, tx, role) => ({ subject:'Dispute Opened ⚠️', html: emailBase(`
    <h2>Dispute Opened</h2><p>Hi ${u}, a dispute on tx ${tx._id} requires your attention.</p>
    ${role==='seller'?'<p>Respond within <strong>3 days</strong> to avoid escalation.</p>':''}
    <a href="${CLIENT_ORIGIN}" class="btn">View Dispute</a>`) }),

  disputeResolved: (u, tx, decision) => ({ subject:'Dispute Resolved', html: emailBase(`
    <h2>Dispute Resolved</h2><p>Hi \${u}, decision: <strong>\${decision==='release'?'Payment released to seller':'Refund to buyer'}</strong>.</p>`) }),

  foundingMemberWelcome: (u, rank) => ({ subject:'⚒️ Welcome, Founding Member #' + rank + '! Access Granted.', html: emailBase(`
    <div style="text-align:center;padding:24px 0">
      <div style="display:inline-block;background:linear-gradient(135deg,#2b2b2b,#4a4a4a,#1a1a1a);border:2px solid #f0ad4e;border-radius:16px;padding:28px 40px;box-shadow:0 8px 32px rgba(240,173,78,.25),inset 0 1px 0 rgba(255,255,255,.1)">
        <div style="font-size:2rem;margin-bottom:8px">⚒️</div>
        <div style="font-size:.7rem;letter-spacing:.25em;color:#f0ad4e;text-transform:uppercase;font-weight:700">Raw Industrial</div>
        <div style="font-size:1.4rem;font-weight:900;color:#eeeef8;margin:4px 0">Founding Member</div>
        <div style="font-size:.8rem;color:#aaaacc">#\${rank} of 200</div>
      </div>
    </div>
    <h2 style="text-align:center">ACCESS GRANTED ⚡</h2>
    <p>Congratulations <strong>\${u}</strong> — you are Founding Member <strong>#\${rank}</strong> of RawFlip Marketplace.</p>
    <div class="meta">
      <p><strong>🎁 Your 180-Day Founding Member Perks:</strong></p>
      <p>✅ 100% Zero Fees — Deposit, Withdrawal &amp; Escrow</p>
      <p>✅ Unlimited Pro Access</p>
      <p>✅ Raw Industrial Badge on your profile</p>
      <p>✅ Priority Support — all your tickets are flagged VIP</p>
      <p>✅ Lifetime access to Legacy pricing after 180 days</p>
    </div>
    <p style="font-size:.85rem;color:#8888aa">After 180 days, lock in your Legacy rate — Legacy Basic (₦750/mo) or Legacy Pro (₦2,250/mo) — at LIFETIME PRICE LOCK. We'll remind you 14 days before.</p>
    <a href="\${CLIENT_ORIGIN}" class="btn">Enter the Marketplace</a>`) }),

  foundingMember14DayAlert: (u, rank, expiresAt) => ({ subject:'⚠️ Your Founding Member benefits are evolving — 14 days left', html: emailBase(`
    <h2>Time to Lock In Your Legacy Rate ⚒️</h2>
    <p>Hi <strong>\${u}</strong> (Founding Member #\${rank}),</p>
    <p>Your 180-day zero-fee Founding Member period ends on <strong>\${new Date(expiresAt).toLocaleDateString('en-NG')}</strong>.</p>
    <div class="meta">
      <p><strong>Your exclusive Legacy options (LIFETIME PRICE LOCK):</strong></p>
      <p>🔒 <strong>Legacy Basic</strong> — ₦750/mo | 12% Escrow | 20 Listings | ₦1,000 Min Withdrawal</p>
      <p>🔒 <strong>Legacy Pro</strong> — ₦2,250/mo | 7.5% Escrow | Unlimited Listings | ₦0 Min Withdrawal</p>
    </div>
    <p>These rates are exclusive to the first 200 and will never be available again. Don't miss the lock-in window.</p>
    <a href="\${CLIENT_ORIGIN}" class="btn">Lock In My Legacy Rate</a>`) }),

  foundingMember7DayAlert: (u, rank, expiresAt) => ({ subject:'🚨 Final Week — Lock In Your Founding Member Legacy Rate', html: emailBase(`
    <h2>Final 7 Days — Don't Lose Your Rate 🚨</h2>
    <p>Hi <strong>\${u}</strong> (Founding Member #\${rank}),</p>
    <p>Your zero-fee access expires on <strong>\${new Date(expiresAt).toLocaleDateString('en-NG')}</strong>. After that, without a Legacy plan, fees revert to standard rates.</p>
    <div class="meta">
      <p>🔒 <strong>Legacy Basic</strong> — ₦750/mo (was ₦1,500) | PRICE LOCKED FOR LIFE</p>
      <p>🔒 <strong>Legacy Pro</strong> — ₦2,250/mo (was ₦4,500) | PRICE LOCKED FOR LIFE</p>
    </div>
    <a href="\${CLIENT_ORIGIN}" class="btn" style="background:#e53e3e">Claim My Legacy Rate Now</a>`) }),
};

const FROM_EMAIL = 'RawFlip <notifications@send.rawflip.shop>';

let _resend = null;
function getResend() {
  if (_resend) return _resend;
  if (!process.env.RESEND_API_KEY) {
    console.warn('[Email] RESEND_API_KEY not set — emails will be skipped');
    return null;
  }
  _resend = new Resend(process.env.RESEND_API_KEY);
  return _resend;
}

async function sendEmail(to, { subject, html }) {
  const resend = getResend();
  if (!resend) { console.warn('[Email] skipped -', subject); return; }
  try {
    const { data, error } = await resend.emails.send({
      from: FROM_EMAIL,
      to: Array.isArray(to) ? to : [to],
      subject,
      html,
    });
    if (error) {
      console.error(`[Email] FAILED "${subject}" -> ${to} | ${error.message}`);
    } else {
      console.log(`[Email] sent "${subject}" -> ${to} (id: ${data?.id})`);
    }
  } catch(e) {
    console.error(`[Email] EXCEPTION "${subject}" -> ${to} | ${e.message}`);
  }
}

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors:{ origin: true, credentials:true, methods:['GET','POST'] },
  pingTimeout:20000, pingInterval:25000, transports:['websocket','polling'],
});

app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy:{ policy:'cross-origin' }, referrerPolicy:{ policy:'strict-origin-when-cross-origin' } }));
const ALLOWED_ORIGINS = new Set([
  CLIENT_ORIGIN,
  APP_URL,

  process.env.APP_URL || '',
].filter(Boolean));

const corsOpts = {
  origin(origin, cb) {

    if (!origin) return cb(null, true);

    if (!IS_PROD) return cb(null, true);

    if (ALLOWED_ORIGINS.has(origin)) return cb(null, true);

    cb(null, true);
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','PATCH','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-CSRF-Token'],
};

app.use(cors(corsOpts));
app.use(express.json({ limit:'4mb' }));
app.use(cookieParser());
app.use(morgan(IS_PROD?'combined':'dev'));
app.use('/uploads', (req, res, next) => {

  res.setHeader('Content-Disposition', 'attachment');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
}, express.static(UPLOADS_DIR, { dotfiles: 'deny', index: false }));
app.use(passport.initialize());

const authLimiter   = rateLimit({ windowMs:15*60*1000, max:20,  standardHeaders:true, legacyHeaders:false, message:{ error:t('rate_limited') } });
const apiLimiter    = rateLimit({ windowMs: 1*60*1000, max:120, standardHeaders:true, legacyHeaders:false, message:{ error:t('rate_limited') } });
const strictLimiter = rateLimit({ windowMs:15*60*1000, max:5,   standardHeaders:true, legacyHeaders:false, message:{ error:t('rate_limited') } });
const searchLimiter = rateLimit({ windowMs: 1*60*1000, max:60,  standardHeaders:true, legacyHeaders:false, message:{ error:t('rate_limited') } });
app.use('/api/auth',   authLimiter);
app.use('/api/search', searchLimiter);
app.use('/api',        apiLimiter);

const storage = multer.diskStorage({
  destination:(_,__,cb) => cb(null,UPLOADS_DIR),
  filename:   (_,file,cb) => cb(null,`${uuid()}${path.extname(file.originalname).toLowerCase()}`),
});
const upload = multer({ storage, limits:{ fileSize:8*1024*1024, files:8 }, fileFilter:(_,file,cb) => /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)?cb(null,true):cb(new Error('Images only')) });
const uploadEvidence = multer({ storage, limits:{ fileSize:10*1024*1024, files:5 }, fileFilter:(_,file,cb) => /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)?cb(null,true):cb(new Error('Images only')) });
const uploadProof = multer({ storage, limits:{ fileSize:10*1024*1024, files:3 }, fileFilter:(_,file,cb) => /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)?cb(null,true):cb(new Error('Images only')) });

const uploadSupport = multer({ storage, limits:{ fileSize:5*1024*1024, files:1 }, fileFilter:(_,file,cb) => {
  const ok = /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype) || file.mimetype === 'application/pdf';
  cb(ok ? null : new Error('Images or PDF only'), ok);
} });

const userSchema = new mongoose.Schema({
  username:         { type:String, required:true, unique:true, trim:true, minlength:3, maxlength:30 },
  email:            { type:String, required:true, unique:true, lowercase:true, trim:true },
  password:         { type:String, select:false },
  role:             { type:String, enum:['user','admin'], default:'user' },
  avatar:           { type:String, default:'' },
  bio:              { type:String, default:'', maxlength:500 },
  location:         { type:String, default:'', maxlength:100 },
  phone:            { type:String, default:'', maxlength:30 },
  whatsapp:         { type:String, default:'', maxlength:30 },
  rating:           { type:Number, default:0, min:0, max:5 },
  reviewCount:      { type:Number, default:0 },
  wishlist:         [{ type:mongoose.Schema.Types.ObjectId, ref:'Listing' }],
  isActive:         { type:Boolean, default:true },
  isVerified:       { type:Boolean, default:false },
  emailVerified:    { type:Boolean, default:false },
  lastSeen:         { type:Date, default:Date.now },
  refreshTokens:    { type:[String], default:[], select:false },
  emailVerifyToken: { type:String, default:null, select:false },
  emailVerifyExpires:{ type:Date, default:null, select:false },
  verifyCode:        { type:String, default:null, select:false },
  verifyCodeExpires: { type:Date,   default:null, select:false },
  verifyCodeSentAt:  { type:Date,   default:null, select:false },
  resetCode:         { type:String, default:null, select:false },
  resetCodeExpires:  { type:Date,   default:null, select:false },
  resetCodeSentAt:   { type:Date,   default:null, select:false },
  twoFAEnabled:     { type:Boolean, default:false },
  twoFASecret:      { type:String, default:null, select:false },
  twoFABackupCodes: { type:[String], default:[], select:false },
  googleId:         { type:String, default:null, select:false },

  availableBalance:   { type:Number, default:0, min:0 },
  reservedBalance:    { type:Number, default:0, min:0 },
  escrowBalance:      { type:Number, default:0, min:0 },
  withdrawableBalance:{ type:Number, default:0, min:0 },
  depositBalance:     { type:Number, default:0, min:0 },
  earningsBalance:    { type:Number, default:0, min:0 },

  activePlan:       { type:String, enum:[...PLAN_IDS,...LEGACY_PLAN_IDS], default:'free' },
  planExpiresAt:    { type:Date, default:null },

  referralCode:     { type:String, unique:true, sparse:true },
  referredBy:       { type:mongoose.Schema.Types.ObjectId, ref:'User', default:null },
  referralCount:    { type:Number, default:0 },
  referralEarnings: { type:Number, default:0 },

  followers:        [{ type:mongoose.Schema.Types.ObjectId, ref:'User' }],
  following:        [{ type:mongoose.Schema.Types.ObjectId, ref:'User' }],
  blockedUsers:     [{ type:mongoose.Schema.Types.ObjectId, ref:'User', select:false }],
  totalSales:       { type:Number, default:0 },
  totalPurchases:   { type:Number, default:0 },
  loginCount:       { type:Number, default:0 },
  loginFailedCount: { type:Number, default:0 },
  loginLockedUntil: { type:Date, default:null },
  lastLoginAt:      { type:Date, default:null },
  loginHistory: [{
    ip:String, device:String, fingerprint:String, location:String,
    time:{ type:Date, default:Date.now }, _id:false,
  }],

  registrationIp:   { type:String, default:'' },
  flaggedForAbuse:  { type:Boolean, default:false },
  firstPurchaseDone:{ type:Boolean, default:false },

  isEarlyAdopter:           { type:Boolean, default:false },
  earlyAdopterNumber:       { type:Number,  default:null  },
  earlyAdopterGrantedAt:    { type:Date,    default:null  },
  foundingMember14DaySent:  { type:Boolean, default:false },
  foundingMember7DaySent:   { type:Boolean, default:false },

  kycStatus:        { type:String, enum:['none','pending','approved','rejected'], default:'none' },
  kycSubmittedAt:   { type:Date,   default:null },
  kycReviewedAt:    { type:Date,   default:null },
  kycReviewedBy:    { type:mongoose.Schema.Types.ObjectId, ref:'User', default:null },
  kycRejectionNote: { type:String, default:'' },

  privacy_policy_agreed:    { type:Boolean, default:false },
  privacy_policy_agreed_at: { type:Date,    default:null  },
  terms_agreed:             { type:Boolean, default:false },
  terms_agreed_at:          { type:Date,    default:null  },
  terms_version:            { type:String,  default:null  },
  about_understood:         { type:Boolean, default:false },
  about_understood_at:      { type:Date,    default:null  },
}, { timestamps:true });

userSchema.pre('save', async function() {
  if (!this.isModified('password') || !this.password) return;
  this.password = await bcrypt.hash(this.password, 12);
});
userSchema.methods.comparePassword = function(pw) {
  return this.password ? bcrypt.compare(pw, this.password) : Promise.resolve(false);
};

userSchema.pre('save', async function() {
  if (!this.referralCode) {

    const UserModel = mongoose.model('User');
    let code, attempts = 0;
    do {
      const prefix = this.username.replace(/[^a-zA-Z0-9]/g,'').toUpperCase().slice(0,4);
      code = prefix + crypto.randomBytes(3).toString('hex').toUpperCase();
      attempts++;
      if (attempts > 10) break;
    } while (await UserModel.exists({ referralCode: code }));
    this.referralCode = code;
  }
});

const subscriptionSchema = new mongoose.Schema({
  userId:       { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, index:true },
  plan:         { type:String, enum:[...PLAN_IDS,...LEGACY_PLAN_IDS], required:true },
  costNGN:      { type:Number, required:true },
  startDate:    { type:Date, required:true },
  endDate:      { type:Date, required:true },
  status:       { type:String, enum:['active','expired','cancelled','gifted'], default:'active' },
  giftedBy:     { type:String, default:'' },
  walletTxId:   { type:mongoose.Schema.Types.ObjectId, ref:'WalletTx', default:null },
  expiryReminderSent: { type:Boolean, default:false },
}, { timestamps:true });

const referralSchema = new mongoose.Schema({
  referrerId:   { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, index:true },
  refereeId:    { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, unique:true },

  emailVerifyRewardPaid:  { type:Boolean, default:false },
  firstPurchaseRewardPaid:{ type:Boolean, default:false },

  milestonesClaimed:      { type:mongoose.Schema.Types.Mixed, default:{} },

  locked:       { type:Boolean, default:false },
  lockedReason: { type:String, default:'' },

  refereeIp:    { type:String, default:'' },
  refereeDevice:{ type:String, default:'' },
}, { timestamps:true });

referralSchema.index({ referrerId:1, refereeId:1 });

const listingSchema = new mongoose.Schema({
  seller:       { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, index:true },
  title:        { type:String, required:true, trim:true, minlength:3, maxlength:150 },
  description:  { type:String, required:true, maxlength:5000 },
  price:        { type:Number, required:true, min:0, max:100000000 },
  currency:     { type:String, default:'NGN' },
  category:     { type:String, enum:['electronics','clothing','furniture','vehicles','sports','books','toys','art','jewelry','food','services','other'], default:'other' },
  condition:    { type:String, enum:['new','like_new','good','fair','poor'], default:'good' },
  images:       [{ type:String }],
  location:     { type:String, default:'', maxlength:100 },
  tags:         [{ type:String, maxlength:30 }],
  status:       { type:String, enum:['active','sold','pending','archived'], default:'active', index:true },
  views:        { type:Number, default:0 },
  favoritedBy:  [{ type:mongoose.Schema.Types.ObjectId, ref:'User' }],
  negotiable:   { type:Boolean, default:false },
  shipping:     { type:Boolean, default:false },
  shippingCost: { type:Number, default:0, min:0 },
  shippingLabel:{ type:mongoose.Schema.Types.Mixed, default:null },

  contactPhone: { type:String, default:'', maxlength:30, trim:true },

  searchPriority: { type:Number, default:0, index:true },
}, { timestamps:true });
listingSchema.index({ title:'text', description:'text', tags:'text' });
listingSchema.index({ category:1, status:1, searchPriority:-1, createdAt:-1 });

const transactionSchema = new mongoose.Schema({
  buyerId:      { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, index:true },
  sellerId:     { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, index:true },
  itemId:       { type:mongoose.Schema.Types.ObjectId, ref:'Listing', required:true },
  offerId:      { type:mongoose.Schema.Types.ObjectId, ref:'Offer', default:null },
  itemTitle:    { type:String, default:'' },
  amount:       { type:Number, required:true, min:1 },
  currency:     { type:String, default:'NGN' },
  escrowAmount: { type:Number, default:0 },
  escrowFeePercent: { type:Number, default:20 },
  escrowFeeAmount:  { type:Number, default:0 },
  exchangeRateUsed: { type:Number, default:0 },
  state:        { type:String, enum:Object.values(TX_STATES), default:TX_STATES.PENDING_OFFER, index:true },

  dispatchType:    { type:String, enum:['international','local',''], default:'' },

  trackingNumber:  { type:String, default:'' },
  shippingCarrier: { type:String, default:'' },

  senderLocation:  { type:String, default:'' },
  transportType:   { type:String, enum:['bus','car','bike','van','truck',''], default:'' },
  sendTime:        { type:Date, default:null },
  estimatedArrival:{ type:Date, default:null },
  driverPhone:     { type:String, default:'' },
  productPictureUrl:{ type:String, default:'' },

  dispatchNotes:   { type:String, default:'', maxlength:1000 },
  dispatchedAt:    { type:Date, default:null },
  autoReleaseAt:      { type:Date, default:null },
  dispatchDeadlineAt: { type:Date, default:null },
  timestamps_state: {
    PENDING_OFFER:{ type:Date,default:null }, ACCEPTED:{ type:Date,default:null },
    ESCROW_FUNDED:{ type:Date,default:null }, SHIPPED:{ type:Date,default:null },
    DELIVERED:{ type:Date,default:null },     RECEIVED_CONFIRMED:{ type:Date,default:null },
    COMPLETED:{ type:Date,default:null },     DISPUTED:{ type:Date,default:null },
    CANCELLED:{ type:Date,default:null },     REFUNDED:{ type:Date,default:null },
  },
  disputeId:      { type:mongoose.Schema.Types.ObjectId, ref:'Dispute', default:null },
  reviewUnlocked: { type:Boolean, default:false },
  adminNote:      { type:String, default:'' },

  refereeDiscount:{ type:Number, default:0 },
}, { timestamps:true });
transactionSchema.index({ buyerId:1, state:1 });
transactionSchema.index({ sellerId:1, state:1 });
transactionSchema.index({ state:1, createdAt:-1 });

transactionSchema.pre('save', function() {
  if (this.isModified('state') && !this.isNew) {
    const prev = this.__previousState;
    if (prev && prev !== this.state && !canTransition(prev, this.state)) {
      throw new Error(`Invalid state transition: ${prev} → ${this.state}`);
    }
  }
  this.__previousState = this.state;
});

const offerSchema = new mongoose.Schema({
  listing:        { type:mongoose.Schema.Types.ObjectId, ref:'Listing', required:true, index:true },
  buyer:          { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true },
  seller:         { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true },
  amount:         { type:Number, required:true, min:1 },
  currency:       { type:String, default:'NGN' },
  exchangeRateUsed:{ type:Number, default:0 },
  message:        { type:String, default:'', maxlength:1000 },
  status:         { type:String, enum:['pending','accepted','rejected','withdrawn','countered','expired'], default:'pending', index:true },
  counterAmount:  { type:Number, default:null },
  counterMessage: { type:String, default:'', maxlength:1000 },
  expiresAt:      { type:Date, default:()=>new Date(Date.now()+OFFER_EXPIRY_DAYS*86400000), index:true },
  respondedAt:    { type:Date, default:null },
  transactionId:  { type:mongoose.Schema.Types.ObjectId, ref:'Transaction', default:null },
}, { timestamps:true });
offerSchema.index({ buyer:1, listing:1 });
offerSchema.index({ seller:1, status:1 });

const disputeSchema = new mongoose.Schema({
  transactionId: { type:mongoose.Schema.Types.ObjectId, ref:'Transaction', required:true, index:true },
  buyerId:       { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true },
  sellerId:      { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true },
  initiator:     { type:mongoose.Schema.Types.ObjectId, ref:'User' },
  respondent:    { type:mongoose.Schema.Types.ObjectId, ref:'User' },
  offer:         { type:mongoose.Schema.Types.ObjectId, ref:'Offer', default:null },
  listing:       { type:mongoose.Schema.Types.ObjectId, ref:'Listing', default:null },
  issueType:     { type:String, enum:['not_received','damaged_item','wrong_item','other'], default:'other' },
  reason:        { type:String, required:true, maxlength:2000 },
  evidenceImages:{ type:[String], default:[] },
  sellerResponse:{ type:String, default:'', maxlength:2000 },
  sellerRespondedAt:{ type:Date, default:null },
  status:        { type:String, enum:['OPEN','RESPONDED','ESCALATED','RESOLVED'], default:'OPEN', index:true },
  decision:      { type:String, enum:['release','refund',''], default:'' },
  resolution:    { type:String, default:'' },
  adminNote:     { type:String, default:'' },
  resolvedAt:    { type:Date, default:null },
  escalatedAt:   { type:Date, default:null },
  responseDeadlineAt:{ type:Date, default:()=>new Date(Date.now()+3*86400000) },
}, { timestamps:true });

const walletTxSchema = new mongoose.Schema({
  user:          { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, index:true },
  type:          { type:String, enum:['deposit','withdrawal','reserve','unreserve','escrow_fund','escrow_release','escrow_refund','earning','refund','adjustment','subscription','referral_bonus','gift_subscription','subscription_commission'], required:true },
  fromBucket:    { type:String, enum:['available','reserved','escrow','withdrawable','earnings','external'], default:'external' },
  toBucket:      { type:String, enum:['available','reserved','escrow','withdrawable','earnings','external'], default:'external' },
  amount:        { type:Number, required:true },
  fee:           { type:Number, default:0 },
  netAmount:     { type:Number, default:0 },
  currency:      { type:String, default:'NGN' },

  status:        { type:String, enum:Object.values(WALLET_TX_STATES), default:'completed' },

  proofImageUrl: { type:String, default:null },
  telegramFileId:{ type:String, default:null },

  approvedBy:    { type:mongoose.Schema.Types.ObjectId, ref:'User', default:null },
  approvedAt:    { type:Date, default:null },
  rejectedBy:    { type:mongoose.Schema.Types.ObjectId, ref:'User', default:null },
  rejectedAt:    { type:Date, default:null },
  rejectReason:  { type:String, default:'' },

  adminActionAt: { type:Date, default:null },

  paymentDetails:{ type:mongoose.Schema.Types.Mixed, default:{} },

  note:          { type:String, default:'' },
  transactionId: { type:mongoose.Schema.Types.ObjectId, ref:'Transaction', default:null },
  botRef:        { type:String, default:null },
  meta:          { type:mongoose.Schema.Types.Mixed, default:{} },
}, { timestamps:true });
walletTxSchema.index({ user:1, type:1, status:1 });
walletTxSchema.index({ status:1, type:1, createdAt:-1 });
walletTxSchema.index({ type:1, status:1, createdAt:-1 });

walletTxSchema.pre('save', function() {

  if (this.isModified('status') && !this.isNew) {
    const prevStatus = this._prevStatus;
    if (prevStatus && prevStatus !== this.status && !canWalletTransition(prevStatus, this.status)) {
      throw new Error(`Invalid wallet tx transition: ${prevStatus} → ${this.status}`);
    }
  }

  this._prevStatus = this.status;
});

walletTxSchema.post('init', function() {
  this._prevStatus = this.status;
});

const reviewSchema = new mongoose.Schema({
  reviewer:      { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true },
  reviewee:      { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true },
  listing:       { type:mongoose.Schema.Types.ObjectId, ref:'Listing', default:null },
  transactionId: { type:mongoose.Schema.Types.ObjectId, ref:'Transaction', default:null },
  rating:        { type:Number, required:true, min:1, max:5 },
  comment:       { type:String, default:'', maxlength:2000 },
}, { timestamps:true });

const postSchema = new mongoose.Schema({
  author:     { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, index:true },
  title:      { type:String, required:true, trim:true, maxlength:200 },
  content:    { type:String, required:true, maxlength:10000 },
  type:       { type:String, enum:['discussion','question','tip','announcement'], default:'discussion' },
  tags:       [{ type:String, maxlength:30 }],
  likes:      [{ type:mongoose.Schema.Types.ObjectId, ref:'User' }],
  commentCount:{ type:Number, default:0 },
  views:      { type:Number, default:0 },
  isPinned:   { type:Boolean, default:false },
}, { timestamps:true });
postSchema.index({ title:'text', content:'text' });

const commentSchema = new mongoose.Schema({
  post:    { type:mongoose.Schema.Types.ObjectId, ref:'Post', required:true, index:true },
  author:  { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true },
  content: { type:String, required:true, trim:true, maxlength:2000 },
}, { timestamps:true });

const taskSchema = new mongoose.Schema({
  user:     { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, index:true },
  title:    { type:String, required:true, maxlength:200 },
  description:{ type:String, default:'', maxlength:2000 },
  status:   { type:String, enum:['todo','in_progress','done'], default:'todo' },
  priority: { type:String, enum:['low','medium','high','urgent'], default:'medium' },
  dueDate:  { type:Date, default:null },
  tags:     [{ type:String }],
}, { timestamps:true });

const notificationSchema = new mongoose.Schema({
  recipient:      { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, index:true },
  sender:         { type:mongoose.Schema.Types.ObjectId, ref:'User', default:null },
  type:           { type:String, enum:['offer_received','offer_accepted','offer_rejected','offer_countered','message','system','dispute','review','listing_sold','follow','referral_bonus'], default:'system' },
  title:          { type:String, required:true },
  message:        { type:String, required:true },
  link:           { type:String, default:'' },
  read:           { type:Boolean, default:false, index:true },
  transactionId:  { type:mongoose.Schema.Types.ObjectId, ref:'Transaction', default:null },
}, { timestamps:true });
notificationSchema.index({ recipient:1, read:1, createdAt:-1 });

const reportSchema = new mongoose.Schema({
  reporter:   { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true },
  targetType: { type:String, enum:['listing','user','post','transaction'], required:true },
  targetId:   { type:mongoose.Schema.Types.ObjectId, required:true },
  reason:     { type:String, required:true, maxlength:1000 },
  status:     { type:String, enum:['pending','reviewed','resolved'], default:'pending' },
  adminNote:  { type:String, default:'' },
}, { timestamps:true });

const configSchema = new mongoose.Schema({
  key:   { type:String, unique:true, required:true },
  value: { type:mongoose.Schema.Types.Mixed },
  updatedBy: { type:mongoose.Schema.Types.ObjectId, ref:'User', default:null },
}, { timestamps:true });

const adminLogSchema = new mongoose.Schema({
  adminId:    { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true },
  action:     { type:String, required:true },
  targetType: { type:String, default:'' },
  targetId:   { type:String, default:'' },
  note:       { type:String, default:'' },
  meta:       { type:mongoose.Schema.Types.Mixed, default:{} },
  source:     { type:String, enum:['web','telegram','system'], default:'web' },
}, { timestamps:true });

const Comment      = mongoose.model('Comment',      commentSchema);
const AdminLog     = mongoose.model('AdminLog',     adminLogSchema);
const User         = mongoose.model('User',         userSchema);
const Listing      = mongoose.model('Listing',      listingSchema);
const Transaction  = mongoose.model('Transaction',  transactionSchema);
const Offer        = mongoose.model('Offer',        offerSchema);
const Dispute      = mongoose.model('Dispute',      disputeSchema);
const WalletTx     = mongoose.model('WalletTx',     walletTxSchema);
const Review       = mongoose.model('Review',       reviewSchema);
const Post         = mongoose.model('Post',         postSchema);
const Task         = mongoose.model('Task',         taskSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Report       = mongoose.model('Report',       reportSchema);
const Subscription = mongoose.model('Subscription', subscriptionSchema);
const Referral     = mongoose.model('Referral',     referralSchema);

const validate = (req,res,next) => {
  const e = validationResult(req);
  if (!e.isEmpty()) return res.status(400).json({ errors:e.array().map(x=>({ field:x.path, message:x.msg })) });
  next();
};

const auth = async (req,res,next) => {
  try {
    let token = req.cookies?.rf_access;
    if (!token) { const h=req.headers.authorization; if (h?.startsWith('Bearer ')) token=h.slice(7); }
    if (!token) return res.status(401).json({ error:'Authentication required' });
    let decoded;
    try { decoded=jwt.verify(token, JWT_SECRET); }
    catch { return res.status(401).json({ error:'Token invalid or expired' }); }
    const user = await User.findById(decoded.id).select('-password -refreshTokens -twoFASecret -twoFABackupCodes -emailVerifyToken');
    if (!user)          return res.status(401).json({ error:'User not found' });
    if (!user.isActive) return res.status(403).json({ error:t('auth.login.suspended') });
    req.user = user; next();
  } catch { res.status(500).json({ error:'Auth error' }); }
};

const adminOnly = (req,res,next) => req.user?.role==='admin' ? next() : res.status(403).json({ error:t('forbidden') });
const asyncH = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);

const requireAgreements = (req,res,next) => {
  const u = req.user;
  if (!u.privacy_policy_agreed)
    return res.status(403).json({ error:'agreements_required', missing:'privacy',
      message:'You must agree to the Privacy Policy before using wallet features.' });
  if (!u.about_understood)
    return res.status(403).json({ error:'agreements_required', missing:'about',
      message:'You must acknowledge the About Us disclosure before using wallet features.' });
  if (!u.terms_agreed || u.terms_version !== CURRENT_TERMS_VERSION)
    return res.status(403).json({ error:'agreements_required', missing:'terms',
      message:'You must agree to the current Terms and Conditions before using wallet features.' });
  next();
};

const requireKYC = (req, res, next) => {
  if (!req.user) return res.status(401).json({ error:'Unauthorized' });
  if (req.user.kycStatus !== 'approved')
    return res.status(403).json({
      error: 'kyc_required',
      message: 'You must complete KYC verification before making withdrawals.',
      kycStatus: req.user.kycStatus || 'none',
    });
  next();
};

const signAccess  = (id, twoFAVerified=false) => jwt.sign({ id, twoFAVerified }, JWT_SECRET, { expiresIn:'15m' });
const signRefresh = id => jwt.sign({ id }, JWT_REFRESH_SECRET, { expiresIn:'7d' });
const signTemp    = id => jwt.sign({ id, temp:true }, JWT_SECRET, { expiresIn:'5m' });

const setAuthCookies = (res, userId) => {
  const access  = signAccess(userId, true);
  const refresh = signRefresh(userId);
  const opts = { httpOnly:true, secure:IS_PROD, sameSite:IS_PROD?'none':'lax' };
  res.cookie('rf_access',  access,  { ...opts, maxAge:15*60*1000 });
  res.cookie('rf_refresh', refresh, { ...opts, maxAge:7*24*60*60*1000 });
  return { access, refresh };
};
const clearAuthCookies = res => { res.clearCookie('rf_access'); res.clearCookie('rf_refresh'); };

const sendNotification = async (data) => {
  const n   = await Notification.create(data);
  const pop = await Notification.findById(n._id).populate('sender','username avatar');

  io.to(`user:${data.recipient}`).emit('notification', pop);
  io.to(`user:${data.recipient}`).emit('notif:ping', { count: 1 });

  sendPushToUser(data.recipient, {
    title: data.title   || 'RawFlip',
    body:  data.message || '',
    url:   data.link    || '/'
  }).catch(() => {});
  return pop;
};

async function sendPushToUser(userId, payload) {
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) return;
  try {
    const subs = await PushSub.find({ user: userId }).lean();
    if (!subs.length) return;
    const promises = subs.map(sub =>
      webpush.sendNotification(
        { endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } },
        JSON.stringify(payload)
      ).catch(async err => {
        if (err.statusCode === 410 || err.statusCode === 404) {

          await PushSub.deleteOne({ _id: sub._id });
          console.log('[Push] removed stale subscription');
        } else {
          console.error('[Push] send error:', err.message);
        }
      })
    );
    await Promise.allSettled(promises);
  } catch (e) {
    console.error('[Push] sendPushToUser error:', e.message);
  }
}

const logAdmin = (adminId, action, targetType, targetId, note, meta={}, source='web') =>
  AdminLog.create({ adminId, action, targetType, targetId, note, meta, source }).catch(()=>{});

const paginate = req => {
  const page  = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  return { skip:(page-1)*limit, limit, page };
};
const convId = (a,b) => [a.toString(),b.toString()].sort().join(':');
const fingerprintDevice = req => crypto.createHash('sha256').update(`${req.ip||''}|${req.headers['user-agent']||''}`).digest('hex').slice(0,16);
const getClientIp = req => (req.headers['x-forwarded-for']||'').split(',')[0].trim() || req.ip || '';

function isEarlyAdopterActive(user) {
  if (!user || !user.isEarlyAdopter || !user.earlyAdopterGrantedAt) return false;
  const exp = new Date(user.earlyAdopterGrantedAt);
  exp.setMonth(exp.getMonth() + EARLY_ADOPTER_PERK_MONTHS);
  return new Date() < exp;
}

function isFoundingMemberActive(user) {
  if (!user || !user.isEarlyAdopter || !user.earlyAdopterGrantedAt) return false;
  if (user.earlyAdopterNumber && user.earlyAdopterNumber > FOUNDING_MEMBER_LIMIT) return false;
  const exp = new Date(user.earlyAdopterGrantedAt);
  exp.setDate(exp.getDate() + FOUNDING_MEMBER_PERK_DAYS);
  return new Date() < exp;
}

function getFoundingMemberExpiry(user) {
  if (!user || !user.earlyAdopterGrantedAt) return null;
  const exp = new Date(user.earlyAdopterGrantedAt);
  exp.setDate(exp.getDate() + FOUNDING_MEMBER_PERK_DAYS);
  return exp;
}

function calculateDepositFee(amount, user) {
  if (isFoundingMemberActive(user)) return 0;
  return calcBlockFee(amount);
}

function calculateWithdrawalFee(amount, user) {
  if (isFoundingMemberActive(user)) return 0;
  return calcBlockFee(amount);
}

function calculateEscrowFee(escrowAmount, feePercent, user) {
  if (isFoundingMemberActive(user)) return 0;
  return Math.round(escrowAmount * feePercent / 100);
}

function getActivePlan(user) {
  // Founding Members in their 180-day window are never on Free plan
  if (isFoundingMemberActive(user)) {
    // If they've locked in a Legacy plan, use that
    if (user.activePlan && LEGACY_PLANS[user.activePlan]) return LEGACY_PLANS[user.activePlan];
    // If they have an active paid plan, use that
    if (user.activePlan && user.activePlan !== 'free' && PLANS[user.activePlan]) {
      if (!user.planExpiresAt || new Date(user.planExpiresAt) >= new Date()) return PLANS[user.activePlan];
    }
    // Otherwise synthesise a Founding Member pro-equivalent plan
    return { id:'founding_member', name:'Founding Member', costNGN:0, escrowFeePercent:0, listingLimit:Infinity, minWithdrawal:0, features:['All Pro features','Zero fees (180-day perk)','Raw Industrial Badge'] };
  }
  if (!user.activePlan || user.activePlan === 'free') return PLANS.free;
  if (user.planExpiresAt && new Date(user.planExpiresAt) < new Date()) {
    return PLANS.free;
  }
  return PLANS[user.activePlan] || LEGACY_PLANS[user.activePlan] || PLANS.free;
}

async function walletMove({ session, userId, fromBucket, toBucket, amount, type, note, transactionId, fee=0 }) {
  const allInc = {};
  if (fromBucket !== 'external') allInc[`${fromBucket}Balance`] = -amount;
  if (toBucket   !== 'external') allInc[`${toBucket}Balance`]   =  amount;

  const user = await User.findOneAndUpdate(
    { _id:userId, ...(fromBucket!=='external' ? { [`${fromBucket}Balance`]:{ $gte:amount } } : {}) },
    { $inc:allInc },
    { new:true, session }
  );
  if (!user) throw new Error(`Insufficient ${fromBucket} balance`);
  await WalletTx.create([{ user:userId, type, fromBucket, toBucket, amount, fee, netAmount:amount-fee, currency:'NGN', status:'completed', note, transactionId }], { session });
  io.to(`user:${userId}`).emit('wallet:updated', { fromBucket, toBucket, amount, note });
  return user;
}

async function creditEarnings({ session, userId, amount, note, type='referral_bonus' }) {
  const user = await User.findByIdAndUpdate(userId, { $inc:{ earningsBalance:amount } }, { new:true, session });
  await WalletTx.create([{ user:userId, type, fromBucket:'external', toBucket:'earnings', amount, currency:'NGN', status:'completed', note }], { session });
  io.to(`user:${userId}`).emit('wallet:updated', { fromBucket:'external', toBucket:'earnings', amount, note });
  return user;
}

async function processReferralEmailVerify(referee) {
  if (!referee.referredBy) return;
  const ref = await Referral.findOne({ referrerId:referee.referredBy, refereeId:referee._id });
  if (!ref || ref.emailVerifyRewardPaid || ref.locked) return;

  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {

      await creditEarnings({ session, userId:referee.referredBy, amount:REFERRAL_REWARDS.referrer_email_verify, note:`Referral reward: ${referee.username} verified email` });

      await creditEarnings({ session, userId:referee._id, amount:REFERRAL_REWARDS.referee_welcome, note:'Welcome bonus for joining via referral' });

      await Referral.findByIdAndUpdate(ref._id, { emailVerifyRewardPaid:true }, { session });

      await User.findByIdAndUpdate(referee.referredBy, { $inc:{ referralCount:1, referralEarnings:REFERRAL_REWARDS.referrer_email_verify } }, { session });
    });

    await checkReferralMilestones(referee.referredBy, ref._id);

    const [referrer, refereeUser] = await Promise.all([User.findById(referee.referredBy), User.findById(referee._id)]);
    if (referrer) sendEmail(referrer.email, emailTemplates.referralBonus(referrer.username, REFERRAL_REWARDS.referrer_email_verify, `${referee.username} verified their email`)).catch(()=>{});
    sendNotification({ recipient:referee.referredBy, type:'referral_bonus', title:'Referral Reward!', message:`₦${REFERRAL_REWARDS.referrer_email_verify.toLocaleString()} earned — ${referee.username} verified email`, link:'/wallet' }).catch(()=>{});
    sendNotification({ recipient:referee._id, type:'referral_bonus', title:'Welcome Bonus!', message:`₦${REFERRAL_REWARDS.referee_welcome.toLocaleString()} added to your earnings wallet`, link:'/wallet' }).catch(()=>{});
  } catch(e) { console.error('[Referral email verify reward]', e.message); }
  finally { await session.endSession(); }
}

async function processReferralFirstPurchase(referee, txId) {
  if (!referee.referredBy) return;
  const ref = await Referral.findOne({ referrerId:referee.referredBy, refereeId:referee._id });
  if (!ref || ref.firstPurchaseRewardPaid || ref.locked) return;

  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      await creditEarnings({ session, userId:referee.referredBy, amount:REFERRAL_REWARDS.referrer_first_purchase, note:`Referral reward: ${referee.username} made first purchase` });
      await Referral.findByIdAndUpdate(ref._id, { firstPurchaseRewardPaid:true }, { session });
      await User.findByIdAndUpdate(referee.referredBy, { $inc:{ referralEarnings:REFERRAL_REWARDS.referrer_first_purchase } }, { session });
      await User.findByIdAndUpdate(referee._id, { firstPurchaseDone:true }, { session });
    });
    await checkReferralMilestones(referee.referredBy, ref._id);
    const referrer = await User.findById(referee.referredBy);
    if (referrer) {
      sendEmail(referrer.email, emailTemplates.referralBonus(referrer.username, REFERRAL_REWARDS.referrer_first_purchase, `${referee.username} made their first purchase`)).catch(()=>{});
      sendNotification({ recipient:referee.referredBy, type:'referral_bonus', title:'Referral Reward!', message:`₦${REFERRAL_REWARDS.referrer_first_purchase.toLocaleString()} earned — ${referee.username} made first purchase`, link:'/wallet' }).catch(()=>{});
    }
  } catch(e) { console.error('[Referral first purchase reward]', e.message); }
  finally { await session.endSession(); }
}

async function checkReferralMilestones(referrerId, refId) {
  const user = await User.findById(referrerId);
  if (!user) return;
  const ref = await Referral.findById(refId);
  if (!ref) return;

  for (const ms of REFERRAL_MILESTONES) {
    if (user.referralCount < ms.count) continue;
    if (ref.milestonesClaimed?.[ms.count]) continue;

    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        if (ms.reward_type === 'cash') {
          await creditEarnings({ session, userId:referrerId, amount:ms.amount, note:`Referral milestone: ${ms.count} referrals — ₦${ms.amount} bonus` });
          sendNotification({ recipient:referrerId, type:'referral_bonus', title:`🏆 Milestone: ${ms.count} Referrals!`, message:`₦${ms.amount.toLocaleString()} bonus added to your wallet`, link:'/wallet' }).catch(()=>{});
        } else if (ms.reward_type === 'plan') {
          await giftSubscription({ session, userId:referrerId, planId:ms.plan, durationDays:ms.duration_days, giftedBy:'referral_milestone' });
          sendNotification({ recipient:referrerId, type:'referral_bonus', title:`🏆 Milestone: ${ms.count} Referrals!`, message:`1 month ${PLANS[ms.plan].name} plan gifted!`, link:'/subscription' }).catch(()=>{});
        }
        await Referral.findByIdAndUpdate(refId, { $set:{ [`milestonesClaimed.${ms.count}`]:true } }, { session });
      });
    } catch(e) { console.error('[Milestone reward]', e.message); }
    finally { await session.endSession(); }
  }
}

async function giftSubscription({ session, userId, planId, durationDays, giftedBy }) {
  const plan = PLANS[planId];
  const startDate = new Date();
  const endDate = new Date(startDate.getTime() + durationDays*86400000);
  await Subscription.create([{ userId, plan:planId, costNGN:0, startDate, endDate, status:'gifted', giftedBy }], { session });
  await User.findByIdAndUpdate(userId, { activePlan:planId, planExpiresAt:endDate }, { session });
}

async function purchaseSubscription(userId, planId) {
  const plan = PLANS[planId] || LEGACY_PLANS[planId];
  if (!plan || plan.costNGN === 0) throw new Error('Invalid plan or free plan requires no purchase');
  const user = await User.findById(userId);
  if (!user) throw new Error('User not found');
  const currentPlanExpiry = user.planExpiresAt;
  const startDate = new Date();
  const endDate = new Date(startDate.getTime() + 30*86400000);

  const session = await mongoose.startSession();
  let sub;
  try {
    await session.withTransaction(async () => {

      let remaining = plan.costNGN;
      const freshUser = await User.findById(userId).session(session);
      if (!freshUser) throw new Error('User not found');
      if (freshUser.availableBalance + freshUser.earningsBalance < remaining) {
        throw new Error(`Insufficient balance. Need ₦${plan.costNGN.toLocaleString()} for ${plan.name} plan.`);
      }

      const fromAvailable = Math.min(freshUser.availableBalance, remaining);
      if (fromAvailable > 0) {
        await walletMove({ session, userId, fromBucket:'available', toBucket:'external', amount:fromAvailable, type:'subscription', note:`${plan.name} plan subscription` });
        remaining -= fromAvailable;
      }

      if (remaining > 0) {
        const fromEarnings = Math.min(freshUser.earningsBalance, remaining);
        await User.findByIdAndUpdate(userId, { $inc:{ earningsBalance:-fromEarnings } }, { session });
        await WalletTx.create([{ user:userId, type:'subscription', fromBucket:'earnings', toBucket:'external', amount:fromEarnings, currency:'NGN', status:'completed', note:`${plan.name} plan (from earnings)` }], { session });
        remaining -= fromEarnings;
      }
      if (remaining > 0) throw new Error('Balance calculation error');

      sub = await Subscription.create([{ userId, plan:planId, costNGN:plan.costNGN, startDate, endDate, status:'active' }], { session });
      sub = sub[0];

      const planGrantsBadge = ['basic','pro','legacy_basic','legacy_pro'].includes(planId);
      await User.findByIdAndUpdate(userId, { activePlan:planId, planExpiresAt:endDate, isVerified:planGrantsBadge }, { session });

      const ref = await Referral.findOne({ refereeId:userId }).session(session);
      if (ref && !ref.locked) {
        const referrerDoc = await User.findById(ref.referrerId).select('activePlan planExpiresAt').session(session);
        const referrerPlan = getActivePlan(referrerDoc);
        const commRate = referrerPlan.id === 'pro' ? REFERRAL_REWARDS.subscription_commission_pro : REFERRAL_REWARDS.subscription_commission;
        const commPct  = Math.round(commRate * 100);
        const commission = Math.round(plan.costNGN * commRate);
        await creditEarnings({ session, userId:ref.referrerId, amount:commission, note:`${commPct}% subscription commission from ${user.username}`, type:'referral_bonus' });
        await User.findByIdAndUpdate(ref.referrerId, { $inc:{ referralEarnings:commission } }, { session });
      }
    });

    const freshUser = await User.findById(userId);
    sendEmail(freshUser.email, emailTemplates.subscriptionConfirmed(freshUser.username, plan, endDate)).catch(()=>{});
    sendNotification({ recipient:userId, type:'system', title:`${plan.name} Plan Activated!`, message:`Your ${plan.name} subscription is active until ${endDate.toLocaleDateString()}`, link:'/subscription' }).catch(()=>{});
    io.to(`user:${userId}`).emit('subscription:updated', { plan:planId, expiresAt:endDate });
    return sub;
  } finally { await session.endSession(); }
}

let esClient = null;
const ES_INDEX = 'rawflip_listings';
async function initES() {
  if (!process.env.ELASTIC_NODE) { console.log('[ES] No ELASTIC_NODE — using MongoDB'); return; }
  try {
    const { Client } = require('@elastic/elasticsearch');
    esClient = new Client({ node:process.env.ELASTIC_NODE, ...(process.env.ELASTIC_API_KEY ? { auth:{ apiKey:process.env.ELASTIC_API_KEY } } : {}) });
    await esClient.ping();
    const exists = await esClient.indices.exists({ index:ES_INDEX });
    if (!exists) await esClient.indices.create({ index:ES_INDEX, mappings:{ properties:{
      title:{type:'text',analyzer:'english'}, description:{type:'text',analyzer:'english'},
      category:{type:'keyword'}, condition:{type:'keyword'}, status:{type:'keyword'},
      price:{type:'float'}, tags:{type:'keyword'}, sellerId:{type:'keyword'},
      createdAt:{type:'date'}, views:{type:'integer'}, searchPriority:{type:'integer'},
    }}});
    console.log('[ES] Elasticsearch connected');
  } catch(e) { console.warn('[ES] Unavailable — fallback MongoDB:', e.message); esClient = null; }
}
async function esIndex(l) {
  if (!esClient) return;
  try { await esClient.index({ index:ES_INDEX, id:l._id.toString(), document:{ title:l.title, description:l.description, category:l.category, condition:l.condition, status:l.status, price:l.price, tags:l.tags||[], sellerId:l.seller.toString(), createdAt:l.createdAt, views:l.views||0, searchPriority:l.searchPriority||0 } }); } catch(e){console.error('[ES]',e.message);}
}
async function esDelete(id) { if (!esClient) return; try { await esClient.delete({ index:ES_INDEX, id:id.toString() }); } catch {} }

if (process.env.GOOGLE_CLIENT_ID) {
  passport.use(new GoogleStrategy({
    clientID:process.env.GOOGLE_CLIENT_ID, clientSecret:process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:process.env.GOOGLE_CALLBACK_URL||`${APP_URL}/api/auth/google/callback`, scope:['profile','email'],
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email  = profile.emails?.[0]?.value?.toLowerCase();
      const avatar = profile.photos?.[0]?.value || '';
      if (!email) return done(new Error('No email from Google'));
      let user = await User.findOne({ $or:[{ googleId:profile.id },{ email }] }).select('+googleId');
      if (!user) {
        const base = profile.displayName?.replace(/[^a-zA-Z0-9_]/g,'').slice(0,28) || 'user';
        let username = base; let n=1;
        while (await User.findOne({ username })) username=`${base}${n++}`;
        const userNumG  = await getNextUserNumber();
        const isEarlyG  = userNumG <= EARLY_ADOPTER_LIMIT;
        const isFMG     = isEarlyG && userNumG <= FOUNDING_MEMBER_LIMIT;
        // Google users are email-verified immediately — clock starts now
        const grantedAt = isEarlyG ? new Date() : null;
        user = await User.create({
          googleId:profile.id, username, email, avatar:avatar.replace(/s\d+/,'s200'), emailVerified:true,
          userNumber:userNumG, isEarlyAdopter:isEarlyG,
          earlyAdopterNumber: isEarlyG ? userNumG : null,
          earlyAdopterGrantedAt: grantedAt,
          isVerified:isEarlyG,
          priority_support: isFMG,
        });
        if (isFMG) {
          const rank = userNumG;
          sendEmail(email, emailTemplates.foundingMemberWelcome(username, rank)).catch(()=>{});
          sendNotification({
            recipient: user._id, type:'system',
            title:`⚒️ Welcome, Founding Member #${rank}!`,
            message:`ACCESS GRANTED. Your 180-day zero-fee access is now active. Visit the Subscription page to see your full perks and Legacy pricing options.`,
            link:'/subscription',
          }).catch(()=>{});
          Post.create({
            author: user._id,
            title: `Founding Member #${rank} has joined the marketplace!`,
            content: `⚒️ I just joined RawFlip as Founding Member #${rank}! Excited to be part of the first 200 building this marketplace. Let's get flipping!`,
            type: 'discussion',
            tags: ['founding-member','introduction'],
          }).catch(()=>{});
        } else {
          sendEmail(email, emailTemplates.welcome(username)).catch(()=>{});
        }
      } else if (!user.googleId) {
        user.googleId = profile.id; user.emailVerified = true;
        if (!user.avatar && avatar) user.avatar = avatar;
        await user.save();
      }
      done(null, user);
    } catch(e) { done(e); }
  }));
}

async function closeConvForTx(txId, reason='') {
  try {

  } catch(e) {  }
}

const kycSchema = new mongoose.Schema({
  user:         { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, unique:true },
  fullName:     { type:String, required:true, trim:true },
  dob:          { type:String, required:true },
  idType:       { type:String, required:true, enum:['nin','bvn','passport','drivers_license','voters_card'] },
  idNumber:     { type:String, required:true, trim:true },
  idDocUrl:     { type:String, required:true },
  selfieUrl:    { type:String, required:true },
  address:      { type:String, required:true, trim:true },
  status:       { type:String, enum:['pending','approved','rejected'], default:'pending' },
  adminNote:    { type:String, default:'' },
  reviewedBy:   { type:mongoose.Schema.Types.ObjectId, ref:'User', default:null },
  reviewedAt:   { type:Date, default:null },
}, { timestamps:true });
const KycDoc = mongoose.model('KycDoc', kycSchema);

const pushSubscriptionSchema = new mongoose.Schema({
  user:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  endpoint: { type: String, required: true, unique: true },
  keys: {
    p256dh: { type: String, required: true },
    auth:   { type: String, required: true },
  },
}, { timestamps: true });
const PushSub = mongoose.model('PushSub', pushSubscriptionSchema);

const counterSchema = new mongoose.Schema({ _id:String, seq:{ type:Number, default:0 } });
const Counter = mongoose.model('Counter', counterSchema);
async function getNextUserNumber() {
  const doc = await Counter.findByIdAndUpdate(
    'userNumber',
    { $inc:{ seq:1 } },
    { new:true, upsert:true, setDefaultsOnInsert:true }
  );
  return doc.seq;
}

function genCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(6);
  return Array.from(bytes, b => chars[b % chars.length]).join('');
}

const CSRF_SECRET = process.env.CSRF_SECRET || JWT_SECRET + '_csrf';
function signCsrf(userId) {
  const payload = `${userId}:${Math.floor(Date.now()/3600000)}`;
  const sig = crypto.createHmac('sha256', CSRF_SECRET).update(payload).digest('hex').slice(0,32);
  return `${payload}:${sig}`;
}
function verifyCsrf(token, userId) {
  if (!token || !userId) return false;
  const parts = token.split(':');
  if (parts.length < 3) return false;
  const [uid, hour, sig] = parts;
  if (uid !== String(userId)) return false;
  const now = Math.floor(Date.now()/3600000);

  return [now, now-1].some(h => {
    const expected = crypto.createHmac('sha256', CSRF_SECRET).update(`${uid}:${h}`).digest('hex').slice(0,32);
    return expected === sig;
  });
}
function csrfMiddleware(req, res, next) {
  if (!['POST','PUT','DELETE','PATCH'].includes(req.method)) return next();

  const skip = ['/auth/login','/auth/register','/auth/login/2fa','/auth/forgot-password',
    '/auth/reset-password','/auth/verify-code','/auth/resend-verify','/auth/resend-verification',
    '/auth/google','/auth/google/callback'];
  if (skip.some(p => req.path.includes(p))) return next();

  if (!req.user) return next();
  const token = req.headers['x-csrf-token'] || req.body?._csrf;
  if (!verifyCsrf(token, req.user._id)) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token. Please refresh the page.' });
  }
  next();
}

const router = express.Router();

router.get('/auth/code-status', asyncH(async (req, res) => {
  const { email, type } = req.query;
  if (!email || !['verify','reset'].includes(type)) return res.status(400).json({ error:'Bad params' });
  const select = type==='verify'
    ? '+verifyCode +verifyCodeExpires +verifyCodeSentAt emailVerified'
    : '+resetCode  +resetCodeExpires  +resetCodeSentAt';
  const user = await User.findOne({ email: email.trim().toLowerCase() }).select(select);
  if (!user) return res.json({ exists: false });
  if (type==='verify' && user.emailVerified) return res.json({ exists:true, alreadyVerified:true });
  const expiresAt = type==='verify' ? user.verifyCodeExpires : user.resetCodeExpires;
  const sentAt    = type==='verify' ? user.verifyCodeSentAt  : user.resetCodeSentAt;
  const hasCode   = !!(type==='verify' ? user.verifyCode : user.resetCode);
  res.json({ exists:true, hasCode, expiresAt: expiresAt?.toISOString()||null, sentAt: sentAt?.toISOString()||null });
}));

router.get('/auth/csrf-token', auth, asyncH(async (req, res) => {
  const csrf = signCsrf(req.user._id);
  res.cookie('rf_csrf', csrf, { httpOnly:false, secure:IS_PROD, sameSite:IS_PROD?'none':'lax', maxAge:24*60*60*1000 });
  res.json({ csrfToken: csrf });
}));

router.get('/health', (_,res) => res.json({ ok:true, ts:Date.now(), env:process.env.NODE_ENV||'development', ngnUsdRate:currencyConfig.rate }));
router.get('/currency/rate', (_,res) => res.json({ rate:currencyConfig.rate, currency:'NGN', secondary:'USD' }));
router.get('/plans', (_,res) => res.json({ plans:PLANS, legacyPlans:LEGACY_PLANS }));

router.post('/auth/register', [
  body('username').trim().isLength({ min:3, max:30 }).withMessage('Username must be 3–30 characters').matches(/^[a-zA-Z0-9_.-]+$/).withMessage('Username can only contain letters, numbers, _ . -'),
  body('email').isEmail().withMessage('Enter a valid email address').normalizeEmail(),
  body('password').isLength({ min:8 }).withMessage('Password must be at least 8 characters').matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter').matches(/[0-9]/).withMessage('Password must contain at least one number'),
  body('referralCode').optional().trim().isLength({ max:20 }),
  body('phone').notEmpty().withMessage('Phone number is required').trim().matches(/^\+234[0-9]{10}$/).withMessage('Phone must be in format +2348012345678'),
  body('whatsapp').notEmpty().withMessage('WhatsApp number is required').trim().matches(/^\+234[0-9]{10}$/).withMessage('WhatsApp must be in format +2348012345678'),
  body('location').notEmpty().withMessage('Location is required').trim().isLength({ max:100 }).withMessage('Location too long'),
], validate, asyncH(async (req,res) => {
  const { username, email, password, referralCode } = req.body;
  if (await User.findOne({ $or:[{ email },{ username }] }))
    return res.status(409).json({ error:'Email or username already taken' });

  const ip = getClientIp(req);
  const fp = fingerprintDevice(req);

  let referrer = null;
  if (referralCode) {
    referrer = await User.findOne({ referralCode });
    if (!referrer) return res.status(400).json({ error:'Invalid referral code' });

    if (referrer.email === email) return res.status(400).json({ error:'Cannot use your own referral code' });

    if (referrer.registrationIp && referrer.registrationIp === ip) {
      console.warn(`[Referral] Same IP abuse attempt: ${ip}`);
      return res.status(400).json({ error:'Referral code cannot be used from same IP' });
    }
  }

  const verifyCode = genCode();
  const codeExpiry = new Date(Date.now() + 30 * 60 * 1000);

  const userNum = await getNextUserNumber();
  const isEA    = userNum <= EARLY_ADOPTER_LIMIT;
  const eaNumber = isEA ? userNum : null;

  const now = new Date();
  const regAgreements = {};
  if (req.body.agreePrivacy === true || req.body.agreePrivacy === 'true') {
    regAgreements.privacy_policy_agreed    = true;
    regAgreements.privacy_policy_agreed_at = now;
  }
  if (req.body.agreeTerms === true || req.body.agreeTerms === 'true') {
    regAgreements.terms_agreed    = true;
    regAgreements.terms_agreed_at = now;
    regAgreements.terms_version   = CURRENT_TERMS_VERSION;
  }

  const user  = await User.create({
    username, email, password,
    phone: req.body.phone || '',
    whatsapp: req.body.whatsapp || '',
    location: req.body.location || '',
    verifyCode:        verifyCode,
    verifyCodeExpires: codeExpiry,
    verifyCodeSentAt:  new Date(),
    referredBy:referrer?._id || null,
    registrationIp:ip,
    isEarlyAdopter:isEA,
    earlyAdopterNumber:eaNumber,
    earlyAdopterGrantedAt: null, // Set at email verification so the 180-day clock starts when they can actually use the platform
    isVerified:isEA,
    priority_support: isEA && eaNumber <= FOUNDING_MEMBER_LIMIT,
    ...regAgreements,
  });

  if (referrer) {
    await Referral.create({ referrerId:referrer._id, refereeId:user._id, refereeIp:ip, refereeDevice:fp });
  }

  sendEmail(email, emailTemplates.verifyEmail(username, verifyCode)).catch(()=>{});
  res.status(201).json({
    ok: true,
    message: t('auth.register.success'),
    isFoundingMember: isEA && eaNumber <= FOUNDING_MEMBER_LIMIT,
    rank: isEA && eaNumber <= FOUNDING_MEMBER_LIMIT ? eaNumber : null,
    expiresAt: codeExpiry.toISOString(),
  });
}));

router.post('/auth/verify-code', [
  body('email').isEmail().normalizeEmail(),
  body('code').isString().trim().isLength({ min:4, max:8 }),
], validate, authLimiter, asyncH(async (req, res) => {
  const { email, code } = req.body;
  const user = await User.findOne({ email })
    .select('+verifyCode +verifyCodeExpires +verifyCodeSentAt emailVerified isEarlyAdopter earlyAdopterNumber username');
  if (!user) return res.status(400).json({ error: 'Invalid or expired code.' });
  if (user.emailVerified) return res.json({ ok: true, alreadyVerified: true });
  if (!user.verifyCode || !user.verifyCodeExpires || user.verifyCodeExpires < new Date())
    return res.status(400).json({ error: 'Code expired. Request a new one.', expired: true });
  if (user.verifyCode.toUpperCase() !== code.trim().toUpperCase())
    return res.status(400).json({ error: 'Incorrect code. Check your email and try again.' });
  user.emailVerified     = true;
  user.verifyCode        = null;
  user.verifyCodeExpires = null;
  user.verifyCodeSentAt  = null;
  // Start the 180-day FM clock now — at the moment they verify and can actually use the platform
  if (user.isEarlyAdopter && !user.earlyAdopterGrantedAt) {
    user.earlyAdopterGrantedAt = new Date();
  }
  await user.save();
  processReferralEmailVerify(user).catch(()=>{});

  const isFoundingMember = user.isEarlyAdopter && user.earlyAdopterNumber && user.earlyAdopterNumber <= FOUNDING_MEMBER_LIMIT;
  if (isFoundingMember) {
    const rank = user.earlyAdopterNumber;
    console.log(`[FM] Sending welcome email to ${user.email} (Founding Member #${rank})`);
    sendEmail(user.email, emailTemplates.foundingMemberWelcome(user.username, rank)).catch((err) => {
      console.error(`[FM] Welcome email FAILED for ${user.email}:`, err.message);
    });
    sendNotification({
      recipient: user._id,
      type: 'system',
      title: `⚒️ Welcome, Founding Member #${rank}!`,
      message: `ACCESS GRANTED. Your 180-day zero-fee access is now active. Visit the Subscription page to see your full perks and Legacy pricing options.`,
      link: '/subscription',
    }).catch(()=>{});
    const welcomePost = `⚒️ I just joined RawFlip as Founding Member #${rank}! Excited to be part of the first 200 building this marketplace. Let's get flipping!`;
    Post.create({
      author: user._id,
      title: `Founding Member #${rank} has joined the marketplace!`,
      content: welcomePost,
      type: 'discussion',
      tags: ['founding-member','introduction'],
    }).catch(()=>{});
  } else {
    sendEmail(user.email, emailTemplates.welcome(user.username)).catch(()=>{});
  }

  res.json({ ok: true, isFoundingMember, rank: isFoundingMember ? user.earlyAdopterNumber : null });
}));

router.post('/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').exists(),
], validate, asyncH(async (req,res) => {
  const { email, password, twoFACode } = req.body;
  const user = await User.findOne({ email }).select('+password +twoFASecret +twoFABackupCodes +refreshTokens +loginFailedCount +loginLockedUntil');

  if (user && user.loginLockedUntil && user.loginLockedUntil > new Date()) {
    const wait = Math.ceil((user.loginLockedUntil - Date.now()) / 60000);
    return res.status(429).json({ error: `Account temporarily locked. Try again in ${wait} minute(s).` });
  }
  const passwordOk = user && await user.comparePassword(password);
  if (!user || !passwordOk) {
    if (user) {
      const fails = (user.loginFailedCount || 0) + 1;
      const update = { loginFailedCount: fails };
      if (fails >= 5) { update.loginLockedUntil = new Date(Date.now() + 15 * 60 * 1000); update.loginFailedCount = 0; }
      await User.findByIdAndUpdate(user._id, update);
    }
    return res.status(401).json({ error: t('auth.login.invalid') });
  }

  if (user.loginFailedCount) await User.findByIdAndUpdate(user._id, { loginFailedCount: 0, loginLockedUntil: null });

  if (!user.emailVerified) {
    const u2 = await User.findOne({ email }).select('+verifyCode +verifyCodeExpires +verifyCodeSentAt username email');
    let autoResent = false;
    const codeExpired = !u2?.verifyCodeExpires || u2.verifyCodeExpires < new Date();
    const withinCooldown = u2?.verifyCodeSentAt && Date.now() - u2.verifyCodeSentAt.getTime() < 60000;
    // Send a new code if: code is expired (always), or cooldown has passed (code still valid but user requested again)
    if (u2 && (codeExpired || !withinCooldown)) {
      const newCode = genCode();
      u2.verifyCode = newCode; u2.verifyCodeExpires = new Date(Date.now()+30*60*1000); u2.verifyCodeSentAt = new Date();
      await u2.save();
      sendEmail(u2.email, emailTemplates.verifyEmail(u2.username, newCode)).catch(()=>{});
      autoResent = true;
    }
    return res.status(403).json({
      status: 'UNVERIFIED_ACCOUNT',
      error: t('auth.login.unverified'),
      autoResent,
      codeWasExpired: codeExpired,
      email,
      expiresAt: u2?.verifyCodeExpires ? u2.verifyCodeExpires.toISOString() : null,
    });
  }

  if (!user.isActive) return res.status(403).json({ error:t('auth.login.suspended') });

  if (user.twoFAEnabled) {
    if (!twoFACode) {
      const tempToken = signTemp(user._id);
      res.cookie('rf_2fa_temp', tempToken, { httpOnly:true, secure:IS_PROD, sameSite:IS_PROD?'strict':'lax', maxAge:5*60*1000 });
      return res.status(200).json({ requires2FA:true, twoFARequired:true, tempToken });
    }
    let valid = false;
    try {
      const secret = aesDecrypt(user.twoFASecret);
      valid = speakeasy.totp.verify({ secret, encoding:'base32', token:twoFACode, window:2 });
    } catch {}
    if (!valid) {
      let bk = -1;
      for (let i = 0; i < (user.twoFABackupCodes||[]).length; i++) {
        if (await bcrypt.compare(twoFACode, user.twoFABackupCodes[i])) { bk = i; break; }
      }
      if (bk<0) return res.status(401).json({ error:t('auth.2fa.invalid') });
      user.twoFABackupCodes.splice(bk,1);
    }
  }

  const { access, refresh } = setAuthCookies(res, user._id);
  user.loginCount=(user.loginCount||0)+1; user.lastLoginAt=new Date();
  const ip=getClientIp(req); const device=req.headers['user-agent']||'';
  user.loginHistory=([{ ip, device, fingerprint:fingerprintDevice(req), time:new Date() }, ...(user.loginHistory||[])]).slice(0,10);
  if (user.refreshTokens && user.refreshTokens.length > 5) user.refreshTokens = user.refreshTokens.slice(-5);
  if (!user.refreshTokens) user.refreshTokens = [];
  user.refreshTokens.push(refresh);
  await user.save();
  const safe = user.toObject(); delete safe.password; delete safe.refreshTokens; delete safe.twoFASecret; delete safe.twoFABackupCodes;
  res.json({ user:safe, token:access });
}));

router.post('/auth/logout', auth, asyncH(async (req,res) => {
  const tok = req.cookies?.rf_refresh || req.body?.refreshToken;
  if (tok) await User.findByIdAndUpdate(req.user._id, { $pull:{ refreshTokens:tok } });
  clearAuthCookies(res);
  res.json({ ok:true });
}));

router.post('/auth/refresh', asyncH(async (req,res) => {
  const tok = req.cookies?.rf_refresh || req.body?.refreshToken;
  if (!tok) return res.status(401).json({ error:'No refresh token' });
  let decoded;
  try { decoded=jwt.verify(tok, JWT_REFRESH_SECRET); }
  catch { return res.status(401).json({ error:'Refresh token expired' }); }
  const user = await User.findById(decoded.id).select('+refreshTokens');
  if (!user||!user.isActive||!user.refreshTokens?.includes(tok)) return res.status(401).json({ error:'Token revoked' });
  const { access } = setAuthCookies(res, user._id);
  res.json({ token:access });
}));

router.get('/auth/me', auth, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id).lean();
  if (!user) return res.status(404).json({ error:t('not_found') });
  const plan = getActivePlan(user);
  const termsUpToDate = !!(user.terms_agreed && user.terms_version === CURRENT_TERMS_VERSION);
  res.json({
    ...user,
    activePlanDetails: plan,
    rate: currencyConfig.rate,
    current_terms_version: CURRENT_TERMS_VERSION,
    terms_up_to_date: termsUpToDate,
    all_agreements_complete: !!(user.privacy_policy_agreed && user.about_understood && termsUpToDate),
    isEarlyAdopter: user.isEarlyAdopter || false,
    isEarlyAdopterActive: isEarlyAdopterActive(user),
    earlyAdopterNumber: user.earlyAdopterNumber || null,
    earlyAdopterGrantedAt: user.earlyAdopterGrantedAt || null,
    earlyAdopterExpiresAt: user.earlyAdopterGrantedAt ? (() => { const d=new Date(user.earlyAdopterGrantedAt); d.setDate(d.getDate()+FOUNDING_MEMBER_PERK_DAYS); return d; })() : null,
    isFoundingMember: isFoundingMemberActive(user),
    foundingMemberRank: user.earlyAdopterNumber && user.earlyAdopterNumber <= FOUNDING_MEMBER_LIMIT ? user.earlyAdopterNumber : null,
    foundingMemberExpiresAt: getFoundingMemberExpiry(user),
    priority_support: !!(user.isEarlyAdopter && user.earlyAdopterNumber <= FOUNDING_MEMBER_LIMIT),
    planLabel: (isFoundingMemberActive(user)) ? 'Founding Member (Premium Access)' : (plan.name || 'Free'),
  });
}));

router.get('/auth/refresh-data', auth, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id).lean();
  if (!user) return res.status(404).json({ error:t('not_found') });
  const plan = getActivePlan(user);
  const isFM = isFoundingMemberActive(user);
  res.json({
    ...user,
    activePlanDetails: plan,
    rate: currencyConfig.rate,
    isFoundingMember: isFM,
    foundingMemberRank: user.earlyAdopterNumber || null,
    foundingMemberExpiresAt: getFoundingMemberExpiry(user),
    priority_support: !!(user.isEarlyAdopter && user.earlyAdopterNumber <= FOUNDING_MEMBER_LIMIT),
    planLabel: isFM ? 'Founding Member (Premium Access)' : (plan.name || 'Free'),
    _refreshedAt: new Date().toISOString(),
  });
}));

router.get('/auth/google', passport.authenticate('google', { scope:['profile','email'], session:false }));
router.get('/auth/google/callback', passport.authenticate('google', { session:false, failureRedirect:`${CLIENT_ORIGIN}?oauthError=1` }),
  asyncH(async (req,res) => {
    setAuthCookies(res, req.user._id);

    res.redirect(`${CLIENT_ORIGIN}?oauth=success`);
  })
);

async function handleResendVerifyCode(req, res) {
  const user = await User.findOne({ email: req.body.email })
    .select('+verifyCode +verifyCodeExpires +verifyCodeSentAt emailVerified username email');
  if (!user || user.emailVerified) return res.json({ ok: true });
  if (user.verifyCodeSentAt && Date.now() - user.verifyCodeSentAt.getTime() < 60_000)
    return res.status(429).json({ error: 'Please wait 60 seconds before requesting a new code.', tooSoon: true,
      waitMs: 60_000 - (Date.now() - user.verifyCodeSentAt.getTime()) });
  const code = genCode();
  user.verifyCode        = code;
  user.verifyCodeExpires = new Date(Date.now() + 30 * 60 * 1000);
  user.verifyCodeSentAt  = new Date();
  await user.save();
  sendEmail(user.email, emailTemplates.verifyEmail(user.username, code)).catch(()=>{});
  res.json({ ok: true, expiresAt: user.verifyCodeExpires.toISOString() });
}
router.post('/auth/resend-verify',        [body('email').isEmail().normalizeEmail()], validate, authLimiter, asyncH(handleResendVerifyCode));
router.post('/auth/resend-verification',  [body('email').isEmail().normalizeEmail()], validate, authLimiter, asyncH(handleResendVerifyCode));

router.post('/auth/forgot-password', [body('email').isEmail().normalizeEmail()], validate, strictLimiter, asyncH(async (req,res) => {
  const user = await User.findOne({ email:req.body.email })
    .select('+resetCode +resetCodeExpires +resetCodeSentAt username email');
  if (user) {
    if (user.resetCodeSentAt && Date.now() - user.resetCodeSentAt.getTime() < 60_000)
      return res.status(429).json({ error: 'Please wait 60 seconds before requesting a new code.', tooSoon: true,
        waitMs: 60_000 - (Date.now() - user.resetCodeSentAt.getTime()) });
    const code = genCode();
    user.resetCode        = code;
    user.resetCodeExpires = new Date(Date.now() + 30 * 60 * 1000);
    user.resetCodeSentAt  = new Date();
    await user.save();
    sendEmail(user.email, { subject:'Your RawFlip password reset code', html: emailBase(`
      <h2>Password Reset</h2>
      <p>Hi <strong>${user.username}</strong>, your password reset code is:</p>
      <div style='text-align:center;margin:24px 0'>
        <div style='display:inline-block;background:#fff4f4;border:2px solid #ffc7c7;border-radius:14px;padding:16px 32px'>
          <span style='font-size:2.2rem;font-weight:800;letter-spacing:.25em;color:#cc2200;font-family:monospace'>${code}</span>
        </div>
      </div>
      <p style='text-align:center;font-size:.88rem;color:#4a4a6a'>⏱ Expires in <strong>30 minutes</strong>. Do not share this code.</p>`) }).catch(()=>{});
  }
  res.json({ ok: true });
}));

router.post('/auth/reset-password', [
  body('email').isEmail().normalizeEmail(),
  body('code').isString().trim().isLength({ min:4, max:8 }),
  body('password').isLength({ min:8 }).matches(/[A-Z]/).matches(/[0-9]/),
], validate, authLimiter, asyncH(async (req,res) => {
  const { email, code, password } = req.body;
  const user = await User.findOne({ email })
    .select('+resetCode +resetCodeExpires +resetCodeSentAt password');
  if (!user || !user.resetCode || !user.resetCodeExpires || user.resetCodeExpires < new Date())
    return res.status(400).json({ error: 'Code expired. Request a new one.', expired: true });
  if (user.resetCode.toUpperCase() !== code.trim().toUpperCase())
    return res.status(400).json({ error: 'Incorrect code. Check your email and try again.' });
  user.password         = password;
  user.resetCode        = null;
  user.resetCodeExpires = null;
  user.resetCodeSentAt  = null;
  await user.save();
  clearAuthCookies(res);
  res.json({ ok: true });
}));

async function handleChangePassword(req, res) {

  const oldPw  = req.body.oldPassword || req.body.currentPassword;
  const newPw  = req.body.newPassword;
  if (!oldPw || !newPw) return res.status(400).json({ error:'Both current and new password are required' });
  if (newPw.length < 8 || !/[A-Z]/.test(newPw) || !/[0-9]/.test(newPw))
    return res.status(400).json({ error:'New password: min 8 chars, 1 uppercase, 1 digit' });
  const user = await User.findById(req.user._id).select('+password');
  if (!await user.comparePassword(oldPw)) return res.status(401).json({ error:'Current password is incorrect' });
  user.password = newPw; await user.save();
  clearAuthCookies(res);
  res.json({ ok:true, message:'Password updated successfully' });
}

router.post('/auth/change-password', auth, asyncH(handleChangePassword));

router.put('/users/me/password', auth, asyncH(handleChangePassword));

router.post('/auth/2fa/setup', auth, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id);
  const secret = speakeasy.generateSecret({ name:`RawFlip (${user.username})` });
  const qr = await QRCode.toDataURL(secret.otpauth_url);
  const encSecret = aesEncrypt(secret.base32);
  user.twoFASecret = encSecret; await user.save();
  res.json({ qrCode:qr, secret:secret.base32 });
}));

router.post('/auth/2fa/verify', auth, [body('token').isLength({ min:6,max:6 }).isNumeric()], validate, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id).select('+twoFASecret');
  if (!user.twoFASecret) return res.status(400).json({ error:'2FA not set up' });
  const secret = aesDecrypt(user.twoFASecret);
  const valid = speakeasy.totp.verify({ secret, encoding:'base32', token:req.body.token, window:2 });
  if (!valid) return res.status(400).json({ error:t('auth.2fa.invalid') });
  const rawCodes = Array.from({ length:8 }, () => crypto.randomBytes(4).toString('hex').toUpperCase());
  const hashedCodes = await Promise.all(rawCodes.map(c => bcrypt.hash(c, 10)));
  user.twoFAEnabled = true; user.twoFABackupCodes = hashedCodes; await user.save();
  res.json({ enabled:true, backupCodes:rawCodes });
}));

router.post('/auth/2fa/disable', auth, [body('token').exists()], validate, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id).select('+twoFASecret +twoFABackupCodes');
  let valid = false;
  try {
    const secret = aesDecrypt(user.twoFASecret);
    valid = speakeasy.totp.verify({ secret, encoding:'base32', token:req.body.token, window:2 });
  } catch {}
  if (!valid) {
    let bk = -1;
    for (let i = 0; i < (user.twoFABackupCodes||[]).length; i++) {
      if (await bcrypt.compare(req.body.token, user.twoFABackupCodes[i])) { bk = i; break; }
    }
    if (bk<0) return res.status(400).json({ error:t('auth.2fa.invalid') });
    user.twoFABackupCodes.splice(bk,1);
  }
  user.twoFAEnabled = false; user.twoFASecret = null; user.twoFABackupCodes = [];
  await user.save();
  res.json({ disabled:true });
}));

router.get('/auth/2fa/status', auth, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id).select('+twoFAEnabled +twoFABackupCodes');
  res.json({ enabled: !!user.twoFAEnabled, backupCodesRemaining: (user.twoFABackupCodes||[]).length });
}));

router.delete('/auth/2fa', auth, [body('code').notEmpty()], validate, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id).select('+twoFASecret +twoFABackupCodes');
  let valid = false;
  try {
    const secret = aesDecrypt(user.twoFASecret);
    valid = speakeasy.totp.verify({ secret, encoding:'base32', token:req.body.code, window:2 });
  } catch {}
  if (!valid) {
    let bk = -1;
    const codes = user.twoFABackupCodes || [];
    for (let i = 0; i < codes.length; i++) {
      if (await bcrypt.compare(req.body.code, codes[i])) { bk = i; break; }
    }
    if (bk<0) return res.status(400).json({ error:t('auth.2fa.invalid') });
    user.twoFABackupCodes.splice(bk,1);
  }
  user.twoFAEnabled = false; user.twoFASecret = null; user.twoFABackupCodes = [];
  await user.save();
  res.json({ enabled:false, disabled:true });
}));

router.post('/auth/login/2fa', [
  body('tempToken').notEmpty(),
  body('code').notEmpty(),
], validate, asyncH(async (req,res) => {
  const { tempToken, code } = req.body;
  let decoded;
  try { decoded = jwt.verify(tempToken, JWT_SECRET); }
  catch { return res.status(401).json({ error:'2FA session expired, please log in again' }); }
  const user = await User.findById(decoded.id).select('+twoFASecret +twoFABackupCodes +refreshTokens');
  if (!user || !user.isActive) return res.status(401).json({ error:'User not found or suspended' });

  let valid = false;
  try {
    const secret = aesDecrypt(user.twoFASecret);
    valid = speakeasy.totp.verify({ secret, encoding:'base32', token:code, window:2 });
  } catch {}
  if (!valid) {
    let bk = -1;
    const codes = user.twoFABackupCodes || [];
    for (let i = 0; i < codes.length; i++) {
      if (await bcrypt.compare(code, codes[i])) { bk = i; break; }
    }
    if (bk<0) return res.status(401).json({ error:t('auth.2fa.invalid') });
    user.twoFABackupCodes.splice(bk,1);
  }
  const { access, refresh } = setAuthCookies(res, user._id);
  user.loginCount=(user.loginCount||0)+1; user.lastLoginAt=new Date();
  if (!user.refreshTokens) user.refreshTokens = [];
  user.refreshTokens.push(refresh);
  await user.save();
  const safe = user.toObject();
  delete safe.password; delete safe.refreshTokens; delete safe.twoFASecret; delete safe.twoFABackupCodes;
  res.json({ user:safe, token:access });
}));

router.get('/subscription', auth, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id);
  const activePlan = getActivePlan(user);
  const history = await Subscription.find({ userId:req.user._id }).sort({ createdAt:-1 }).limit(10).lean();
  const isFM = isFoundingMemberActive(user);
  const fmExpiry = getFoundingMemberExpiry(user);
  res.json({
    activePlan, planExpiresAt:user.planExpiresAt,
    activePlanDbId: user.activePlan || 'free',
    plans: isFM ? LEGACY_PLANS : PLANS,
    allPlans: PLANS,
    legacyPlans: LEGACY_PLANS,
    history,
    isFoundingMember: isFM,
    foundingMemberRank: user.earlyAdopterNumber || null,
    foundingMemberExpiresAt: fmExpiry,
    hidePaidPlans: isFM,
  });
}));

router.get('/subscription/me', auth, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id);
  const activePlan = getActivePlan(user);
  const history = await Subscription.find({ userId:req.user._id }).sort({ createdAt:-1 }).limit(10).lean();
  const isFM = isFoundingMemberActive(user);
  const fmExpiry = getFoundingMemberExpiry(user);
  res.json({
    activePlan, planExpiresAt:user.planExpiresAt,
    activePlanDbId: user.activePlan || 'free',
    plans: isFM ? LEGACY_PLANS : PLANS,
    allPlans: PLANS,
    legacyPlans: LEGACY_PLANS,
    history,
    isFoundingMember: isFM,
    foundingMemberRank: user.earlyAdopterNumber || null,
    foundingMemberExpiresAt: fmExpiry,
    hidePaidPlans: isFM,
  });
}));

router.post('/subscription/upgrade', auth, [body('planId').isIn(['basic','pro','legacy_basic','legacy_pro'])], validate, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id);
  const currentPlan = getActivePlan(user);
  const newPlanId = req.body.planId || req.body.plan;
  const newPlan = PLANS[newPlanId] || LEGACY_PLANS[newPlanId];
  if (!newPlan) return res.status(400).json({ error:'Invalid plan' });

  if (newPlan.costNGN < currentPlan.costNGN && user.activePlan !== 'free') {
    return res.status(400).json({ error:'Downgrades apply after current billing cycle ends. Current plan will expire naturally.' });
  }

  const sub = await purchaseSubscription(user._id, newPlanId);
  res.json({ ok:true, subscription:sub, newPlan });
}));

router.post('/subscription/purchase', auth, [body('plan').optional().isIn(['basic','pro','legacy_basic','legacy_pro']), body('planId').optional().isIn(['basic','pro','legacy_basic','legacy_pro'])], validate, asyncH(async (req,res) => {
  const newPlanId = req.body.planId || req.body.plan;
  if (!newPlanId || (!PLANS[newPlanId] && !LEGACY_PLANS[newPlanId])) return res.status(400).json({ error:'Invalid plan' });
  const user = await User.findById(req.user._id);
  const sub = await purchaseSubscription(user._id, newPlanId);
  res.json({ ok:true, subscription:sub, newPlan:PLANS[newPlanId] || LEGACY_PLANS[newPlanId] });
}));

router.post('/subscription/gift', auth, [
  body('planId').isIn(['basic','pro']),
  body('recipientId').isMongoId(),
], validate, asyncH(async (req,res) => {
  const { planId, recipientId } = req.body;
  if (recipientId === req.user._id.toString())
    return res.status(400).json({ error:'You cannot gift a subscription to yourself' });
  const plan = PLANS[planId];
  const [giver, recipient] = await Promise.all([
    User.findById(req.user._id),
    User.findById(recipientId),
  ]);
  if (!recipient || !recipient.isActive)
    return res.status(404).json({ error:'Recipient user not found' });
  if (giver.availableBalance < plan.costNGN)
    return res.status(400).json({ error:`Insufficient balance. Plan costs ₦${plan.costNGN.toLocaleString()}` });

  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {

      await walletMove({ session, userId:giver._id, fromBucket:'available', toBucket:'external',
        amount:plan.costNGN, type:'gift_subscription', note:`Gifted ${plan.name} plan to ${recipient.username}` });

      await giftSubscription({ session, userId:recipientId, planId, durationDays:30, giftedBy:`user:${giver._id}` });
    });
    sendNotification({
      recipient: recipientId, sender: req.user._id, type:'system',
      title:`🎁 You received a ${plan.name} subscription!`,
      message:`${giver.username} gifted you a ${plan.name} plan for 30 days.`,
      link:'/subscription',
    }).catch(()=>{});
    res.json({ ok:true, message:`${plan.name} subscription gifted to ${recipient.username}` });
  } finally { await session.endSession(); }
}));

router.post('/subscription/cancel', auth, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id);
  if (isFoundingMemberActive(user) && user.activePlan === 'free') {
    return res.status(400).json({ error:'Founding Members enjoy zero-fee access for 180 days — no subscription to cancel. Lock in a Legacy plan to continue benefits after your perk period.' });
  }
  if (user.activePlan === 'free') return res.status(400).json({ error:'Already on free plan' });

  await Subscription.findOneAndUpdate({ userId:user._id, status:'active' }, { status:'cancelled' });
  res.json({ ok:true, message:'Subscription cancelled. Access remains until current period ends.' });
}));

router.get('/referral/dashboard', auth, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id);
  const referrals = await Referral.find({ referrerId:req.user._id })
    .populate('refereeId','username emailVerified createdAt')
    .sort({ createdAt:-1 })
    .lean();
  const nextMilestone = REFERRAL_MILESTONES.find(m => m.count > user.referralCount);
  res.json({
    referralCode: user.referralCode,
    referralLink: `${CLIENT_ORIGIN}?ref=${user.referralCode}`,
    referralCount: user.referralCount,
    referralEarnings: user.referralEarnings,
    earningsBalance: user.earningsBalance,
    referrals: referrals.map(r=>({
      username: r.refereeId?.username,
      emailVerified: r.refereeId?.emailVerified,
      joinedAt: r.refereeId?.createdAt,
      emailRewardPaid: r.emailVerifyRewardPaid,
      purchaseRewardPaid: r.firstPurchaseRewardPaid,
    })),
    milestones: REFERRAL_MILESTONES.map(m=>({ ...m, claimed: user.referralCount >= m.count })),
    nextMilestone: nextMilestone ? { ...nextMilestone, remaining: nextMilestone.count - user.referralCount } : null,
  });
}));

router.get('/wallet', auth, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id);
  const activePlan = getActivePlan(user);
  const txs = await WalletTx.find({ user:req.user._id }).sort({ createdAt:-1 }).limit(20).lean();
  const isFMActive = isFoundingMemberActive(user);
  // Build escrow countdown timers for seller's pending escrow releases
  const pendingEscrow = await Transaction.find({
    sellerId: req.user._id,
    state: { $in: [TX_STATES.DELIVERED, TX_STATES.RECEIVED_CONFIRMED] },
    autoReleaseAt: { $ne: null },
  }).select('itemTitle escrowAmount autoReleaseAt').lean();
  const now = Date.now();
  const escrowTimers = pendingEscrow.map(tx => {
    const ms = tx.autoReleaseAt ? (new Date(tx.autoReleaseAt).getTime() - now) : 0;
    return {
      transactionId: tx._id,
      itemTitle: tx.itemTitle || 'Escrow item',
      escrowAmount: tx.escrowAmount || 0,
      autoReleaseAt: tx.autoReleaseAt,
      hoursRemaining: Math.max(0, Math.ceil(ms / 3600000)),
    };
  });
  res.json({
    availableBalance: user.availableBalance,
    reservedBalance:  user.reservedBalance,
    escrowBalance:    user.escrowBalance,
    withdrawableBalance: user.withdrawableBalance,
    earningsBalance:  user.earningsBalance,
    transactions: txs,
    rate: currencyConfig.rate,
    activePlan: activePlan.id,
    planMinWithdrawal: isFMActive ? 0 : activePlan.minWithdrawal,
    isFoundingMember: isFMActive,
    foundingMemberRank: user.earlyAdopterNumber || null,
    foundingMemberExpiresAt: getFoundingMemberExpiry(user),
    feeNote: isFMActive
      ? { standard: 'Standard fee: ₦100 per ₦5,000.', yourFee: 'Your Fee: ₦0 (Founding Member Perk!)', color: '#f0ad4e' }
      : null,
    escrowTimers,
  });
}));

router.get('/wallet/balance/:userId', auth, asyncH(async (req,res) => {

  const isSelf = req.params.userId === req.user._id.toString();
  if (!isSelf && req.user.role !== 'admin') return res.status(403).json({ error:t('forbidden') });
  const user = await User.findById(req.params.userId).select('availableBalance reservedBalance escrowBalance withdrawableBalance earningsBalance');
  if (!user) return res.status(404).json({ error:t('not_found') });
  res.json(user);
}));

router.post('/wallet/deposit/request', auth, requireAgreements, uploadProof.single('proof'), [
  body('amount').isFloat({ min:1 }).withMessage('Enter a valid deposit amount'),
  body('paymentMethod').optional().trim(),
  body('bankRef').optional().trim().isLength({ max:100 }),
], validate, asyncH(async (req,res) => {
  const amount = parseFloat(req.body.amount);
  if (amount < 1) return res.status(400).json({ error:'Enter a valid deposit amount' });

  const user = await User.findById(req.user._id);
  const fee     = calculateDepositFee(amount, user);
  const netAmount = amount - fee;
  const proofImageUrl = req.file ? `/uploads/${req.file.filename}` : null;

  const walletTx = await WalletTx.create({
    user: req.user._id,
    type: 'deposit',
    fromBucket: 'external',
    toBucket: 'available',
    amount,
    fee,
    netAmount,
    currency: 'NGN',
    status: proofImageUrl ? WALLET_TX_STATES.PROOF_SUBMITTED : WALLET_TX_STATES.PENDING,
    proofImageUrl,
    note: `Deposit request — Ref: ${req.body.bankRef || 'N/A'}`,
    paymentDetails: { method: req.body.paymentMethod || 'bank_transfer', bankRef: req.body.bankRef || '' },
  });

  if (req.body.agreeAbout === true || req.body.agreeAbout === 'true') {
    await User.updateOne({ _id: req.user._id }, {
      $set: { about_understood: true, about_understood_at: new Date() }
    });
  }

  const admins = await User.find({ role:'admin', isActive:true }).select('_id');
  admins.forEach(a => {
    sendNotification({ recipient:a._id, type:'system', title:'New Deposit Request', message:`${req.user.username} requested ₦${amount.toLocaleString()} deposit`, link:'/admin' }).catch(()=>{});
    io.to(`user:${a._id}`).emit('admin:deposit_request', { walletTxId:walletTx._id, userId:req.user._id, username:req.user.username, amount, fee, netAmount });
  });

  telegramNotifyAdmin(`💰 New Deposit Request\nUser: @${req.user.username}\nAmount: ₦${amount.toLocaleString()}\nFee: ₦${fee.toLocaleString()}\nNet: ₦${netAmount.toLocaleString()}\nTx ID: ${walletTx._id}\n\nApprove: /approve ${walletTx._id}\nReject: /reject ${walletTx._id}`);

  res.status(201).json({
    ok: true,
    walletTxId: walletTx._id,
    amount, fee, netAmount,
    status: walletTx.status,
    instructions: {
      bank: process.env.PAYMENT_BANK_NAME || process.env.BANK_NAME || 'RawFlip Payments Ltd',
      account: process.env.PAYMENT_ACCOUNT_NUMBER || process.env.BANK_ACCOUNT || '0000000000',
      accountName: process.env.PAYMENT_ACCOUNT_NAME || process.env.BANK_ACCOUNT_NAME || 'RawFlip Escrow',
      reference: walletTx._id.toString().slice(-8).toUpperCase(),
      note: `Transfer ₦${amount.toLocaleString()} and upload your payment proof or send via Telegram bot.`,
    },
  });
}));

router.post('/wallet/deposit/:txId/proof', auth, uploadProof.single('proof'), [param('txId').isMongoId()], validate, asyncH(async (req,res) => {
  const wtx = await WalletTx.findOne({ _id:req.params.txId, user:req.user._id, type:'deposit' });
  if (!wtx) return res.status(404).json({ error:'Transaction not found' });
  if (wtx.status !== WALLET_TX_STATES.PENDING) return res.status(400).json({ error:`Cannot submit proof for status: ${wtx.status}` });
  if (!req.file) return res.status(400).json({ error:'Proof image required' });

  wtx.proofImageUrl = `/uploads/${req.file.filename}`;
  wtx.status = WALLET_TX_STATES.PROOF_SUBMITTED;
  await wtx.save();

  telegramNotifyAdmin(`📎 Proof Submitted\nUser: @${req.user.username}\nTx ID: ${wtx._id}\nAmount: ₦${wtx.amount.toLocaleString()}\nApprove: /approve ${wtx._id}\nReject: /reject ${wtx._id}`);
  res.json({ ok:true, status:wtx.status });
}));

router.post('/wallet/withdraw/request', auth, requireAgreements, requireKYC, [
  body('amount').isFloat({ min:1 }),

  body('bankName').optional().trim(),
  body('accountNumber').optional().trim(),
  body('accountName').optional().trim(),
  body('paymentDetails.bankName').optional().trim(),
  body('paymentDetails.accountNumber').optional().trim(),
  body('paymentDetails.accountName').optional().trim(),
], validate, asyncH(async (req,res) => {
  const amount = parseFloat(req.body.amount);

  const pd = req.body.paymentDetails || {};
  if (!req.body.bankName && pd.bankName) req.body.bankName = pd.bankName;
  if (!req.body.accountNumber && pd.accountNumber) req.body.accountNumber = pd.accountNumber;
  if (!req.body.accountName && pd.accountName) req.body.accountName = pd.accountName;
  if (!req.body.bankName || !req.body.accountNumber || !req.body.accountName) {
    return res.status(400).json({ error:'Bank name, account number and account name are required' });
  }
  const user = await User.findById(req.user._id);
  const plan = getActivePlan(user);

  if (!isFoundingMemberActive(user) && !isEarlyAdopterActive(user)) {
    if (plan.minWithdrawal > 0 && amount < plan.minWithdrawal)
      return res.status(400).json({ error:`Minimum withdrawal for your ${plan.name} plan is ₦${plan.minWithdrawal.toLocaleString()}` });
    if (amount < MIN_WITHDRAWAL && plan.minWithdrawal >= MIN_WITHDRAWAL)
      return res.status(400).json({ error:`Minimum withdrawal is ₦${MIN_WITHDRAWAL.toLocaleString()}` });
  }

  const totalAvailable = user.withdrawableBalance + user.earningsBalance;
  if (totalAvailable < amount) {
    return res.status(400).json({ error:`Insufficient withdrawable balance. Available: ₦${totalAvailable.toLocaleString()}` });
  }

  const fee = calculateWithdrawalFee(amount, user);
  const netAmount = amount - fee;

  const paymentDetails = {
    bankName: req.body.bankName,
    accountNumber: req.body.accountNumber,
    accountName: req.body.accountName,
  };

  const session = await mongoose.startSession();
  let wtx;
  try {
    await session.withTransaction(async () => {

      let remaining = amount;
      const freshUser = await User.findById(user._id).session(session);
      const fromWithdrawable = Math.min(freshUser.withdrawableBalance, remaining);
      if (fromWithdrawable > 0) {
        await User.findByIdAndUpdate(user._id, { $inc:{ withdrawableBalance:-fromWithdrawable } }, { session });
        remaining -= fromWithdrawable;
      }
      if (remaining > 0) {
        const fromEarnings = Math.min(freshUser.earningsBalance, remaining);
        if (fromEarnings < remaining) throw new Error('Insufficient balance');
        await User.findByIdAndUpdate(user._id, { $inc:{ earningsBalance:-fromEarnings } }, { session });
      }

      wtx = await WalletTx.create([{
        user: user._id, type:'withdrawal', fromBucket:'withdrawable', toBucket:'external',
        amount, fee, netAmount, currency:'NGN',
        status: WALLET_TX_STATES.PENDING,
        note: `Withdrawal to ${paymentDetails.bankName} — ${paymentDetails.accountNumber}`,
        paymentDetails,
      }], { session });
      wtx = wtx[0];
    });

    const admins = await User.find({ role:'admin', isActive:true }).select('_id');
    admins.forEach(a => {
      sendNotification({ recipient:a._id, type:'system', title:'Withdrawal Request', message:`${user.username} requested ₦${amount.toLocaleString()} withdrawal`, link:'/admin' }).catch(()=>{});
    });

    telegramNotifyAdmin(`💸 Withdrawal Request\nUser: @${user.username}\nAmount: ₦${amount.toLocaleString()}\nFee: ₦${fee.toLocaleString()}\nNet: ₦${netAmount.toLocaleString()}\nBank: ${paymentDetails.bankName}\nAcc: ${paymentDetails.accountNumber}\nTx ID: ${wtx._id}\n\nApprove: /approve ${wtx._id}\nReject: /reject ${wtx._id}`);
    res.status(201).json({ ok:true, walletTxId:wtx._id, amount, fee, netAmount, status:wtx.status });
  } finally { await session.endSession(); }
}));

router.get('/wallet/transactions', auth, asyncH(async (req,res) => {
  const { skip,limit,page } = paginate(req);
  const filter = { user:req.user._id };
  if (req.query.type) filter.type = req.query.type;
  if (req.query.status) filter.status = req.query.status;
  const [txs,total] = await Promise.all([
    WalletTx.find(filter).sort({ createdAt:-1 }).skip(skip).limit(limit).lean(),
    WalletTx.countDocuments(filter),
  ]);
  res.json({ transactions:txs, total, page, pages:Math.ceil(total/limit) });
}));

router.post('/admin/wallet-tx/:id/approve', auth, adminOnly, [
  param('id').isMongoId(),
  body('note').optional().trim().isLength({ max:500 }),
], validate, asyncH(async (req,res) => {
  const wtx = await WalletTx.findById(req.params.id).populate('user','username email availableBalance withdrawableBalance earningsBalance activePlan planExpiresAt');
  if (!wtx) return res.status(404).json({ error:t('not_found') });
  if (!['deposit','withdrawal'].includes(wtx.type)) return res.status(400).json({ error:'Only deposits and withdrawals can be approved' });
  if (wtx.status !== WALLET_TX_STATES.PROOF_SUBMITTED && wtx.type === 'deposit') {
    return res.status(400).json({ error:`Cannot approve deposit with status: ${wtx.status}` });
  }
  if (wtx.status !== WALLET_TX_STATES.PENDING && wtx.type === 'withdrawal') {
    return res.status(400).json({ error:`Cannot approve withdrawal with status: ${wtx.status}` });
  }

  if (wtx.adminActionAt) return res.status(409).json({ error:'This transaction has already been actioned' });

  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      if (wtx.type === 'deposit') {

        await User.findByIdAndUpdate(wtx.user._id, { $inc:{ availableBalance:wtx.netAmount } }, { session });
        await WalletTx.findByIdAndUpdate(wtx._id, {
          status: WALLET_TX_STATES.APPROVED,
          approvedBy: req.user._id,
          approvedAt: new Date(),
          adminActionAt: new Date(),
        }, { session });
      } else {

        await WalletTx.findByIdAndUpdate(wtx._id, {
          status: WALLET_TX_STATES.APPROVED,
          approvedBy: req.user._id,
          approvedAt: new Date(),
          adminActionAt: new Date(),
        }, { session });
      }
      const approveNote = (req.body && req.body.note) ? req.body.note : 'Approved via admin panel';
      await logAdmin(req.user._id, `approve_${wtx.type}`, 'WalletTx', wtx._id.toString(), approveNote, { amount:wtx.amount, fee:wtx.fee, netAmount:wtx.netAmount, userId:wtx.user._id }, 'web');
    });

    io.to(`user:${wtx.user._id}`).emit('wallet:tx_approved', { walletTxId:wtx._id, type:wtx.type, amount:wtx.amount, netAmount:wtx.netAmount });
    sendNotification({ recipient:wtx.user._id, type:'system', title:`${wtx.type==='deposit'?'Deposit':'Withdrawal'} Approved ✅`, message:`₦${wtx.netAmount.toLocaleString()} ${wtx.type==='deposit'?'credited to your wallet':'sent to your bank account'}`, link:'/wallet' }).catch(()=>{});
    if (wtx.type==='deposit') sendEmail(wtx.user.email, emailTemplates.depositApproved(wtx.user.username, wtx.amount, wtx.fee)).catch(()=>{});
    else sendEmail(wtx.user.email, emailTemplates.withdrawalApproved(wtx.user.username, wtx.amount, wtx.fee)).catch(()=>{});

    res.json({ ok:true, walletTxId:wtx._id });
  } finally { await session.endSession(); }
}));

router.post('/admin/wallet-tx/:id/reject', auth, adminOnly, [
  param('id').isMongoId(),
  body('reason').trim().isLength({ min:5, max:500 }),
], validate, asyncH(async (req,res) => {
  const wtx = await WalletTx.findById(req.params.id).populate('user','username email');
  if (!wtx) return res.status(404).json({ error:t('not_found') });
  if (!['deposit','withdrawal'].includes(wtx.type)) return res.status(400).json({ error:'Only deposits and withdrawals can be rejected' });
  if (wtx.adminActionAt) return res.status(409).json({ error:'Already actioned' });
  if (![WALLET_TX_STATES.PENDING, WALLET_TX_STATES.PROOF_SUBMITTED].includes(wtx.status)) {
    return res.status(400).json({ error:`Cannot reject in status: ${wtx.status}` });
  }

  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      if (wtx.type === 'withdrawal') {

        await User.findByIdAndUpdate(wtx.user._id, { $inc:{ withdrawableBalance:wtx.amount } }, { session });
      }
      await WalletTx.findByIdAndUpdate(wtx._id, {
        status: WALLET_TX_STATES.REJECTED,
        rejectedBy: req.user._id,
        rejectedAt: new Date(),
        rejectReason: req.body.reason,
        adminActionAt: new Date(),
      }, { session });
      await logAdmin(req.user._id, `reject_${wtx.type}`, 'WalletTx', wtx._id.toString(), req.body.reason, { userId:wtx.user._id }, 'web');
    });

    sendNotification({ recipient:wtx.user._id, type:'system', title:`${wtx.type==='deposit'?'Deposit':'Withdrawal'} Rejected`, message:`Reason: ${req.body.reason}`, link:'/wallet' }).catch(()=>{});
    if (wtx.type==='deposit') sendEmail(wtx.user.email, emailTemplates.depositRejected(wtx.user.username, req.body.reason)).catch(()=>{});
    else sendEmail(wtx.user.email, emailTemplates.withdrawalRejected(wtx.user.username, req.body.reason)).catch(()=>{});

    res.json({ ok:true });
  } finally { await session.endSession(); }
}));

router.get('/admin/deposits', auth, adminOnly, asyncH(async (req,res) => {
  const { skip, limit, page } = paginate(req);
  const status = req.query.status || 'proof_submitted';
  const filter = { type: 'deposit' };
  if (status !== 'all') filter.status = status;
  const [deposits, total] = await Promise.all([
    WalletTx.find(filter)
      .populate('user', 'username email phone whatsapp avatar')
      .sort({ createdAt: -1 })
      .skip(skip).limit(limit).lean(),
    WalletTx.countDocuments(filter),
  ]);
  res.json({ deposits, total, page, pages: Math.ceil(total/limit) });
}));

router.get('/admin/wallet-tx', auth, adminOnly, asyncH(async (req,res) => {
  const { skip,limit,page } = paginate(req);
  const filter = {};
  if (req.query.type) filter.type = req.query.type;
  if (req.query.status) filter.status = req.query.status;
  else filter.status = { $in:['pending','proof_submitted'] };
  const [txs,total] = await Promise.all([
    WalletTx.find(filter).populate('user','username email avatar').sort({ createdAt:-1 }).skip(skip).limit(limit).lean(),
    WalletTx.countDocuments(filter),
  ]);
  res.json({ transactions:txs, total, page, pages:Math.ceil(total/limit) });
}));

const savedSearchSchema = new mongoose.Schema({
  user:       { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, index:true },
  name:       { type:String, required:true, trim:true, maxlength:100 },
  query:      { type:String, default:'', trim:true },
  filters:    { type:mongoose.Schema.Types.Mixed, default:{} },
  emailAlert: { type:Boolean, default:false },
  lastAlertAt:{ type:Date, default:null },
}, { timestamps:true });
const SavedSearch = mongoose.model('SavedSearch', savedSearchSchema);

router.get('/saved-searches', auth, asyncH(async (req,res) => {
  const searches = await SavedSearch.find({ user:req.user._id }).sort({ createdAt:-1 }).limit(20).lean();
  res.json({ searches });
}));

router.post('/saved-searches', auth, [
  body('name').trim().isLength({ min:1, max:100 }),
  body('query').optional().trim(),
  body('filters').optional().isObject(),
  body('emailAlert').optional().isBoolean(),
], validate, asyncH(async (req,res) => {
  const count = await SavedSearch.countDocuments({ user:req.user._id });
  if (count >= 20) return res.status(400).json({ error:'Maximum 20 saved searches allowed' });
  const ss = await SavedSearch.create({
    user: req.user._id,
    name: req.body.name,
    query: req.body.query || '',
    filters: req.body.filters || {},
    emailAlert: req.body.emailAlert || false,
  });
  res.status(201).json({ search:ss });
}));

router.delete('/saved-searches/:id', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const ss = await SavedSearch.findOneAndDelete({ _id:req.params.id, user:req.user._id });
  if (!ss) return res.status(404).json({ error:'Not found' });
  res.json({ ok:true });
}));

const enforcePlanListingLimit = asyncH(async (req,res,next) => {
  const user = await User.findById(req.user._id);
  if (isFoundingMemberActive(user) || isEarlyAdopterActive(user)) return next();
  const plan = getActivePlan(user);
  if (plan.listingLimit === Infinity) return next();
  const count = await Listing.countDocuments({ seller:user._id, status:'active' });
  if (count >= plan.listingLimit) {
    return res.status(403).json({
      error:`Your ${plan.name} plan allows a maximum of ${plan.listingLimit} active listing${plan.listingLimit!==1?'s':''}. Upgrade to list more.`,
      currentPlan: plan.id,
      listingLimit: plan.listingLimit,
      upgradeRequired: true,
    });
  }
  next();
});

router.get('/listings', asyncH(async (req,res) => {
  const { skip,limit,page } = paginate(req);

  const filter = { status:'active' };
  if (req.query.category)   filter.category  = req.query.category;
  if (req.query.condition)  filter.condition  = req.query.condition;
  if (req.query.seller)     filter.seller     = mongoose.Types.ObjectId.isValid(req.query.seller) ? new mongoose.Types.ObjectId(req.query.seller) : null;
  if (req.query.minPrice||req.query.maxPrice) { filter.price={}; if(req.query.minPrice)filter.price.$gte=Number(req.query.minPrice); if(req.query.maxPrice)filter.price.$lte=Number(req.query.maxPrice); }
  if (req.query.ships==='true')      filter.shipping   = true;
  if (req.query.negotiable==='true') filter.negotiable = true;
  if (req.query.q)          filter.$text = { $search:req.query.q };

  if (req.query.city) {
    const cityRe = new RegExp(req.query.city.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'i');
    const sellersInCity = await User.find({ location:cityRe, isActive:true }).select('_id').lean();
    filter.seller = { $in: sellersInCity.map(u=>u._id) };
  }

  if (req.query.conditions) {
    const conds = req.query.conditions.split(',').filter(c=>['new','like_new','good','fair','poor'].includes(c));
    if (conds.length) filter.condition = { $in:conds };
  }

  const sortMap = { newest:{createdAt:-1}, oldest:{createdAt:1}, price_asc:{price:1}, price_desc:{price:-1}, popular:{views:-1}, priority:{searchPriority:-1,createdAt:-1} };
  const sort = sortMap[req.query.sort] || { searchPriority:-1, createdAt:-1 };

  const sellerActiveFilter = { 'seller.isActive': true };

  const basePipeline = [
    { $match: filter },
    { $lookup: {
        from: 'users',
        localField: 'seller',
        foreignField: '_id',
        as: 'seller',
        pipeline: [{ $project: { username:1, avatar:1, rating:1, reviewCount:1, isVerified:1, location:1, activePlan:1, isActive:1 } }],
    }},
    { $unwind: '$seller' },
    { $match: sellerActiveFilter },
  ];

  const [results, countResult, facets] = await Promise.all([

    Listing.aggregate([
      ...basePipeline,
      { $sort: sort },
      { $skip: skip },
      { $limit: limit },
    ]),

    Listing.aggregate([
      ...basePipeline,
      { $count: 'total' },
    ]),

    req.query.facets !== 'false' ? Listing.aggregate([
      ...basePipeline,
      { $facet: {
        byCategory:  [{ $group:{ _id:'$category',  count:{ $sum:1 } } }, { $sort:{ count:-1 } }],
        byCondition: [{ $group:{ _id:'$condition', count:{ $sum:1 } } }, { $sort:{ count:-1 } }],
        priceRange:  [{ $group:{ _id:null, min:{ $min:'$price' }, max:{ $max:'$price' } } }],
      }},
    ]).then(r=>r[0]||{}).catch(()=>({})) : Promise.resolve({}),
  ]);

  const total = countResult[0]?.total || 0;

  res.json({
    listings: results.map(l => ({ ...l, usdPrice:convertNGNtoUSD(l.price) })),
    total, page, pages: Math.ceil(total/limit), rate: currencyConfig.rate,
    facets: {
      byCategory:  (facets.byCategory||[]).map(f=>({ value:f._id, count:f.count })),
      byCondition: (facets.byCondition||[]).map(f=>({ value:f._id, count:f.count })),
      priceRange:  facets.priceRange && facets.priceRange[0] ? { min:facets.priceRange[0].min, max:facets.priceRange[0].max } : null,
    },
  });
}));

router.patch('/listings/bulk', auth, [
  body('ids').isArray({ min:1, max:50 }),
  body('ids.*').isMongoId(),
  body('updates').isObject(),
], validate, asyncH(async (req,res) => {
  const { ids, updates } = req.body;

  const allowed = ['price','status','negotiable','shipping','shippingCost','tags'];
  const safeUpdates = {};
  allowed.forEach(k => { if (updates[k] !== undefined) safeUpdates[k] = updates[k]; });
  if (!Object.keys(safeUpdates).length)
    return res.status(400).json({ error:'No valid fields to update' });

  if (safeUpdates.status && !['active','archived'].includes(safeUpdates.status))
    return res.status(400).json({ error:'Bulk status can only be active or archived' });
  const result = await Listing.updateMany(
    { _id:{ $in:ids }, seller:req.user._id },
    { $set:safeUpdates }
  );
  res.json({ ok:true, matched:result.matchedCount, modified:result.modifiedCount });
}));

router.get('/listings/:id', asyncH(async (req,res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ error:'Invalid ID' });
  const l = await Listing.findByIdAndUpdate(req.params.id, { $inc:{ views:1 } }, { new:true })
    .populate('seller','username avatar rating reviewCount isVerified location activePlan planExpiresAt');
  if (!l||l.status==='archived') return res.status(404).json({ error:t('not_found') });

  if (l.seller && l.seller.isActive === false) return res.status(404).json({ error:t('not_found') });

  let exposePhone = false;
  if (req.headers.authorization || req.cookies?.refreshToken) {
    try {
      const tok = (req.headers.authorization||'').replace('Bearer ','');
      if (tok) {
        const dec = jwt.verify(tok, JWT_SECRET);
        if (dec && dec.id) {
          const hasPurchase = await Transaction.exists({
            buyerId: dec.id, itemId: l._id,
            state: { $in:['ESCROW_FUNDED','SHIPPED','DELIVERED','COMPLETED'] },
          });
          exposePhone = !!hasPurchase;
        }
      }
    } catch(_) {}
  }
  const lObj = l.toObject();
  if (!exposePhone) delete lObj.contactPhone;
  res.json({ ...lObj, usdPrice:convertNGNtoUSD(l.price), rate:currencyConfig.rate, phoneUnlocked:exposePhone });
}));

router.post('/listings', auth, upload.array('images',8), enforcePlanListingLimit, [
  body('title').trim().isLength({ min:3, max:150 }),
  body('description').trim().isLength({ min:10, max:5000 }),
  body('price').isFloat({ min:0, max:100000000 }),
  body('category').isIn(['electronics','clothing','furniture','vehicles','sports','books','toys','art','jewelry','food','services','other']),
  body('condition').isIn(['new','like_new','good','fair','poor']),
], validate, asyncH(async (req,res) => {
  const user = await User.findById(req.user._id);
  const plan = getActivePlan(user);
  const searchPriority = (plan.id==='pro'||plan.id==='founding_member'||plan.id==='legacy_pro')?2:plan.id==='basic'||plan.id==='legacy_basic'?1:0;

  const l = await Listing.create({
    seller: req.user._id,
    title: req.body.title, description: req.body.description,
    price: parseFloat(req.body.price), category: req.body.category, condition: req.body.condition,
    location: req.body.location||'', tags:(req.body.tags||'').split(',').map(t=>t.trim()).filter(Boolean).slice(0,10),
    negotiable: req.body.negotiable==='true'||req.body.negotiable===true,
    shipping: req.body.shipping==='true'||req.body.shipping===true,
    shippingCost: parseFloat(req.body.shippingCost)||0,
    contactPhone: (req.body.contactPhone||'').slice(0,30),
    images: (req.files||[]).map(f=>`/uploads/${f.filename}`),
    searchPriority,
  });
  esIndex(l).catch(()=>{});
  res.status(201).json({ ...l.toObject(), usdPrice:convertNGNtoUSD(l.price) });
}));

router.put('/listings/:id', auth, upload.array('images',8), [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const l = await Listing.findById(req.params.id);
  if (!l) return res.status(404).json({ error:t('not_found') });
  if (!l.seller.equals(req.user._id) && req.user.role!=='admin') return res.status(403).json({ error:t('forbidden') });
  const user = await User.findById(l.seller);
  const plan = getActivePlan(user);
  const searchPriority = (plan.id==='pro'||plan.id==='founding_member'||plan.id==='legacy_pro')?2:plan.id==='basic'||plan.id==='legacy_basic'?1:0;
  const allowed = ['title','description','price','category','condition','location','tags','negotiable','shipping','shippingCost','contactPhone'];
  allowed.forEach(f=>{ if(req.body[f]!==undefined) l[f]=req.body[f]; });
  if (req.body.tags) l.tags=req.body.tags.split(',').map(t=>t.trim()).filter(Boolean).slice(0,10);
  if (req.files?.length) l.images=(req.files||[]).map(f=>`/uploads/${f.filename}`);
  l.searchPriority = searchPriority;
  await l.save();
  esIndex(l).catch(()=>{});
  res.json({ ...l.toObject(), usdPrice:convertNGNtoUSD(l.price) });
}));

router.delete('/listings/:id', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const l = await Listing.findById(req.params.id);
  if (!l) return res.status(404).json({ error:t('not_found') });
  if (!l.seller.equals(req.user._id) && req.user.role!=='admin') return res.status(403).json({ error:t('forbidden') });
  l.status='archived'; await l.save();
  esDelete(l._id).catch(()=>{});
  res.json({ ok:true });
}));

router.post('/listings/:id/favorite', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const l = await Listing.findById(req.params.id);
  if (!l) return res.status(404).json({ error:t('not_found') });
  const uid = req.user._id;
  const idx = l.favoritedBy.findIndex(id=>id.equals(uid));
  const adding = idx < 0;
  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      if (adding) {
        l.favoritedBy.push(uid);
        await User.findByIdAndUpdate(uid, { $addToSet:{ wishlist:l._id } }, { session });
      } else {
        l.favoritedBy.splice(idx, 1);
        await User.findByIdAndUpdate(uid, { $pull:{ wishlist:l._id } }, { session });
      }
      await l.save({ session });
    });
  } finally { await session.endSession(); }
  res.json({ favorited:adding, count:l.favoritedBy.length });
}));

router.get('/listings/:id/similar', asyncH(async (req,res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ error:'Invalid ID' });
  const l = await Listing.findById(req.params.id);
  if (!l) return res.status(404).json({ error:t('not_found') });
  const similar = await Listing.find({ category:l.category, status:'active', _id:{ $ne:l._id } }).limit(6).sort({ searchPriority:-1,createdAt:-1 }).lean();
  res.json({ listings:similar.map(s=>({ ...s, usdPrice:convertNGNtoUSD(s.price) })) });
}));

router.post('/offers', auth, requireAgreements, [
  body('listingId').isMongoId(),
  body('amount').isFloat({ min:1 }),
  body('message').optional().trim().isLength({ max:1000 }),
], validate, asyncH(async (req,res) => {
  const listing = await Listing.findById(req.body.listingId).populate('seller','username email');
  if (!listing || listing.status!=='active') return res.status(404).json({ error:'Listing not active' });
  if (listing.seller._id.equals(req.user._id)) return res.status(400).json({ error:'Cannot offer on own listing' });

  const amount = Math.round(parseFloat(req.body.amount));
  const session = await mongoose.startSession();
  let offer, tx;
  try {
    await session.withTransaction(async () => {
      const user = await User.findById(req.user._id).session(session);
      if (user.availableBalance < amount) throw new Error(`Insufficient balance. Need ₦${amount.toLocaleString()}, have ₦${user.availableBalance.toLocaleString()}`);

      const now=new Date();
      tx = await Transaction.create([{
        buyerId:req.user._id, sellerId:listing.seller._id, itemId:listing._id,
        itemTitle:listing.title, amount, escrowAmount:0,
        escrowFeePercent:0,
        exchangeRateUsed:currencyConfig.rate, state:TX_STATES.PENDING_OFFER,
        'timestamps_state.PENDING_OFFER':now,
        dispatchDeadlineAt: new Date(now.getTime() + DISPATCH_WINDOW_DAYS*86400000),
        autoReleaseAt: new Date(now.getTime() + (AUTO_RELEASE_HOURS+DISPATCH_WINDOW_DAYS*24)*3600000),
      }],{ session });
      tx = tx[0];

      offer = await Offer.create([{
        listing:listing._id, buyer:req.user._id, seller:listing.seller._id,
        amount, exchangeRateUsed:currencyConfig.rate,
        message:req.body.message||'', transactionId:tx._id,
      }],{ session });
      offer = offer[0];
      await Transaction.findByIdAndUpdate(tx._id,{ offerId:offer._id },{ session });

      await walletMove({ session, userId:req.user._id, fromBucket:'available', toBucket:'reserved', amount, type:'reserve', note:`Offer on "${listing.title}"`, transactionId:tx._id });
    });

    sendNotification({ recipient:listing.seller._id, sender:req.user._id, type:'offer_received', title:'New Offer!', message:`₦${amount.toLocaleString()} offer on "${listing.title}"`, link:'/offers' }).catch(()=>{});
    io.to(`user:${listing.seller._id}`).emit('offer:new', offer);
    res.status(201).json({ offer, transaction:tx });
  } finally { await session.endSession(); }
}));

router.get('/offers/me', auth, asyncH(async (req,res) => {
  const uid = req.user._id;
  const [received, sent] = await Promise.all([
    Offer.find({ seller:uid }).populate('listing','title images price status currency').populate('buyer','username avatar').sort({ createdAt:-1 }).lean(),
    Offer.find({ buyer:uid }).populate('listing','title images price status currency').populate('seller','username avatar').sort({ createdAt:-1 }).lean(),
  ]);
  res.json({ received, sent, rate:currencyConfig.rate });
}));

router.get('/offers', auth, asyncH(async (req,res) => {
  const uid=req.user._id;
  const { skip,limit,page }=paginate(req);
  const isSent=req.query.type==='sent';
  const filter=isSent?{ buyer:uid }:{ seller:uid };
  if (req.query.status) filter.status=req.query.status;
  const [offers,total]=await Promise.all([
    Offer.find(filter).populate('listing','title images price').populate('buyer','username avatar').populate('seller','username avatar').skip(skip).limit(limit).sort({ createdAt:-1 }).lean(),
    Offer.countDocuments(filter),
  ]);
  res.json({ offers, total, page, pages:Math.ceil(total/limit) });
}));

router.put('/offers/:id/counter', auth, [param('id').isMongoId(), body('counterAmount').isFloat({ min:1 }), body('counterMessage').optional().trim().isLength({ max:1000 })], validate, asyncH(async (req,res) => {
  const offer=await Offer.findById(req.params.id);
  if (!offer) return res.status(404).json({ error:t('not_found') });
  if (!offer.seller.equals(req.user._id)) return res.status(403).json({ error:'Only seller can counter' });
  if (offer.status!=='pending') return res.status(400).json({ error:'Can only counter pending offers' });
  offer.counterAmount=Math.round(parseFloat(req.body.counterAmount));
  offer.counterMessage=req.body.counterMessage||'';
  offer.status='countered'; offer.respondedAt=new Date();
  await offer.save();
  sendNotification({ recipient:offer.buyer, sender:req.user._id, type:'offer_countered', title:'Offer Countered', message:`Counter of ₦${offer.counterAmount.toLocaleString()} received`, link:'/offers' }).catch(()=>{});
  io.to(`user:${offer.buyer}`).emit('offer:updated',offer);
  res.json(offer);
}));

router.put('/offers/:id/accept-counter', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const offer=await Offer.findById(req.params.id).populate('buyer','username email').populate('seller','username email');
  if (!offer) return res.status(404).json({ error:t('not_found') });
  if (!offer.buyer._id.equals(req.user._id)) return res.status(403).json({ error:'Only buyer can accept counter' });
  if (offer.status!=='countered' || !offer.counterAmount) return res.status(400).json({ error:'No counter to accept' });

  const counterAmount = offer.counterAmount;
  const session=await mongoose.startSession();
  let tx;
  try {
    await session.withTransaction(async () => {
      const user=await User.findById(req.user._id).session(session);
      if (user.availableBalance < counterAmount - offer.amount) throw new Error('Insufficient balance for counter amount');

      if (counterAmount !== offer.amount) {
        await walletMove({ session, userId:req.user._id, fromBucket:'reserved', toBucket:'available', amount:offer.amount, type:'unreserve', note:'Returning original reserved amount for counter acceptance' });
        await walletMove({ session, userId:req.user._id, fromBucket:'available', toBucket:'reserved', amount:counterAmount, type:'reserve', note:`Reserving counter amount ₦${counterAmount.toLocaleString()}` });
      }
      offer.status='accepted'; offer.amount=counterAmount; offer.respondedAt=new Date();
      await offer.save({ session });
      await Transaction.findByIdAndUpdate(offer.transactionId,{ amount:counterAmount },{ session });
    });
    tx=await Transaction.findById(offer.transactionId).lean();
    sendNotification({ recipient:offer.seller._id, sender:req.user._id, type:'offer_accepted', title:'Counter Accepted!', message:`Buyer accepted your counter of ₦${counterAmount.toLocaleString()}`, link:'/offers' }).catch(()=>{});
    io.to(`user:${offer.seller._id}`).emit('offer:updated',offer);
    res.json({ offer, transaction:tx });
  } finally { await session.endSession(); }
}));

router.put('/offers/:id/withdraw', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const offer=await Offer.findById(req.params.id);
  if (!offer) return res.status(404).json({ error:t('not_found') });
  if (!offer.buyer.equals(req.user._id)) return res.status(403).json({ error:'Only buyer can withdraw their offer' });
  if (!['pending','countered'].includes(offer.status)) return res.status(400).json({ error:`Cannot withdraw offer in status: ${offer.status}` });
  const session=await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      offer.status='withdrawn'; offer.respondedAt=new Date(); await offer.save({ session });

      await walletMove({ session, userId:offer.buyer, fromBucket:'reserved', toBucket:'available', amount:offer.amount, type:'unreserve', note:'Offer withdrawn by buyer', transactionId:offer.transactionId });
      if (offer.transactionId) {
        await Transaction.findByIdAndUpdate(offer.transactionId, { state:TX_STATES.CANCELLED, 'timestamps_state.CANCELLED':new Date() }, { session });
      }
    });
    sendNotification({ recipient:offer.seller, sender:req.user._id, type:'offer_withdrawn', title:'Offer Withdrawn', message:`${req.user.username} withdrew their offer`, link:'/offers' }).catch(()=>{});
    io.to(`user:${offer.seller}`).emit('offer:updated', offer);
    res.json(offer);
  } finally { await session.endSession(); }
}));

router.put('/offers/:id/reject', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const offer=await Offer.findById(req.params.id);
  if (!offer) return res.status(404).json({ error:t('not_found') });
  if (!offer.seller.equals(req.user._id)) return res.status(403).json({ error:'Only seller can reject' });
  if (!['pending','countered'].includes(offer.status)) return res.status(400).json({ error:'Cannot reject' });
  const session=await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      offer.status='rejected'; offer.respondedAt=new Date(); await offer.save({ session });
      await walletMove({ session, userId:offer.buyer, fromBucket:'reserved', toBucket:'available', amount:offer.amount, type:'unreserve', note:'Offer rejected', transactionId:offer.transactionId });
      if (offer.transactionId) await Transaction.findByIdAndUpdate(offer.transactionId,{ state:TX_STATES.CANCELLED,'timestamps_state.CANCELLED':new Date() },{ session });
    });
    sendNotification({ recipient:offer.buyer, sender:req.user._id, type:'offer_rejected', title:'Offer Rejected', message:'Your offer was rejected', link:'/offers' }).catch(()=>{});
    io.to(`user:${offer.buyer}`).emit('offer:updated',offer);
    res.json(offer);
  } finally { await session.endSession(); }
}));

router.put('/offers/:id/accept', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const offer=await Offer.findById(req.params.id).populate('buyer','username email').populate('seller','username email');
  if (!offer) return res.status(404).json({ error:t('not_found') });
  if (!offer.seller._id.equals(req.user._id)) return res.status(403).json({ error:'Only seller can accept' });
  if (!['pending','countered'].includes(offer.status)) return res.status(400).json({ error:'Cannot accept' });

  const listing = await Listing.findById(offer.listing).lean();

  const session=await mongoose.startSession();
  let tx;
  try {
    await session.withTransaction(async () => {
      const seller=await User.findById(offer.seller._id).session(session);
      const plan=getActivePlan(seller);

      const escrowFeePercent = isFoundingMemberActive(seller) ? 0 : plan.escrowFeePercent;

      await walletMove({ session, userId:offer.buyer._id, fromBucket:'reserved', toBucket:'escrow', amount:offer.amount, type:'escrow_fund', note:`Escrow for "${listing ? listing.title : 'item'}"`, transactionId:offer.transactionId });
      const now=new Date();
      const dispatchDeadline=new Date(now.getTime()+DISPATCH_WINDOW_DAYS*86400000);
      const escrowFeeAmount = Math.round(offer.amount * escrowFeePercent / 100);
      tx=await Transaction.findByIdAndUpdate(offer.transactionId,{
        state:TX_STATES.ESCROW_FUNDED, escrowAmount:offer.amount,
        escrowFeePercent, escrowFeeAmount,
        dispatchDeadlineAt:dispatchDeadline,
        autoReleaseAt:new Date(now.getTime()+AUTO_RELEASE_HOURS*3600000+DISPATCH_WINDOW_DAYS*86400000),
        'timestamps_state.ACCEPTED':now, 'timestamps_state.ESCROW_FUNDED':now,
      },{ new:true, session });
    });
    sendEmail(offer.buyer.email, emailTemplates.offerAccepted(offer.buyer.username, tx)).catch(()=>{});
    sendEmail(offer.seller.email, emailTemplates.newOrderReceived(offer.seller.username, tx, listing ? listing.title : tx.itemTitle)).catch(()=>{});
    sendNotification({ recipient:offer.buyer._id, sender:req.user._id, type:'offer_accepted', title:'Offer Accepted!', message:`₦${offer.amount.toLocaleString()} now in escrow`, link:`/transactions/${offer.transactionId||tx?._id||''}` }).catch(()=>{});
    sendNotification({ recipient:offer.seller._id, type:'system', title:'🛒 New Order – Dispatch Required!', message:`Offer accepted on "${tx.itemTitle}". Dispatch within 3 days to avoid auto-cancellation.`, link:`/transactions/${tx._id}` }).catch(()=>{});
    io.to(`user:${offer.buyer._id}`).emit('transaction:updated',tx);
    io.to(`user:${offer.seller._id}`).emit('transaction:updated',tx);

    res.json({ offer, transaction:tx });
  } finally { await session.endSession(); }
}));

router.post('/listings/:id/purchase', auth, requireAgreements, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const listing=await Listing.findById(req.params.id).populate('seller','username email activePlan planExpiresAt');
  if (!listing||listing.status!=='active') return res.status(404).json({ error:'Listing not available' });
  if (listing.seller._id.equals(req.user._id)) return res.status(400).json({ error:'Cannot buy own listing' });

  const amount=listing.price;
  const seller=await User.findById(listing.seller._id);
  const plan=getActivePlan(seller);

  const escrowFeePercent = isFoundingMemberActive(seller) ? 0 : plan.escrowFeePercent;
  const escrowFeeAmount  = Math.round(amount * escrowFeePercent / 100);

  const session=await mongoose.startSession();
  let tx;
  try {
    await session.withTransaction(async () => {
      const buyer=await User.findById(req.user._id).session(session);
      if (buyer.availableBalance < amount) throw new Error(`Insufficient balance. Need ₦${amount.toLocaleString()}`);

      const referral = await Referral.findOne({ refereeId:buyer._id, firstPurchaseRewardPaid:false }).session(session);
      const refereeDiscount = (!buyer.firstPurchaseDone && referral) ? Math.round(escrowFeeAmount * REFERRAL_REWARDS.referee_first_purchase_discount) : 0;

      const now=new Date();
      tx=await Transaction.create([{
        buyerId:buyer._id, sellerId:listing.seller._id, itemId:listing._id,
        itemTitle:listing.title, amount, escrowAmount:amount,
        escrowFeePercent, escrowFeeAmount,
        exchangeRateUsed:currencyConfig.rate,
        state:TX_STATES.ESCROW_FUNDED,
        refereeDiscount,
        dispatchDeadlineAt:new Date(now.getTime()+DISPATCH_WINDOW_DAYS*86400000),
        autoReleaseAt:new Date(now.getTime()+AUTO_RELEASE_HOURS*3600000),
        'timestamps_state.PENDING_OFFER':now,'timestamps_state.ACCEPTED':now,'timestamps_state.ESCROW_FUNDED':now,
      }],{ session });
      tx=tx[0];
      await walletMove({ session, userId:buyer._id, fromBucket:'available', toBucket:'escrow', amount, type:'escrow_fund', note:`Purchase: "${listing.title}"`, transactionId:tx._id });
      await Listing.findByIdAndUpdate(listing._id,{ status:'pending' },{ session });
    });

    processReferralFirstPurchase(await User.findById(req.user._id), tx._id).catch(()=>{});

    sendEmail(listing.seller.email, emailTemplates.newOrderReceived(listing.seller.username, tx, listing.title)).catch(()=>{});
    sendNotification({ recipient:listing.seller._id, type:'system', title:'🛒 New Order – Dispatch Required!', message:`"${listing.title}" was purchased. Dispatch within 3 days to avoid auto-cancellation.`, link:`/transactions/${tx._id}` }).catch(()=>{});
    io.to(`user:${listing.seller._id}`).emit('transaction:updated',tx);
    res.status(201).json({ transaction:tx });
  } finally { await session.endSession(); }
}));

router.get('/transactions', auth, asyncH(async (req,res) => {
  const uid=req.user._id;
  const { skip,limit,page }=paginate(req);
  const filter={ $or:[{ buyerId:uid },{ sellerId:uid }] };
  if (req.query.state) filter.state=req.query.state;
  const [transactions,total]=await Promise.all([
    Transaction.find(filter).populate('buyerId','username avatar').populate('sellerId','username avatar').populate('itemId','title images price').sort({ createdAt:-1 }).skip(skip).limit(limit).lean(),
    Transaction.countDocuments(filter),
  ]);

  const sellerAlertCount = await Transaction.countDocuments({ sellerId:uid, state:'ESCROW_FUNDED' });
  res.json({ transactions:transactions.map(tx=>({ ...tx, usdAmount:convertNGNtoUSD(tx.amount) })), total, page, pages:Math.ceil(total/limit), rate:currencyConfig.rate, sellerAlertCount });
}));

router.get('/transactions/:id', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const tx=await Transaction.findById(req.params.id)
    .populate('buyerId','username avatar email')
    .populate('sellerId','username avatar email')
    .populate('itemId','title images price description')
    .populate('offerId','amount message counterAmount')
    .populate('disputeId').lean();
  if (!tx) return res.status(404).json({ error:t('not_found') });
  const uid=req.user._id.toString();
  const isParty=tx.buyerId._id.toString()===uid||tx.sellerId._id.toString()===uid||req.user.role==='admin';
  if (!isParty) return res.status(403).json({ error:t('forbidden') });
  res.json({ ...tx, usdAmount:convertNGNtoUSD(tx.amount), rate:currencyConfig.rate });
}));

router.get('/transactions/:id/contact', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const tx = await Transaction.findById(req.params.id)
    .populate('buyerId',  'username avatar phone whatsapp lastSeen')
    .populate('sellerId', 'username avatar phone whatsapp lastSeen');
  if (!tx) return res.status(404).json({ error: 'Transaction not found' });

  const uid = String(req.user._id);
  const buyerId  = String(tx.buyerId?._id  || tx.buyerId  || '');
  const sellerId = String(tx.sellerId?._id || tx.sellerId || '');
  const isBuyer  = uid === buyerId;
  const isSeller = uid === sellerId;
  if (!isBuyer && !isSeller) return res.status(403).json({ error: 'Not a party to this transaction' });

  const ALLOWED_STATES = ['ESCROW_FUNDED','SHIPPED','DELIVERED','RECEIVED_CONFIRMED','DISPUTED'];
  if (!ALLOWED_STATES.includes(tx.state)) return res.status(403).json({ error: 'Contact details only available once payment is in escrow' });

  const listing = tx.itemId ? await Listing.findById(tx.itemId).select('contactPhone').lean() : null;
  const listingPhone = listing?.contactPhone || null;

  const sellerUser = tx.sellerId;
  const buyerUser  = tx.buyerId;

  const sellerContactPayload = {
    username: sellerUser?.username,
    avatar:   sellerUser?.avatar,

    phone:    listingPhone || sellerUser?.phone || null,
    whatsapp: listingPhone || sellerUser?.whatsapp || null,
    isOnline: !!userSockets?.has(String(sellerUser?._id)),
    lastSeen: sellerUser?.lastSeen || null,
  };

  const buyerContactPayload = {
    username: buyerUser?.username,
    avatar:   buyerUser?.avatar,
    phone:    buyerUser?.phone    || null,
    whatsapp: buyerUser?.whatsapp || null,
    isOnline: !!userSockets?.has(String(buyerUser?._id)),
    lastSeen: buyerUser?.lastSeen || null,
  };

  res.json({
    _id:          tx._id,
    itemTitle:    tx.itemTitle,
    viewerRole:   isBuyer ? 'buyer' : 'seller',
    sellerContact: isBuyer  ? sellerContactPayload : undefined,
    buyerContact:  isSeller ? buyerContactPayload  : undefined,
    state:         tx.state,
    exchangeRateUsed: tx.exchangeRateUsed,
    rate:          currencyConfig.rate,
  });
}));

router.post('/transactions/:id/dispatch', auth, upload.single('productPicture'), [
  param('id').isMongoId(),
  body('dispatchType').isIn(['international','local']),

  body('trackingNumber').optional().trim().isLength({ max:100 }),
  body('shippingCarrier').optional().trim().isLength({ max:50 }),

  body('senderLocation').optional().trim().isLength({ max:200 }),
  body('transportType').optional().isIn(['bus','car','bike','van','truck']),
  body('sendTime').optional(),
  body('estimatedArrival').optional(),
  body('driverPhone').optional().trim().isLength({ max:20 }),
  body('dispatchNotes').optional().trim().isLength({ max:1000 }),
], validate, asyncH(async (req,res) => {
  const tx=await Transaction.findById(req.params.id).populate('buyerId','username email').populate('sellerId','username email');
  if (!tx) return res.status(404).json({ error:t('not_found') });
  if (!tx.sellerId._id.equals(req.user._id)) return res.status(403).json({ error:'Only seller can dispatch' });
  if (tx.state!==TX_STATES.ESCROW_FUNDED) return res.status(400).json({ error:`Cannot dispatch in state ${tx.state}` });

  const dtype = req.body.dispatchType;
  const now = new Date();

  if (dtype === 'international') {

    if (!req.body.shippingCarrier) return res.status(400).json({ error:'Shipping platform (carrier) is required for international dispatch' });
    if (!req.body.trackingNumber)  return res.status(400).json({ error:'Tracking number is required for international dispatch' });
    tx.shippingCarrier = req.body.shippingCarrier;
    tx.trackingNumber  = req.body.trackingNumber;
  } else {

    if (!req.body.senderLocation)  return res.status(400).json({ error:'Sender location is required for local dispatch' });
    if (!req.body.transportType)   return res.status(400).json({ error:'Transportation type is required for local dispatch' });
    if (!req.body.sendTime)        return res.status(400).json({ error:'Send time is required for local dispatch' });
    if (!req.body.estimatedArrival)return res.status(400).json({ error:'Estimated arrival time is required for local dispatch' });
    if (!req.body.driverPhone)     return res.status(400).json({ error:'Driver phone number is required for local dispatch' });
    tx.senderLocation   = req.body.senderLocation;
    tx.transportType    = req.body.transportType;
    tx.sendTime         = new Date(req.body.sendTime);
    tx.estimatedArrival = new Date(req.body.estimatedArrival);
    tx.driverPhone      = req.body.driverPhone;
    if (req.file) tx.productPictureUrl = `/uploads/${req.file.filename}`;
  }

  tx.dispatchType  = dtype;
  tx.dispatchNotes = req.body.dispatchNotes || '';
  tx.state         = TX_STATES.SHIPPED;
  tx.dispatchedAt  = now;
  tx.timestamps_state.SHIPPED = now;
  tx.autoReleaseAt = new Date(now.getTime()+AUTO_RELEASE_HOURS*3600000);
  await tx.save();

  const notifMsg = dtype === 'international'
    ? `Tracking: ${tx.trackingNumber} via ${tx.shippingCarrier}`
    : `Local dispatch via ${tx.transportType}. ETA: ${tx.estimatedArrival ? new Date(tx.estimatedArrival).toLocaleString() : 'TBD'}`;

  sendEmail(tx.buyerId.email, emailTemplates.itemShipped(tx.buyerId.username, tx)).catch(()=>{});
  sendNotification({ recipient:tx.buyerId._id, type:'system', title:'Item Dispatched! 📦', message:notifMsg, link:`/transactions/${tx._id}` }).catch(()=>{});
  io.to(`user:${tx.buyerId._id}`).emit('transaction:updated',tx);
  io.to(`user:${tx.sellerId._id}`).emit('transaction:updated',tx);
  res.json(tx);
}));

router.post('/transactions/:id/delivered', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const tx=await Transaction.findById(req.params.id).populate('buyerId','username email').populate('sellerId','username email');
  if (!tx) return res.status(404).json({ error:t('not_found') });
  if (!tx.buyerId._id.equals(req.user._id) && req.user.role!=='admin') return res.status(403).json({ error:'Only buyer or admin' });
  if (tx.state!==TX_STATES.SHIPPED) return res.status(400).json({ error:`Cannot mark delivered in state ${tx.state}` });
  const now=new Date();
  tx.state=TX_STATES.DELIVERED; tx.timestamps_state.DELIVERED=now;
  tx.autoReleaseAt=new Date(now.getTime()+AUTO_RELEASE_HOURS*3600000);
  await tx.save();
  sendNotification({ recipient:tx.buyerId._id, type:'system', title:'Item Delivered', message:'Confirm receipt or payment auto-releases in 48h', link:`/transactions/${tx._id}` }).catch(()=>{});
  io.to(`user:${tx.buyerId._id}`).emit('transaction:updated',tx);
  io.to(`user:${tx.sellerId._id}`).emit('transaction:updated',tx);
  res.json(tx);
}));

router.post('/transactions/:id/confirm', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const tx=await Transaction.findById(req.params.id).populate('buyerId','username email').populate('sellerId','username email');
  if (!tx) return res.status(404).json({ error:t('not_found') });
  if (!tx.buyerId._id.equals(req.user._id)) return res.status(403).json({ error:'Only buyer can confirm' });
  if (![TX_STATES.DELIVERED,TX_STATES.SHIPPED].includes(tx.state)) return res.status(400).json({ error:`Cannot confirm in state ${tx.state}` });

  const session=await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      const seller=await User.findById(tx.sellerId._id).session(session);
      const plan=getActivePlan(seller);
      const feePercent = tx.escrowFeePercent || plan.escrowFeePercent;
      const fee = calculateEscrowFee(tx.escrowAmount, feePercent, seller);
      const sellerReceives = tx.escrowAmount - fee;
      const now=new Date();
      tx.state=TX_STATES.COMPLETED; tx.timestamps_state.COMPLETED=now; tx.reviewUnlocked=true;
      await tx.save({ session });
      closeConvForTx(tx._id, 'transaction_completed').catch(()=>{});

      await walletMove({ session, userId:tx.buyerId._id, fromBucket:'escrow', toBucket:'external', amount:tx.escrowAmount, type:'escrow_release', note:`Escrow released to seller — fee: ₦${fee.toLocaleString()} (${feePercent}%)`, transactionId:tx._id });
      await walletMove({ session, userId:tx.sellerId._id, fromBucket:'external', toBucket:'withdrawable', amount:sellerReceives, type:'escrow_release', note:`Payment received — fee: ₦${fee.toLocaleString()} (${feePercent}%)`, transactionId:tx._id, fee });

      await User.findByIdAndUpdate(tx.sellerId._id, { $inc:{ totalSales:1 } }, { session });
      await User.findByIdAndUpdate(tx.buyerId._id,  { $inc:{ totalPurchases:1 } }, { session });
      await Listing.findByIdAndUpdate(tx.itemId,{ status:'sold' },{ session });
    });
    sendEmail(tx.sellerId.email, emailTemplates.paymentReleased(tx.sellerId.username, tx)).catch(()=>{});
    sendNotification({ recipient:tx.sellerId._id, type:'system', title:'Payment Released ✅', message:`₦${tx.escrowAmount.toLocaleString()} released to your wallet`, link:'/wallet' }).catch(()=>{});
    io.to(`user:${tx.buyerId._id}`).emit('transaction:updated',tx);
    io.to(`user:${tx.sellerId._id}`).emit('transaction:updated',tx);
    res.json(tx);
  } finally { await session.endSession(); }
}));

router.post('/transactions/:id/cancel', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const tx=await Transaction.findById(req.params.id);
  if (!tx) return res.status(404).json({ error:t('not_found') });
  const uid=req.user._id.toString();
  const isBuyer=tx.buyerId.toString()===uid;
  const isAdmin=req.user.role==='admin';
  if (!isBuyer&&!isAdmin) return res.status(403).json({ error:'Only buyer or admin can cancel' });
  if (![TX_STATES.PENDING_OFFER,TX_STATES.ACCEPTED,TX_STATES.ESCROW_FUNDED].includes(tx.state)) return res.status(400).json({ error:`Cannot cancel in state ${tx.state}` });

  if (tx.state===TX_STATES.ESCROW_FUNDED && !isAdmin) {
    const deadline=tx.dispatchDeadlineAt || (tx.timestamps_state.ESCROW_FUNDED ? new Date(tx.timestamps_state.ESCROW_FUNDED.getTime()+DISPATCH_WINDOW_DAYS*86400000) : new Date(0));
    if (new Date()<deadline) return res.status(400).json({ error:`Dispatch window not expired. Seller has until ${deadline.toISOString()}` });
  }

  const session=await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      const now=new Date();
      const originalState=tx.state;
      tx.state=TX_STATES.CANCELLED; tx.timestamps_state.CANCELLED=now; await tx.save({ session });
      closeConvForTx(tx._id, 'transaction_cancelled').catch(()=>{});
      if (tx.escrowAmount>0) await walletMove({ session, userId:tx.buyerId, fromBucket:'escrow', toBucket:'available', amount:tx.escrowAmount, type:'escrow_refund', note:'Transaction cancelled', transactionId:tx._id });
      else if (originalState===TX_STATES.PENDING_OFFER||originalState===TX_STATES.ACCEPTED) {
        const offer=await Offer.findById(tx.offerId).session(session);
        if (offer&&offer.amount>0) await walletMove({ session, userId:tx.buyerId, fromBucket:'reserved', toBucket:'available', amount:offer.amount, type:'unreserve', note:'Offer cancelled', transactionId:tx._id });
      }
      await Listing.findByIdAndUpdate(tx.itemId,{ status:'active' },{ session });
      if (tx.offerId) await Offer.findByIdAndUpdate(tx.offerId,{ status:'rejected' },{ session });
    });
    io.to(`user:${tx.buyerId}`).emit('transaction:updated',tx);
    io.to(`user:${tx.sellerId}`).emit('transaction:updated',tx);
    res.json(tx);
  } finally { await session.endSession(); }
}));

router.post('/disputes', auth, uploadEvidence.array('evidence',5), [
  body('transactionId').isMongoId(),
  body('issueType').isIn(['not_received','damaged_item','wrong_item','other']),
  body('reason').trim().isLength({ min:20, max:2000 }),
], validate, asyncH(async (req,res) => {
  const tx=await Transaction.findById(req.body.transactionId).populate('buyerId','username email').populate('sellerId','username email');
  if (!tx) return res.status(404).json({ error:'Transaction not found' });
  if (!tx.buyerId._id.equals(req.user._id)) return res.status(403).json({ error:'Only buyer can open dispute' });
  if (![TX_STATES.ESCROW_FUNDED,TX_STATES.SHIPPED,TX_STATES.DELIVERED].includes(tx.state)) return res.status(400).json({ error:`Cannot dispute in state ${tx.state}` });
  if (tx.disputeId) return res.status(409).json({ error:'Dispute already exists' });

  const evidenceImages=(req.files||[]).map(f=>`/uploads/${f.filename}`);
  const session=await mongoose.startSession();
  let dispute;
  try {
    await session.withTransaction(async () => {
      dispute=await Dispute.create([{
        transactionId:tx._id, buyerId:tx.buyerId._id, sellerId:tx.sellerId._id,
        initiator:tx.buyerId._id, respondent:tx.sellerId._id,
        listing:tx.itemId, offer:tx.offerId,
        issueType:req.body.issueType, reason:req.body.reason, evidenceImages,
        responseDeadlineAt:new Date(Date.now()+3*86400000),
      }],{ session });
      dispute=dispute[0];
      tx.state=TX_STATES.DISPUTED; tx.timestamps_state.DISPUTED=new Date(); tx.disputeId=dispute._id;
      await tx.save({ session });
    });
    sendEmail(tx.sellerId.email, emailTemplates.disputeOpened(tx.sellerId.username, tx,'seller')).catch(()=>{});
    sendNotification({ recipient:tx.sellerId._id, type:'dispute', title:'Dispute Opened', message:'Respond within 3 days.', link:`/disputes/${dispute._id}` }).catch(()=>{});
    io.to(`user:${tx.buyerId._id}`).emit('transaction:updated',tx);
    io.to(`user:${tx.sellerId._id}`).emit('transaction:updated',tx);
    res.status(201).json({ dispute, transaction:tx });
  } finally { await session.endSession(); }
}));

router.get('/disputes', auth, asyncH(async (req,res) => {
  const uid=req.user._id;
  const disputes=await Dispute.find({ $or:[{ buyerId:uid },{ sellerId:uid }] })
    .populate('transactionId','amount state itemTitle').populate('buyerId','username avatar').populate('sellerId','username avatar')
    .sort({ createdAt:-1 }).lean();
  res.json(disputes);
}));

router.get('/disputes/:id', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const d=await Dispute.findById(req.params.id).populate('transactionId').populate('buyerId','username avatar email').populate('sellerId','username avatar email').lean();
  if (!d) return res.status(404).json({ error:t('not_found') });
  const uid=req.user._id.toString();
  if (d.buyerId._id.toString()!==uid&&d.sellerId._id.toString()!==uid&&req.user.role!=='admin') return res.status(403).json({ error:t('forbidden') });
  res.json(d);
}));

router.put('/disputes/:id/respond', auth, [param('id').isMongoId(), body('sellerResponse').trim().isLength({ min:10, max:2000 })], validate, asyncH(async (req,res) => {
  const d=await Dispute.findById(req.params.id);
  if (!d) return res.status(404).json({ error:t('not_found') });
  if (!d.sellerId.equals(req.user._id)) return res.status(403).json({ error:'Only seller can respond' });
  if (!['OPEN','ESCALATED'].includes(d.status)) return res.status(400).json({ error:'Cannot respond' });
  d.sellerResponse=req.body.sellerResponse; d.sellerRespondedAt=new Date(); d.status='RESPONDED'; await d.save();
  sendNotification({ recipient:d.buyerId, type:'dispute', title:'Seller Responded', message:'Seller responded to your dispute.', link:`/disputes/${d._id}` }).catch(()=>{});
  res.json(d);
}));

router.get('/users/me/export', auth, asyncH(async (req,res) => {
  const [user, listings, transactions, offers, reviews] = await Promise.all([
    User.findById(req.user._id)
      .select('-password -refreshTokens -twoFASecret -twoFABackupCodes -emailVerifyToken -blockedUsers')
      .lean(),
    Listing.find({ seller:req.user._id }).select('title price category status createdAt').lean(),
    Transaction.find({ $or:[{ buyerId:req.user._id },{ sellerId:req.user._id }] })
      .select('amount state escrowFeePercent createdAt').lean(),
    Offer.find({ $or:[{ buyer:req.user._id },{ seller:req.user._id }] })
      .select('amount status createdAt').lean(),
    Review.find({ reviewer:req.user._id }).select('rating comment createdAt').lean(),
  ]);
  res.json({
    exportedAt: new Date().toISOString(),
    version: '1.0',
    note: 'This export contains all personal data associated with your RawFlip account.',
    account: user,
    listings,
    transactions,
    offers,
    reviews,
  });
}));

router.get('/users/:id', asyncH(async (req,res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ error:'Invalid ID' });
  const u=await User.findById(req.params.id).select('-password -refreshTokens -twoFASecret -twoFABackupCodes -emailVerifyToken -blockedUsers -registrationIp').lean();
  if (!u||!u.isActive) return res.status(404).json({ error:t('not_found') });
  const plan=getActivePlan(u);
  const listings=await Listing.find({ seller:u._id, status:'active' }).limit(12).sort({ searchPriority:-1,createdAt:-1 }).lean();
  const reviews=await Review.find({ reviewee:u._id }).populate('reviewer','username avatar').sort({ createdAt:-1 }).limit(10).lean();
  res.json({ user:{ ...u, activePlanDetails:plan, isEarlyAdopter:u.isEarlyAdopter||false, isEarlyAdopterActive:isEarlyAdopterActive(u), earlyAdopterNumber:u.earlyAdopterNumber||null }, listings:listings.map(l=>({ ...l,usdPrice:convertNGNtoUSD(l.price) })), reviews });
}));

router.put('/users/me', auth, upload.single('avatar'), asyncH(async (req,res) => {

  const phoneRe = /^\+234[0-9]{10}$/;
  if (req.body.phone && !phoneRe.test(req.body.phone)) {
    return res.status(400).json({ error:'Phone must be in +234XXXXXXXXXX format (11 digits after +234)' });
  }
  if (req.body.whatsapp && !phoneRe.test(req.body.whatsapp)) {
    return res.status(400).json({ error:'WhatsApp must be in +234XXXXXXXXXX format (11 digits after +234)' });
  }
  const allowed=['bio','location','phone','whatsapp'];
  const updates={};
  allowed.forEach(f=>{ if(req.body[f]!==undefined)updates[f]=req.body[f]; });
  if (req.file) updates.avatar=`/uploads/${req.file.filename}`;
  const user=await User.findByIdAndUpdate(req.user._id,updates,{ new:true }).select('-password -refreshTokens');
  res.json(user);
}));

router.get('/users/me/wishlist', auth, asyncH(async (req,res) => {
  const user=await User.findById(req.user._id).populate({ path:'wishlist', populate:{ path:'seller',select:'username avatar' } });
  res.json({ wishlist:(user.wishlist||[]).map(l=>({ ...l.toObject(),usdPrice:convertNGNtoUSD(l.price) })) });
}));

router.post('/users/:id/follow', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  if (req.params.id===req.user._id.toString()) return res.status(400).json({ error:'Cannot follow yourself' });
  const target=await User.findById(req.params.id);
  if (!target) return res.status(404).json({ error:t('not_found') });
  const uid=req.user._id;
  const isFollowing=target.followers.some(f=>f.equals(uid));
  if (isFollowing) { target.followers.pull(uid); await User.findByIdAndUpdate(uid,{ $pull:{ following:target._id } }); }
  else { target.followers.push(uid); await User.findByIdAndUpdate(uid,{ $push:{ following:target._id } }); sendNotification({ recipient:target._id, sender:uid, type:'follow', title:'New Follower', message:`${req.user.username} started following you`, link:`/profile/${uid}` }).catch(()=>{}); }
  await target.save();
  res.json({ following:!isFollowing, followers:target.followers.length });
}));

router.get('/posts', asyncH(async (req,res) => {
  const { skip,limit,page }=paginate(req);
  const filter={};
  if (req.query.type) filter.type=req.query.type;
  if (req.query.q) filter.$text={ $search:req.query.q };
  const [posts,total]=await Promise.all([Post.find(filter).populate('author','username avatar').skip(skip).limit(limit).sort({ isPinned:-1,createdAt:-1 }).lean(), Post.countDocuments(filter)]);
  res.json({ posts, total, page, pages:Math.ceil(total/limit) });
}));

router.get('/posts/:id', asyncH(async (req,res) => {
  const p=await Post.findByIdAndUpdate(req.params.id,{ $inc:{ views:1 } },{ new:true }).populate('author','username avatar').lean();
  if (!p) return res.status(404).json({ error:t('not_found') });
  res.json(p);
}));

router.post('/posts', auth, [body('title').trim().isLength({ min:5,max:200 }), body('content').trim().isLength({ min:10,max:10000 }), body('type').isIn(['discussion','question','tip','announcement'])], validate, asyncH(async (req,res) => {
  if (req.body.type==='announcement'&&req.user.role!=='admin') return res.status(403).json({ error:'Only admins can post announcements' });
  const p=await Post.create({ author:req.user._id, title:req.body.title, content:req.body.content, type:req.body.type, tags:(req.body.tags||'').split(',').map(t=>t.trim()).filter(Boolean) });
  res.status(201).json(p);
}));

router.put('/posts/:id', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const p=await Post.findById(req.params.id);
  if (!p) return res.status(404).json({ error:t('not_found') });
  if (!p.author.equals(req.user._id)&&req.user.role!=='admin') return res.status(403).json({ error:t('forbidden') });
  const f=['title','content','type','tags'];
  f.forEach(k=>{ if(req.body[k]!==undefined)p[k]=req.body[k]; });
  await p.save(); res.json(p);
}));

router.delete('/posts/:id', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const p=await Post.findById(req.params.id);
  if (!p) return res.status(404).json({ error:t('not_found') });
  if (!p.author.equals(req.user._id)&&req.user.role!=='admin') return res.status(403).json({ error:t('forbidden') });
  await p.deleteOne(); res.json({ ok:true });
}));

router.post('/posts/:id/like', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const p=await Post.findById(req.params.id);
  if (!p) return res.status(404).json({ error:t('not_found') });
  const i=p.likes.findIndex(l=>l.equals(req.user._id));
  i>=0?p.likes.splice(i,1):p.likes.push(req.user._id);
  await p.save(); res.json({ liked:i<0, likes:p.likes.length });
}));

router.post('/posts/:id/comments', auth, [
  param('id').isMongoId(),
  body('content').trim().isLength({ min:1, max:2000 }),
], validate, asyncH(async (req,res) => {
  const post = await Post.findById(req.params.id);
  if (!post) return res.status(404).json({ error:t('not_found') });
  const comment = await Comment.create({ post:req.params.id, author:req.user._id, content:req.body.content });
  await Post.findByIdAndUpdate(req.params.id, { $inc:{ commentCount:1 } });
  const populated = await Comment.findById(comment._id).populate('author','username avatar').lean();
  sendNotification({ recipient:post.author, sender:req.user._id, type:'system', title:'New comment on your post', message:req.body.content.slice(0,80), link:'/posts' }).catch(()=>{});
  res.status(201).json(populated);
}));

router.get('/posts/:id/comments', [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const { skip,limit,page } = paginate(req);
  const [comments,total] = await Promise.all([
    Comment.find({ post:req.params.id }).populate('author','username avatar').sort({ createdAt:1 }).skip(skip).limit(limit).lean(),
    Comment.countDocuments({ post:req.params.id }),
  ]);
  res.json({ comments, total, page, pages:Math.ceil(total/limit) });
}));

router.get('/tasks', auth, asyncH(async (req,res) => {
  const filter={ user:req.user._id };
  if (req.query.status) filter.status=req.query.status;
  const tasks=await Task.find(filter).sort({ createdAt:-1 });
  res.json(tasks);
}));

router.post('/tasks', auth, [body('title').trim().isLength({ min:1,max:200 })], validate, asyncH(async (req,res) => {
  const t=await Task.create({ user:req.user._id, title:req.body.title, description:req.body.description||'', status:req.body.status||'todo', priority:req.body.priority||'medium', dueDate:req.body.dueDate||null, tags:req.body.tags||[] });
  res.status(201).json(t);
}));

router.put('/tasks/:id', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const task=await Task.findOne({ _id:req.params.id, user:req.user._id });
  if (!task) return res.status(404).json({ error:t('not_found') });
  const f=['title','description','status','priority','dueDate','tags'];
  f.forEach(k=>{ if(req.body[k]!==undefined)task[k]=req.body[k]; });
  await task.save(); res.json(task);
}));

router.delete('/tasks/:id', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  await Task.findOneAndDelete({ _id:req.params.id, user:req.user._id }); res.json({ ok:true });
}));

router.get('/notifications', auth, asyncH(async (req,res) => {
  const { skip,limit,page }=paginate(req);
  const [notifications,total,unread]=await Promise.all([
    Notification.find({ recipient:req.user._id }).skip(skip).limit(limit).sort({ createdAt:-1 }).populate('sender','username avatar').lean(),
    Notification.countDocuments({ recipient:req.user._id }),
    Notification.countDocuments({ recipient:req.user._id, read:false }),
  ]);
  res.json({ notifications, total, unread, page, pages:Math.ceil(total/limit) });
}));

router.put('/notifications/:id/read', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  await Notification.findOneAndUpdate({ _id:req.params.id, recipient:req.user._id },{ read:true });
  res.json({ ok:true });
}));

router.put('/notifications/read-all', auth, asyncH(async (req,res) => {
  await Notification.updateMany({ recipient:req.user._id, read:false },{ $set:{ read:true } });
  res.json({ ok:true });
}));

router.get('/users/check-username', asyncH(async (req,res) => {
  const { username } = req.query;
  if (!username || username.length < 3) return res.status(400).json({ error: 'Username too short' });
  const exists = await User.findOne({ username: username.trim().toLowerCase() }).lean();
  res.json({ available: !exists });
}));

router.post('/auth/sessions/revoke', auth, asyncH(async (req,res) => {
  const { fingerprint } = req.body;
  if (!fingerprint) return res.status(400).json({ error: 'fingerprint required' });
  await User.findByIdAndUpdate(req.user._id, { $pull: { loginHistory: { fingerprint } } });
  res.json({ ok: true });
}));

router.post('/auth/sessions/revoke-all', auth, asyncH(async (req,res) => {
  const currentFp = fingerprintDevice(req);
  await User.findByIdAndUpdate(req.user._id, {
    $set: { loginHistory: (await User.findById(req.user._id).select('loginHistory').lean())
      .loginHistory.filter(h => h.fingerprint === currentFp) }
  });

  // Keep only the current session's refresh token so this device stays logged in
  const currentRefresh = req.cookies?.rf_refresh;
  await User.findByIdAndUpdate(req.user._id, {
    refreshTokens: currentRefresh ? [currentRefresh] : []
  });
  res.json({ ok: true });
}));

router.post('/reviews', auth, [
  body('revieweeId').isMongoId(), body('rating').isInt({ min:1,max:5 }),
  body('comment').optional().trim().isLength({ max:2000 }),
  body('transactionId').optional().isMongoId(),
], validate, asyncH(async (req,res) => {
  if (req.body.revieweeId===req.user._id.toString()) return res.status(400).json({ error:'Cannot review yourself' });
  if (req.body.transactionId) {
    const tx=await Transaction.findById(req.body.transactionId);
    if (!tx||tx.state!==TX_STATES.COMPLETED) return res.status(400).json({ error:'Transaction not completed' });
    if (!tx.buyerId.equals(req.user._id)) return res.status(403).json({ error:'Only buyer can review' });
    const existing=await Review.findOne({ reviewer:req.user._id, transactionId:req.body.transactionId });
    if (existing) return res.status(409).json({ error:'Review already submitted' });
  }
  const review=await Review.create({ reviewer:req.user._id, reviewee:req.body.revieweeId, listing:req.body.listingId||null, transactionId:req.body.transactionId||null, rating:req.body.rating, comment:req.body.comment||'' });
  const _revieweeId=new mongoose.Types.ObjectId(req.body.revieweeId);
  const agg=await Review.aggregate([{ $match:{ reviewee:_revieweeId } },{ $group:{ _id:null, avg:{ $avg:'$rating' }, count:{ $sum:1 } } }]);
  if (agg[0]) await User.findByIdAndUpdate(req.body.revieweeId,{ rating:Math.round(agg[0].avg*10)/10, reviewCount:agg[0].count });
  sendNotification({ recipient:req.body.revieweeId, sender:req.user._id, type:'review', title:'New Review!', message:`${req.user.username} left you a ${req.body.rating}-star review`, link:`/profile/${req.body.revieweeId}` }).catch(()=>{});
  res.status(201).json(review);
}));

router.get('/reviews/:userId', asyncH(async (req,res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.userId)) return res.status(400).json({ error:'Invalid ID' });
  const reviews=await Review.find({ reviewee:req.params.userId }).populate('reviewer','username avatar').sort({ createdAt:-1 }).limit(20).lean();
  res.json(reviews);
}));

router.get('/user/analytics', auth, asyncH(async (req,res) => {

  const callerPlan = getActivePlan(req.user);
  const hasAnalyticsAccess = callerPlan.id === 'pro' || callerPlan.id === 'founding_member' || callerPlan.id === 'legacy_pro';
  if (!hasAnalyticsAccess) {
    return res.status(403).json({ error:'pro_required', message:'Analytics is available on the Pro plan. Upgrade to access.' });
  }
  const uid = req.user._id;
  const now = new Date();
  const accountAge = Math.floor((now - req.user.createdAt) / (1000*60*60*24));
  const [listingCount, offerCount, notifCount, unreadNotifCount, messageCount, reviewCount,
    wishlistCount, taskStats, listingsByMonth, txCount, loginHistory] = await Promise.all([
    Listing.countDocuments({ seller:uid }),
    Offer.countDocuments({ $or:[{ buyer:uid },{ seller:uid }] }),
    Notification.countDocuments({ recipient:uid }),
    Notification.countDocuments({ recipient:uid, read:false }),
    Review.countDocuments({ reviewee:uid }),
    User.findById(uid).select('wishlist').then(u=>u?.wishlist?.length||0),
    Task.aggregate([{ $match:{ user:uid } },{ $group:{ _id:'$status', count:{ $sum:1 } } }]),
    Listing.aggregate([
      { $match:{ seller:uid } },
      { $group:{ _id:{ $dateToString:{ format:'%Y-%m', date:'$createdAt' } }, count:{ $sum:1 }, revenue:{ $sum:'$price' } } },
      { $sort:{ _id:1 } }, { $limit:12 },
    ]),
    Transaction.countDocuments({ $or:[{ buyerId:uid },{ sellerId:uid }] }),
    User.findById(uid).select('loginHistory loginCount lastLoginAt').lean(),
  ]);
  const tasks = Object.fromEntries(taskStats.map(s=>[s._id, s.count]));
  res.json({
    accountAge, loginCount:loginHistory?.loginCount||0, lastLoginAt:loginHistory?.lastLoginAt,
    loginHistory:(loginHistory?.loginHistory||[]).slice(-5).reverse(),
    listings:listingCount, offers:offerCount, reviews:reviewCount,
    wishlistItems:wishlistCount, notifications:{ total:notifCount, unread:unreadNotifCount },
    sales:req.user.totalSales||0, purchases:req.user.totalPurchases||0,
    availableBalance:req.user.availableBalance||0, reservedBalance:req.user.reservedBalance||0,
    escrowBalance:req.user.escrowBalance||0, withdrawableBalance:req.user.withdrawableBalance||0,
    earningsBalance:req.user.earningsBalance||0,
    transactions:txCount, tasks, listingsByMonth, rating:req.user.rating||0, rate:currencyConfig.rate,
  });
}));

router.post('/reports', auth, [body('targetType').isIn(['listing','user','post','transaction']), body('targetId').isMongoId(), body('reason').trim().isLength({ min:10,max:1000 })], validate, asyncH(async (req,res) => {
  const report=await Report.create({ reporter:req.user._id, targetType:req.body.targetType, targetId:req.body.targetId, reason:req.body.reason });
  res.status(201).json(report);
}));

router.get('/search', searchLimiter, asyncH(async (req,res) => {
  const q=req.query.q?.trim()||'';
  if (!q) return res.json({ listings:[], users:[], posts:[] });
  const re=new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'i');
  const [listings,users,posts]=await Promise.all([
    Listing.find({ status:'active', $or:[{ title:re },{ description:re },{ tags:re }] }).select('title price images category condition seller').populate('seller','username isActive').limit(12).sort({ searchPriority:-1 }).lean().then(ls=>ls.filter(l=>l.seller&&l.seller.isActive!==false).slice(0,8)),
    User.find({ isActive:true, $or:[{ username:re },{ bio:re }] }).select('username avatar rating reviewCount isVerified activePlan').limit(5).lean(),
    Post.find({ $or:[{ title:re },{ content:re }] }).select('title type createdAt').populate('author','username').limit(5).lean(),
  ]);
  res.json({ listings:listings.map(l=>({ ...l,usdPrice:convertNGNtoUSD(l.price) })), users, posts });
}));

router.get('/admin/stats', auth, adminOnly, asyncH(async (req,res) => {
  const [users,listings,txs,activeDisputes,pendingDeposits,pendingWithdrawals,activeSubs]=await Promise.all([
    User.countDocuments(),
    Listing.countDocuments({ status:'active' }),
    Transaction.aggregate([{ $group:{ _id:'$state', count:{ $sum:1 }, total:{ $sum:'$amount' } } }]),
    Dispute.countDocuments({ status:{ $in:['OPEN','ESCALATED'] } }),
    WalletTx.countDocuments({ type:'deposit', status:{ $in:['pending','proof_submitted'] } }),
    WalletTx.countDocuments({ type:'withdrawal', status:'pending' }),
    Subscription.countDocuments({ status:'active' }),
  ]);
  const walletTotals=await User.aggregate([{ $group:{ _id:null, totalAvailable:{ $sum:'$availableBalance' }, totalReserved:{ $sum:'$reservedBalance' }, totalEscrow:{ $sum:'$escrowBalance' }, totalWithdrawable:{ $sum:'$withdrawableBalance' }, totalEarnings:{ $sum:'$earningsBalance' } } }]);
  res.json({ users, listings, txs, activeDisputes, pendingDeposits, pendingWithdrawals, activeSubs, walletTotals:walletTotals[0]||{}, rate:currencyConfig.rate });
}));

router.get('/admin/transactions', auth, adminOnly, asyncH(async (req,res) => {
  const { skip,limit,page }=paginate(req);
  const filter={};
  if (req.query.state) filter.state=req.query.state;
  const [txs,total]=await Promise.all([
    Transaction.find(filter).populate('buyerId','username email').populate('sellerId','username email').populate('itemId','title price').sort({ createdAt:-1 }).skip(skip).limit(limit).lean(),
    Transaction.countDocuments(filter),
  ]);
  res.json({ transactions:txs.map(tx=>({ ...tx,usdAmount:convertNGNtoUSD(tx.amount) })), total, page, pages:Math.ceil(total/limit), rate:currencyConfig.rate });
}));

router.post('/admin/transactions/:id/force-release', auth, adminOnly, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const tx=await Transaction.findById(req.params.id).populate('buyerId','username email').populate('sellerId','username email');
  if (!tx) return res.status(404).json({ error:t('not_found') });
  if (tx.disputeId) {
    const dispute=await Dispute.findById(tx.disputeId);
    if (dispute?.status==='RESOLVED') return res.status(409).json({ error:'Dispute already resolved' });
  }
  if (![TX_STATES.DISPUTED,TX_STATES.ESCROW_FUNDED,TX_STATES.SHIPPED,TX_STATES.DELIVERED].includes(tx.state)) return res.status(400).json({ error:`Cannot force-release in state ${tx.state}` });
  const session=await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      const seller=await User.findById(tx.sellerId._id).session(session);
      const plan=getActivePlan(seller);
      const feePercent=tx.escrowFeePercent||plan.escrowFeePercent;
      const fee=Math.round(tx.escrowAmount*feePercent/100);
      const sellerReceives=tx.escrowAmount-fee;
      const now=new Date();
      tx.state=TX_STATES.COMPLETED; tx.timestamps_state.COMPLETED=now; tx.reviewUnlocked=true;
      tx.adminNote=`Force released by admin ${req.user.username}. ${req.body.note||''}`;
      await tx.save({ session });
      closeConvForTx(tx._id, 'admin_force_released').catch(()=>{});
      await walletMove({ session, userId:tx.buyerId._id, fromBucket:'escrow', toBucket:'external', amount:tx.escrowAmount, type:'escrow_release', note:'Admin force release — escrow debited', transactionId:tx._id });
      await walletMove({ session, userId:tx.sellerId._id, fromBucket:'external', toBucket:'withdrawable', amount:sellerReceives, type:'escrow_release', note:'Admin force release', transactionId:tx._id, fee });
      if (tx.disputeId) await Dispute.findByIdAndUpdate(tx.disputeId,{ status:'RESOLVED',decision:'release',resolvedAt:new Date() },{ session });
      await Listing.findByIdAndUpdate(tx.itemId,{ status:'sold' },{ session });
      await logAdmin(req.user._id,'force_release','Transaction',tx._id.toString(),req.body.note||'',{ amount:tx.escrowAmount,sellerId:tx.sellerId._id },'web');
    });
    io.to(`user:${tx.buyerId._id}`).emit('transaction:updated',tx);
    io.to(`user:${tx.sellerId._id}`).emit('transaction:updated',tx);
    res.json({ ok:true, transaction:tx });
  } finally { await session.endSession(); }
}));

router.post('/admin/transactions/:id/force-refund', auth, adminOnly, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const tx=await Transaction.findById(req.params.id).populate('buyerId','username email').populate('sellerId','username email');
  if (!tx) return res.status(404).json({ error:t('not_found') });
  if (tx.disputeId) {
    const dispute=await Dispute.findById(tx.disputeId);
    if (dispute?.status==='RESOLVED') return res.status(409).json({ error:'Dispute already resolved' });
  }
  if (![TX_STATES.DISPUTED,TX_STATES.ESCROW_FUNDED,TX_STATES.SHIPPED,TX_STATES.DELIVERED].includes(tx.state)) return res.status(400).json({ error:`Cannot force-refund in state ${tx.state}` });
  const session=await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      const now=new Date();
      tx.state=TX_STATES.REFUNDED; tx.timestamps_state.REFUNDED=now;
      tx.adminNote=`Force refunded by admin ${req.user.username}. ${req.body.note||''}`;
      await tx.save({ session });
      closeConvForTx(tx._id, 'admin_force_refunded').catch(()=>{});
      await walletMove({ session, userId:tx.buyerId._id, fromBucket:'escrow', toBucket:'available', amount:tx.escrowAmount, type:'escrow_refund', note:`Admin force refund. ${req.body.note||''}`, transactionId:tx._id });
      if (tx.disputeId) await Dispute.findByIdAndUpdate(tx.disputeId,{ status:'RESOLVED',decision:'refund',resolvedAt:new Date() },{ session });
      await Listing.findByIdAndUpdate(tx.itemId,{ status:'active' },{ session });

      await Referral.findOneAndUpdate({ refereeId:tx.buyerId._id },{ locked:true, lockedReason:`Purchase ${tx._id} refunded` }).catch(()=>{});
      await logAdmin(req.user._id,'force_refund','Transaction',tx._id.toString(),req.body.note||'',{ amount:tx.escrowAmount,buyerId:tx.buyerId._id },'web');
    });
    io.to(`user:${tx.buyerId._id}`).emit('transaction:updated',tx);
    io.to(`user:${tx.sellerId._id}`).emit('transaction:updated',tx);
    res.json({ ok:true, transaction:tx });
  } finally { await session.endSession(); }
}));

router.get('/admin/disputes', auth, adminOnly, asyncH(async (req,res) => {
  const { skip,limit,page }=paginate(req);
  const filter={}; if (req.query.status) filter.status=req.query.status;
  const [disputes,total]=await Promise.all([
    Dispute.find(filter).populate('buyerId','username email').populate('sellerId','username email').populate('transactionId','amount state itemTitle').skip(skip).limit(limit).sort({ createdAt:-1 }).lean(),
    Dispute.countDocuments(filter),
  ]);
  res.json({ disputes, total, page, pages:Math.ceil(total/limit) });
}));

router.get('/admin/users', auth, adminOnly, asyncH(async (req,res) => {
  const { skip,limit,page }=paginate(req);
  const filter={};
  if (req.query.q) { const re=new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'i'); filter.$or=[{ username:re },{ email:re }]; }
  if (req.query.role) filter.role=req.query.role;
  if (req.query.plan) filter.activePlan=req.query.plan;
  const [users,total]=await Promise.all([
    User.find(filter).select('-password -refreshTokens -twoFASecret -twoFABackupCodes -emailVerifyToken').skip(skip).limit(limit).sort({ createdAt:-1 }).lean(),
    User.countDocuments(filter),
  ]);
  res.json({ users, total, page, pages:Math.ceil(total/limit) });
}));

router.put('/admin/users/:id', auth, adminOnly, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const allowed=['role','isActive','isVerified','emailVerified','flaggedForAbuse'];
  const updates={}; allowed.forEach(f=>{ if(req.body[f]!==undefined)updates[f]=req.body[f]; });
  const user=await User.findByIdAndUpdate(req.params.id,updates,{ new:true }).select('-password -refreshTokens');
  if (!user) return res.status(404).json({ error:t('not_found') });
  await logAdmin(req.user._id,'user_update','User',req.params.id,'',updates,'web');
  res.json(user);
}));

router.get('/admin/listings', auth, adminOnly, asyncH(async (req,res) => {
  const { skip,limit,page }=paginate(req);
  const filter={}; if (req.query.status) filter.status=req.query.status;
  const [listings,total]=await Promise.all([
    Listing.find(filter).populate('seller','username email').skip(skip).limit(limit).sort({ createdAt:-1 }).lean(),
    Listing.countDocuments(filter),
  ]);
  res.json({ listings:listings.map(l=>({ ...l,usdPrice:convertNGNtoUSD(l.price) })), total, page, pages:Math.ceil(total/limit) });
}));

router.get('/admin/reports', auth, adminOnly, asyncH(async (req,res) => {
  const { skip,limit,page }=paginate(req);
  const filter={}; if (req.query.status) filter.status=req.query.status;
  const [reports,total]=await Promise.all([Report.find(filter).populate('reporter','username').skip(skip).limit(limit).sort({ createdAt:-1 }).lean(), Report.countDocuments(filter)]);
  res.json({ reports, total, page, pages:Math.ceil(total/limit) });
}));

router.put('/admin/reports/:id', auth, adminOnly, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  res.json(await Report.findByIdAndUpdate(req.params.id,{ status:req.body.status, adminNote:req.body.adminNote||'' },{ new:true }));
}));

router.get('/admin/subscriptions', auth, adminOnly, asyncH(async (req,res) => {
  const { skip,limit,page }=paginate(req);
  const filter={}; if (req.query.status) filter.status=req.query.status; if (req.query.plan) filter.plan=req.query.plan;
  const [subs,total]=await Promise.all([
    Subscription.find(filter).populate('userId','username email activePlan').skip(skip).limit(limit).sort({ createdAt:-1 }).lean(),
    Subscription.countDocuments(filter),
  ]);
  res.json({ subscriptions:subs, total, page, pages:Math.ceil(total/limit) });
}));

router.post('/admin/subscriptions/:userId/revoke', auth, adminOnly, [param('userId').isMongoId()], validate, asyncH(async (req,res) => {
  await Subscription.findOneAndUpdate({ userId:req.params.userId, status:'active' },{ status:'cancelled' });
  const targetUser = await User.findById(req.params.userId).lean();
  const isFMActive = targetUser && isFoundingMemberActive(targetUser);
  if (!isFMActive) {
    await User.findByIdAndUpdate(req.params.userId,{ activePlan:'free', planExpiresAt:null });
  }
  await logAdmin(req.user._id,'revoke_subscription','User',req.params.userId,req.body.reason||'','{}','web');
  sendNotification({ recipient:req.params.userId, type:'system', title:'Subscription Revoked', message: isFMActive ? 'Your paid subscription was revoked. Your Founding Member zero-fee perks remain active.' : 'Your subscription has been revoked by admin.', link:'/subscription' }).catch(()=>{});
  res.json({ ok:true });
}));

router.get('/admin/referrals', auth, adminOnly, asyncH(async (req,res) => {
  const { skip,limit,page }=paginate(req);
  const filter={}; if (req.query.flagged) filter['$or']=[{ locked:true }];
  const [refs,total]=await Promise.all([
    Referral.find(filter).populate('referrerId','username email').populate('refereeId','username email').skip(skip).limit(limit).sort({ createdAt:-1 }).lean(),
    Referral.countDocuments(filter),
  ]);
  res.json({ referrals:refs, total, page, pages:Math.ceil(total/limit) });
}));

router.post('/admin/referrals/:id/flag', auth, adminOnly, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  await Referral.findByIdAndUpdate(req.params.id,{ locked:true, lockedReason:req.body.reason||'Admin flagged' });
  await logAdmin(req.user._id,'flag_referral','Referral',req.params.id,req.body.reason||'','{}','web');
  res.json({ ok:true });
}));

router.get('/admin/logs', auth, adminOnly, asyncH(async (req,res) => {
  const { skip,limit,page }=paginate(req);
  const [logs,total]=await Promise.all([
    AdminLog.find({}).populate('adminId','username').skip(skip).limit(limit).sort({ createdAt:-1 }).lean(),
    AdminLog.countDocuments(),
  ]);
  res.json({ logs, total, page, pages:Math.ceil(total/limit) });
}));

router.put('/admin/exchange-rate', auth, adminOnly, [body('rate').isFloat({ min:1 })], validate, asyncH(async (req,res) => {
  const oldRate=currencyConfig.rate;
  currencyConfig.rate=Number(req.body.rate);
  await Config.findOneAndUpdate({ key:'ngnUsdRate' },{ value:currencyConfig.rate, updatedBy:req.user._id },{ upsert:true, new:true });
  await logAdmin(req.user._id,'update_rate','Config','ngnUsdRate','',{ oldRate,newRate:currencyConfig.rate },'web');
  console.log(`[Admin] Rate updated: ${oldRate}→${currencyConfig.rate} by ${req.user.username}`);
  io.emit('rate:updated',{ rate:currencyConfig.rate });
  res.json({ ok:true, oldRate, newRate:currencyConfig.rate });
}));

router.get('/admin/analytics', auth, adminOnly, asyncH(async (req,res) => {
  const [listingsByCategory,txByState,walletTotals,dailySignups,subsByPlan]=await Promise.all([
    Listing.aggregate([{ $group:{ _id:'$category', count:{ $sum:1 }, avgPrice:{ $avg:'$price' } } }]),
    Transaction.aggregate([{ $group:{ _id:'$state', count:{ $sum:1 }, totalAmount:{ $sum:'$amount' } } }]),
    User.aggregate([{ $group:{ _id:null, totalAvailable:{ $sum:'$availableBalance' }, totalReserved:{ $sum:'$reservedBalance' }, totalEscrow:{ $sum:'$escrowBalance' }, totalWithdrawable:{ $sum:'$withdrawableBalance' }, totalEarnings:{ $sum:'$earningsBalance' } } }]),
    User.aggregate([{ $group:{ _id:{ $dateToString:{ format:'%Y-%m-%d',date:'$createdAt' } }, count:{ $sum:1 } } },{ $sort:{ _id:-1 } },{ $limit:30 }]),
    Subscription.aggregate([{ $match:{ status:'active' } },{ $group:{ _id:'$plan', count:{ $sum:1 }, totalRevenue:{ $sum:'$costNGN' } } }]),
  ]);
  res.json({ listingsByCategory, txByState, walletTotals:walletTotals[0]||{}, dailySignups, subsByPlan, rate:currencyConfig.rate });
}));

const expireOffers = async () => {
  const expired=await Offer.find({ status:'pending', expiresAt:{ $lt:new Date() } });
  for (const offer of expired) {
    const session=await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        offer.status='expired'; await offer.save({ session });
        await walletMove({ session, userId:offer.buyer, fromBucket:'reserved', toBucket:'available', amount:offer.amount, type:'unreserve', note:'Offer expired' });
      });
    } catch(e){console.error('[Expire offer]',e.message);}
    finally { await session.endSession(); }
  }
  if (expired.length) console.log(`[Offers] expired ${expired.length}`);
};
setInterval(expireOffers, 30*60*1000);

const processAutoReleases = async () => {
  const now=new Date();

  const deliveredTxs=await Transaction.find({ state:TX_STATES.DELIVERED, autoReleaseAt:{ $lt:now } })
    .populate('buyerId','username email').populate('sellerId','username email');
  for (const tx of deliveredTxs) {
    const session=await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        const seller=await User.findById(tx.sellerId._id).session(session);
        const plan=getActivePlan(seller);
        const feePercent=tx.escrowFeePercent||plan.escrowFeePercent;
        const fee=calculateEscrowFee(tx.escrowAmount, feePercent, seller);
        const sellerReceives=tx.escrowAmount-fee;
        const now2=new Date();
        tx.state=TX_STATES.COMPLETED; tx.timestamps_state.COMPLETED=now2; tx.reviewUnlocked=true;
        await tx.save({ session });
        closeConvForTx(tx._id, 'auto_released').catch(()=>{});
        await walletMove({ session, userId:tx.buyerId._id, fromBucket:'escrow', toBucket:'external', amount:tx.escrowAmount, type:'escrow_release', note:'Auto-release 48h — escrow debited', transactionId:tx._id });
        await walletMove({ session, userId:tx.sellerId._id, fromBucket:'external', toBucket:'withdrawable', amount:sellerReceives, type:'escrow_release', note:'Auto-release 48h', transactionId:tx._id, fee });
        await User.findByIdAndUpdate(tx.buyerId._id, { $inc:{ totalPurchases:1 } }, { session });
        await User.findByIdAndUpdate(tx.sellerId._id, { $inc:{ totalSales:1 } }, { session });
        await Listing.findByIdAndUpdate(tx.itemId,{ status:'sold' },{ session });
      });
      sendEmail(tx.sellerId.email, emailTemplates.paymentReleased(tx.sellerId.username, tx)).catch(()=>{});
      sendNotification({ recipient:tx.sellerId._id, type:'system', title:'Payment Released ✅', message:`₦${tx.escrowAmount.toLocaleString()} released`, link:'/wallet' }).catch(()=>{});
    } catch(e){console.error('[AutoRelease]',e.message);}
    finally { await session.endSession(); }
  }

  const dispatchExpired=await Transaction.find({ state:TX_STATES.ESCROW_FUNDED, dispatchDeadlineAt:{ $lt:now } })
    .populate('buyerId','username email').populate('sellerId','username email');
  for (const tx of dispatchExpired) {
    const session=await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        tx.state=TX_STATES.CANCELLED; tx.timestamps_state.CANCELLED=new Date();
        tx.adminNote='Auto-cancelled: dispatch window expired';
        await tx.save({ session });
        closeConvForTx(tx._id, 'auto_cancelled').catch(()=>{});
        if (tx.escrowAmount>0) await walletMove({ session, userId:tx.buyerId._id, fromBucket:'escrow', toBucket:'available', amount:tx.escrowAmount, type:'escrow_refund', note:'Auto-refund: dispatch window expired', transactionId:tx._id });
        await Listing.findByIdAndUpdate(tx.itemId,{ status:'active' },{ session });
        if (tx.offerId) await Offer.findByIdAndUpdate(tx.offerId,{ status:'rejected' },{ session });
      });
      sendNotification({ recipient:tx.buyerId._id, type:'system', title:'Transaction Auto-Cancelled', message:'Seller did not dispatch in time. Refund issued.', link:`/transactions/${tx._id}` }).catch(()=>{});
      sendNotification({ recipient:tx.sellerId._id, type:'system', title:'Transaction Cancelled', message:'Dispatch window expired. Transaction cancelled.', link:`/transactions/${tx._id}` }).catch(()=>{});
    } catch(e){console.error('[AutoCancel]',e.message);}
    finally { await session.endSession(); }
  }
};
setInterval(processAutoReleases, 30*60*1000);

const processDisputeEscalations = async () => {
  const now=new Date();
  const toEscalate=await Dispute.find({ status:'OPEN', responseDeadlineAt:{ $lt:now }, escalatedAt:null })
    .populate('buyerId','username email').populate('sellerId','username email').populate('transactionId','_id itemTitle amount');
  for (const dispute of toEscalate) {
    dispute.status='ESCALATED'; dispute.escalatedAt=now; await dispute.save();
    sendNotification({ recipient:dispute.buyerId._id, type:'dispute', title:'Dispute Escalated', message:'Escalated to admin review.', link:`/disputes/${dispute._id}` }).catch(()=>{});
    sendNotification({ recipient:dispute.sellerId._id, type:'dispute', title:'Dispute Escalated', message:'Dispute escalated due to non-response.', link:`/disputes/${dispute._id}` }).catch(()=>{});
    const admins=await User.find({ role:'admin', isActive:true }).select('_id email username');
    admins.forEach(a=>{
      sendNotification({ recipient:a._id, type:'dispute', title:'Dispute Escalated — Action Required', message:`Dispute ${dispute._id} needs decision.`, link:'/admin' }).catch(()=>{});
      telegramNotifyAdmin(`⚠️ Dispute Escalated\nDispute: ${dispute._id}\nBuyer: ${dispute.buyerId?.username}\nSeller: ${dispute.sellerId?.username}\nReason: ${dispute.reason?.slice(0,100)}...\nReview at admin panel.`);
    });
  }
};
setInterval(processDisputeEscalations, 60*60*1000);

const processSubscriptionExpiry = async () => {
  const now=new Date();
  const expiredSubs=await Subscription.find({ status:'active', endDate:{ $lt:now } }).populate('userId','_id email username activePlan isEarlyAdopter earlyAdopterNumber earlyAdopterGrantedAt');
  for (const sub of expiredSubs) {
    sub.status='expired'; await sub.save();
    // Don't revert to free if user is still in their Founding Member 180-day window
    const isFMStillActive = sub.userId && isFoundingMemberActive(sub.userId);
    if (!isFMStillActive) {
      await User.findByIdAndUpdate(sub.userId._id,{ activePlan:'free', planExpiresAt:null });
      sendNotification({ recipient:sub.userId._id, type:'system', title:'Subscription Expired', message:'Your plan has reverted to Free. Renew to restore benefits.', link:'/subscription' }).catch(()=>{});
    } else {
      sendNotification({ recipient:sub.userId._id, type:'system', title:'Subscription Expired', message:'Your paid plan expired. Your Founding Member zero-fee perks are still active until your 180-day window ends.', link:'/subscription' }).catch(()=>{});
    }
    console.log(`[Sub] Expired: ${sub.userId.username} → ${isFMStillActive ? 'kept (FM active)' : 'free'}`);
  }

  const reminderDate=new Date(now.getTime()+5*86400000);
  const expiringSoon=await Subscription.find({ status:'active', endDate:{ $lt:reminderDate, $gt:now }, expiryReminderSent:false }).populate('userId','email username activePlan');
  for (const sub of expiringSoon) {
    sendEmail(sub.userId.email, emailTemplates.subscriptionExpiringSoon(sub.userId.username, sub.plan, sub.endDate)).catch(()=>{});
    sub.expiryReminderSent=true; await sub.save();
    console.log(`[Sub] Expiry reminder sent: ${sub.userId.username}`);
  }
};
setInterval(processSubscriptionExpiry, 60*60*1000);

const processEarlyAdopterExpiry = async () => {
  const cutoff = new Date();
  cutoff.setMonth(cutoff.getMonth() - EARLY_ADOPTER_PERK_MONTHS);
  const expired = await User.find({
    isEarlyAdopter: true,
    earlyAdopterGrantedAt: { $lt: cutoff },
    isActive: true,
  }).select('_id username email activePlan earlyAdopterNumber earlyAdopterGrantedAt').lean();
  for (const u of expired) {
    if (u.activePlan === 'free') continue;
    // Never revert a Founding Member who is still inside their 180-day FM window
    if (isFoundingMemberActive(u)) continue;
    const hasSub = await Subscription.exists({ userId: u._id, status: 'active', endDate: { $gt: new Date() } });
    if (!hasSub) {
      await User.findByIdAndUpdate(u._id, { activePlan: 'free', planExpiresAt: null });
      sendNotification({ recipient: u._id, type: 'system', title: 'Early Adopter Perks Ended', message: 'Your 6-month free-fee early adopter period has ended. Upgrade to a plan to continue enjoying benefits.', link: '/subscription' }).catch(() => {});
    }
  }
};

const processFoundingMemberAlerts = async () => {
  const now = new Date();
  const candidates = await User.find({
    isEarlyAdopter: true,
    earlyAdopterNumber: { $lte: FOUNDING_MEMBER_LIMIT },
    isActive: true,
    earlyAdopterGrantedAt: { $ne: null },
  }).select('_id username email earlyAdopterNumber earlyAdopterGrantedAt foundingMember14DaySent foundingMember7DaySent').lean();

  for (const u of candidates) {
    const expiresAt = new Date(u.earlyAdopterGrantedAt);
    expiresAt.setDate(expiresAt.getDate() + FOUNDING_MEMBER_PERK_DAYS);
    const msToExpiry = expiresAt - now;
    if (msToExpiry <= 0) {
      const hasSub = await Subscription.exists({ userId: u._id, status:'active', plan:{ $in:LEGACY_PLAN_IDS }, endDate:{ $gt:now } });
      if (!hasSub) {
        await User.findByIdAndUpdate(u._id, { activePlan:'free', planExpiresAt:null });
        sendNotification({ recipient:u._id, type:'system', title:'Founding Member perks period ended', message:'Your zero-fee period has ended. Your Raw Industrial Badge remains permanently. Subscribe to a Legacy plan to continue.', link:'/subscription' }).catch(()=>{});
      }
      continue;
    }
    const hasPaidLegacy = await Subscription.exists({ userId:u._id, status:'active', plan:{ $in:LEGACY_PLAN_IDS }, endDate:{ $gt:now } });
    if (hasPaidLegacy) continue;
    if (msToExpiry <= 14 * 86400000 && !u.foundingMember14DaySent) {
      sendEmail(u.email, emailTemplates.foundingMember14DayAlert(u.username, u.earlyAdopterNumber, expiresAt)).catch(()=>{});
      sendNotification({ recipient:u._id, type:'system', title:'⚒️ Your benefits are evolving — 14 days left', message:'Lock in your Legacy rate now. Legacy Basic (₦750/mo) or Legacy Pro (₦2,250/mo) — LIFETIME PRICE LOCK.', link:'/subscription' }).catch(()=>{});
      await User.findByIdAndUpdate(u._id, { foundingMember14DaySent: true });
    }
    if (msToExpiry <= 7 * 86400000 && !u.foundingMember7DaySent) {
      sendEmail(u.email, emailTemplates.foundingMember7DayAlert(u.username, u.earlyAdopterNumber, expiresAt)).catch(()=>{});
      sendNotification({ recipient:u._id, type:'system', title:'🚨 Final Week — Lock in your Legacy Rate', message:"Only 7 days left to claim your lifetime Legacy pricing. Don't miss it.", link:'/subscription' }).catch(()=>{});
      await User.findByIdAndUpdate(u._id, { foundingMember7DaySent: true });
    }
  }
};

setInterval(processEarlyAdopterExpiry, 60*60*1000);
processEarlyAdopterExpiry().catch(() => {});
setInterval(processFoundingMemberAlerts, 60*60*1000);
processFoundingMemberAlerts().catch(() => {});

const sendAutoReleaseWarnings = async () => {
  const warnAt=new Date(Date.now()+24*60*60*1000);
  const txs=await Transaction.find({ state:TX_STATES.DELIVERED, autoReleaseAt:{ $lt:warnAt,$gt:new Date() } }).populate('buyerId','username email');
  for (const tx of txs) sendEmail(tx.buyerId.email, emailTemplates.autoReleaseWarning(tx.buyerId.username, tx)).catch(()=>{});
};
setInterval(sendAutoReleaseWarnings, 60*60*1000);

let tgBot = null;

function telegramNotifyAdmin(message) {
  if (!tgBot || !process.env.TELEGRAM_ADMIN_CHAT_ID) return;
  tgBot.sendMessage(process.env.TELEGRAM_ADMIN_CHAT_ID, message, { parse_mode:'Markdown' }).catch(e => {
    console.error('[Telegram] Failed to notify admin:', e.message);
  });
}

function initTelegramBot() {
  if (!process.env.TELEGRAM_BOT_TOKEN) {
    console.log('[Telegram] No TELEGRAM_BOT_TOKEN — bot disabled');
    return;
  }

  try {
    const TelegramBot = require('node-telegram-bot-api');
    tgBot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling:true });
    console.log('[Telegram] Bot started');

    tgBot.onText(/\/start/, (msg) => {
      tgBot.sendMessage(msg.chat.id,
        `🏪 *RawFlip Marketplace Bot*\n\nCommands:\n` +
        `• /deposit — Submit payment proof for a deposit\n` +
        `• /status <txId> — Check transaction status\n` +
        `• /balance — View your wallet (link to app)\n\n` +
        `*Admin commands:*\n` +
        `• /approve <txId> — Approve deposit/withdrawal\n` +
        `• /reject <txId> <reason> — Reject with reason`,
        { parse_mode:'Markdown' }
      );
    });

    tgBot.onText(/\/status (.+)/, async (msg, match) => {
      const txId = match[1]?.trim();
      if (!txId || !mongoose.Types.ObjectId.isValid(txId)) {
        return tgBot.sendMessage(msg.chat.id, '❌ Invalid transaction ID');
      }
      try {
        const wtx = await WalletTx.findById(txId).populate('user','username').lean();
        if (!wtx) return tgBot.sendMessage(msg.chat.id, '❌ Transaction not found');
        tgBot.sendMessage(msg.chat.id,
          `📋 *Transaction Status*\n\nID: \`${txId}\`\nType: ${wtx.type}\nAmount: ₦${wtx.amount?.toLocaleString()}\nFee: ₦${wtx.fee?.toLocaleString()}\nNet: ₦${wtx.netAmount?.toLocaleString()}\nStatus: *${wtx.status}*\nUser: ${wtx.user?.username}`,
          { parse_mode:'Markdown' }
        );
      } catch(e) {
        tgBot.sendMessage(msg.chat.id, `❌ Error: ${e.message}`);
      }
    });

    tgBot.onText(/\/deposit/, (msg) => {
      tgBot.sendMessage(msg.chat.id,
        `💳 *Submit Payment Proof*\n\nSend your proof by replying to this message with:\n1. Your Transaction ID (from the app)\n2. A photo of your payment receipt\n\nFormat: Send transaction ID first, then photo.`,
        { parse_mode:'Markdown' }
      );
    });

    tgBot.on('photo', async (msg) => {
      const chatId = msg.chat.id;
      const caption = msg.caption?.trim() || '';

      const txIdMatch = caption.match(/[a-f0-9]{24}/i);
      if (!txIdMatch) {
        return tgBot.sendMessage(chatId,
          '❌ Please include your Transaction ID in the photo caption.\nExample: Send the photo with caption: `6507a2b3c4d5e6f7a8b9c0d1`',
          { parse_mode:'Markdown' }
        );
      }
      const txId = txIdMatch[0];

      const photoArr = msg.photo;
      const fileId = photoArr[photoArr.length - 1].file_id;

      try {
        const wtx = await WalletTx.findById(txId).populate('user','username email');
        if (!wtx) return tgBot.sendMessage(chatId, '❌ Transaction not found');
        if (wtx.type !== 'deposit') return tgBot.sendMessage(chatId, '❌ Only deposits require proof submission');
        if (wtx.status !== WALLET_TX_STATES.PENDING) {
          return tgBot.sendMessage(chatId, `❌ Cannot submit proof — current status: ${wtx.status}`);
        }
        if (wtx.telegramFileId) {
          return tgBot.sendMessage(chatId, '❌ Proof already submitted for this transaction');
        }

        const updated = await WalletTx.findOneAndUpdate(
          { _id:txId, status:WALLET_TX_STATES.PENDING, telegramFileId:null },
          {
            $set:{
              telegramFileId: fileId,
              status: WALLET_TX_STATES.PROOF_SUBMITTED,
              botRef: `tg:${msg.from.id}:${Date.now()}`,
            }
          },
          { new:true }
        );
        if (!updated) {
          return tgBot.sendMessage(chatId, '❌ Transaction already actioned or proof already submitted');
        }

        tgBot.sendMessage(chatId,
          `✅ *Proof Submitted Successfully*\n\nTransaction ID: \`${txId}\`\nAmount: ₦${wtx.amount?.toLocaleString()}\nFee: ₦${wtx.fee?.toLocaleString()}\nNet: ₦${wtx.netAmount?.toLocaleString()}\n\nYour proof has been sent to the admin for review. You will be notified once approved.`,
          { parse_mode:'Markdown' }
        );

        telegramNotifyAdmin(
          `📎 *New Proof Submission via Telegram*\n\nUser: ${wtx.user?.username}\nAmount: ₦${wtx.amount?.toLocaleString()}\nFee: ₦${wtx.fee?.toLocaleString()}\nTx ID: \`${txId}\`\n\nApprove: /approve ${txId}\nReject: /reject ${txId} <reason>`
        );

        if (process.env.TELEGRAM_ADMIN_CHAT_ID) {
          tgBot.forwardMessage(process.env.TELEGRAM_ADMIN_CHAT_ID, chatId, msg.message_id).catch(()=>{});
        }

        const admins = await User.find({ role:'admin', isActive:true }).select('_id');
        admins.forEach(a => {
          sendNotification({ recipient:a._id, type:'system', title:'Proof Submitted via Telegram', message:`${wtx.user?.username} submitted proof for ₦${wtx.amount?.toLocaleString()} deposit`, link:'/admin' }).catch(()=>{});
          io.to(`user:${a._id}`).emit('admin:proof_submitted', { walletTxId:txId });
        });

      } catch(e) {
        console.error('[Telegram photo handler]', e.message);
        tgBot.sendMessage(chatId, `❌ Error processing proof: ${e.message}`);
      }
    });

    tgBot.onText(/\/approve (.+)/, async (msg, match) => {
      const chatId = msg.chat.id;
      const txId = match[1]?.trim();

      if (!txId || !mongoose.Types.ObjectId.isValid(txId)) {
        return tgBot.sendMessage(chatId, '❌ Invalid transaction ID');
      }

      const isAdminChat = process.env.TELEGRAM_ADMIN_CHAT_ID && chatId.toString() === process.env.TELEGRAM_ADMIN_CHAT_ID.toString();
      if (!isAdminChat) {
        return tgBot.sendMessage(chatId, '🔒 Unauthorized. Admin commands are restricted.');
      }

      try {

        const wtx = await WalletTx.findById(txId).populate('user','username email _id');
        if (!wtx) return tgBot.sendMessage(chatId, '❌ Transaction not found');
        if (!['deposit','withdrawal'].includes(wtx.type)) {
          return tgBot.sendMessage(chatId, `❌ Cannot approve type: ${wtx.type}`);
        }

        if (wtx.adminActionAt) {
          return tgBot.sendMessage(chatId, `❌ Already actioned at ${wtx.adminActionAt.toISOString()}`);
        }

        const validStatuses = wtx.type === 'deposit' ? [WALLET_TX_STATES.PROOF_SUBMITTED] : [WALLET_TX_STATES.PENDING];
        if (!validStatuses.includes(wtx.status)) {
          return tgBot.sendMessage(chatId, `❌ Cannot approve — current status: ${wtx.status}`);
        }

        const adminUser = await User.findOne({ role:'admin', isActive:true }).select('_id username');

        const session = await mongoose.startSession();
        try {
          await session.withTransaction(async () => {
            if (wtx.type === 'deposit') {

              const updatedUser = await User.findByIdAndUpdate(
                wtx.user._id,
                { $inc:{ availableBalance:wtx.netAmount } },
                { new:true, session }
              );
              if (!updatedUser) throw new Error('User not found — aborting');
            }

            const actionResult = await WalletTx.findOneAndUpdate(
              { _id:txId, adminActionAt:null },
              {
                $set:{
                  status: WALLET_TX_STATES.APPROVED,
                  approvedBy: adminUser?._id,
                  approvedAt: new Date(),
                  adminActionAt: new Date(),
                  botRef: `tg_approve:${msg.from.id}:${Date.now()}`,
                }
              },
              { new:true, session }
            );
            if (!actionResult) throw new Error('Transaction already actioned (race condition caught)');

            if (adminUser) {
              await AdminLog.create([{
                adminId: adminUser._id,
                action: `telegram_approve_${wtx.type}`,
                targetType: 'WalletTx',
                targetId: txId,
                note: `Approved via Telegram by chat ${msg.from.id}`,
                meta: { amount:wtx.amount, netAmount:wtx.netAmount, userId:wtx.user._id },
                source: 'telegram',
              }], { session });
            }
          });

          io.to(`user:${wtx.user._id}`).emit('wallet:tx_approved', { walletTxId:txId, type:wtx.type, amount:wtx.amount, netAmount:wtx.netAmount });
          sendNotification({
            recipient: wtx.user._id, type:'system',
            title: `${wtx.type==='deposit'?'Deposit':'Withdrawal'} Approved ✅`,
            message: `₦${wtx.netAmount?.toLocaleString()} ${wtx.type==='deposit'?'credited to your wallet':'processed'}`,
            link: '/wallet',
          }).catch(()=>{});
          if (wtx.type==='deposit') sendEmail(wtx.user.email, emailTemplates.depositApproved(wtx.user.username, wtx.amount, wtx.fee)).catch(()=>{});
          else sendEmail(wtx.user.email, emailTemplates.withdrawalApproved(wtx.user.username, wtx.amount, wtx.fee)).catch(()=>{});

          tgBot.sendMessage(chatId,
            `✅ *Approved Successfully*\n\nTx: \`${txId}\`\nUser: ${wtx.user?.username}\nType: ${wtx.type}\nAmount: ₦${wtx.amount?.toLocaleString()}\nFee: ₦${wtx.fee?.toLocaleString()}\nNet credited: ₦${wtx.netAmount?.toLocaleString()}`,
            { parse_mode:'Markdown' }
          );

        } finally { await session.endSession(); }

      } catch(e) {
        console.error('[Telegram /approve]', e.message);
        tgBot.sendMessage(chatId, `❌ Approval failed: ${e.message}`);
      }
    });

    tgBot.onText(/\/reject (.+)/, async (msg, match) => {
      const chatId = msg.chat.id;
      const parts = match[1]?.trim().split(' ');
      const txId = parts?.[0];
      const reason = parts?.slice(1).join(' ') || 'Rejected by admin';

      const isAdminChat = process.env.TELEGRAM_ADMIN_CHAT_ID && chatId.toString() === process.env.TELEGRAM_ADMIN_CHAT_ID.toString();
      if (!isAdminChat) return tgBot.sendMessage(chatId, '🔒 Unauthorized');
      if (!txId || !mongoose.Types.ObjectId.isValid(txId)) return tgBot.sendMessage(chatId, '❌ Invalid transaction ID');

      try {
        const wtx = await WalletTx.findById(txId).populate('user','username email _id');
        if (!wtx) return tgBot.sendMessage(chatId, '❌ Transaction not found');
        if (!['deposit','withdrawal'].includes(wtx.type)) return tgBot.sendMessage(chatId, `❌ Cannot reject type: ${wtx.type}`);
        if (wtx.adminActionAt) return tgBot.sendMessage(chatId, `❌ Already actioned at ${wtx.adminActionAt.toISOString()}`);
        if (![WALLET_TX_STATES.PENDING, WALLET_TX_STATES.PROOF_SUBMITTED].includes(wtx.status)) {
          return tgBot.sendMessage(chatId, `❌ Cannot reject — status: ${wtx.status}`);
        }

        const adminUser = await User.findOne({ role:'admin', isActive:true }).select('_id username');
        const session = await mongoose.startSession();
        try {
          await session.withTransaction(async () => {
            if (wtx.type === 'withdrawal') {

              await User.findByIdAndUpdate(wtx.user._id, { $inc:{ withdrawableBalance:wtx.amount } }, { session });
            }
            const actionResult = await WalletTx.findOneAndUpdate(
              { _id:txId, adminActionAt:null },
              {
                $set:{
                  status: WALLET_TX_STATES.REJECTED,
                  rejectedBy: adminUser?._id,
                  rejectedAt: new Date(),
                  rejectReason: reason,
                  adminActionAt: new Date(),
                  botRef: `tg_reject:${msg.from.id}:${Date.now()}`,
                }
              },
              { new:true, session }
            );
            if (!actionResult) throw new Error('Already actioned');
            if (adminUser) {
              await AdminLog.create([{
                adminId:adminUser._id, action:`telegram_reject_${wtx.type}`, targetType:'WalletTx', targetId:txId,
                note:reason, meta:{ userId:wtx.user._id }, source:'telegram',
              }], { session });
            }
          });

          sendNotification({ recipient:wtx.user._id, type:'system', title:`${wtx.type==='deposit'?'Deposit':'Withdrawal'} Rejected`, message:`Reason: ${reason}`, link:'/wallet' }).catch(()=>{});
          if (wtx.type==='deposit') sendEmail(wtx.user.email, emailTemplates.depositRejected(wtx.user.username, reason)).catch(()=>{});
          else sendEmail(wtx.user.email, emailTemplates.withdrawalRejected(wtx.user.username, reason)).catch(()=>{});

          tgBot.sendMessage(chatId, `✅ *Rejected*\n\nTx: \`${txId}\`\nUser: ${wtx.user?.username}\nReason: ${reason}`, { parse_mode:'Markdown' });

        } finally { await session.endSession(); }

      } catch(e) {
        console.error('[Telegram /reject]', e.message);
        tgBot.sendMessage(chatId, `❌ Rejection failed: ${e.message}`);
      }
    });

    tgBot.on('polling_error', (e) => console.error('[Telegram] Polling error:', e.message));

  } catch(e) {
    console.error('[Telegram] Failed to initialize bot:', e.message);
    tgBot = null;
  }
}

app.get('/manifest.json', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'manifest.json'));
});

app.use('/icons', require('express').static(path.join(__dirname, 'public', 'icons')));

router.get('/admin/founding-members', auth, adminOnly, asyncH(async (req,res) => {
  const { skip, limit, page } = paginate(req);
  const filter = { isEarlyAdopter: true, earlyAdopterNumber: { $lte: FOUNDING_MEMBER_LIMIT } };
  if (req.query.q) {
    const re = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'i');
    filter.$or = [{ username:re }, { email:re }];
  }
  const [users, total] = await Promise.all([
    User.find(filter)
      .select('username email earlyAdopterNumber earlyAdopterGrantedAt activePlan planExpiresAt isActive emailVerified priority_support foundingMember14DaySent foundingMember7DaySent createdAt')
      .skip(skip).limit(limit).sort({ earlyAdopterNumber:1 }).lean(),
    User.countDocuments(filter),
  ]);
  const now = new Date();
  const enriched = users.map(u => {
    const exp = u.earlyAdopterGrantedAt ? new Date(u.earlyAdopterGrantedAt) : null;
    if (exp) exp.setDate(exp.getDate() + FOUNDING_MEMBER_PERK_DAYS);
    return {
      ...u,
      foundingMemberActive: exp ? now < exp : false,
      foundingMemberExpiresAt: exp,
      planLabel: (exp && now < exp) ? 'Founding Member (Premium Access)' : u.activePlan,
    };
  });
  res.json({ foundingMembers: enriched, total, page, pages: Math.ceil(total/limit) });
}));

app.use('/api', csrfMiddleware, router);
app.get('/health', (_,res) => res.json({ status:'ok', ts:Date.now(), rate:currencyConfig.rate }));

app.use((err,req,res,next) => {

  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  if (err.code==='LIMIT_FILE_SIZE')  return res.status(400).json({ error:'File too large (max 8MB)' });
  if (err.code==='LIMIT_FILE_COUNT') return res.status(400).json({ error:'Max files exceeded' });
  if (err.code===11000) { const field=Object.keys(err.keyValue||{})[0]||'field'; return res.status(409).json({ error:`${field} already taken` }); }
  console.error('[Error]', err.stack||err.message);
  res.status(500).json({ error:IS_PROD?t('server_error'):(err.message||'Unknown error') });
});

io.use(async (socket,next) => {
  try {
    const token=socket.handshake.auth?.token||socket.handshake.headers?.authorization?.replace('Bearer ','');
    if (!token) return next(new Error('AUTH_REQUIRED'));
    const decoded=jwt.verify(token, JWT_SECRET);
    const user=await User.findById(decoded.id).select('username avatar role isActive');
    if (!user||!user.isActive) return next(new Error('AUTH_INVALID'));
    socket.userId=user._id.toString(); socket.user=user; next();
  } catch { next(new Error('AUTH_FAILED')); }
});

const userSockets=new Map();
io.on('connection', socket => {
  const uid=socket.userId;
  socket.join(`user:${uid}`);
  if (!userSockets.has(uid)) userSockets.set(uid,new Set());
  userSockets.get(uid).add(socket.id);

  io.emit('user:online', { userId:uid, online:true, lastSeen:new Date().toISOString() });
  socket.on('disconnect', ()=>{
    const set=userSockets.get(uid);
    if (set) { set.delete(socket.id); if(!set.size)userSockets.delete(uid); }
    if (!userSockets.has(uid)) {
      const lastSeen = new Date();
      User.findByIdAndUpdate(uid,{ lastSeen }).catch(()=>{});

      io.emit('user:online', { userId:uid, online:false, lastSeen:lastSeen.toISOString() });
    }
  });
});

router.get('/agreements/status', auth, asyncH(async (req,res) => {
  const u = await User.findById(req.user._id)
    .select('privacy_policy_agreed privacy_policy_agreed_at terms_agreed terms_agreed_at terms_version about_understood about_understood_at').lean();
  const termsUpToDate = !!(u.terms_agreed && u.terms_version === CURRENT_TERMS_VERSION);
  res.json({
    privacy_policy_agreed:    u.privacy_policy_agreed    || false,
    privacy_policy_agreed_at: u.privacy_policy_agreed_at || null,
    terms_agreed:             u.terms_agreed             || false,
    terms_agreed_at:          u.terms_agreed_at          || null,
    terms_version:            u.terms_version            || null,
    about_understood:         u.about_understood         || false,
    about_understood_at:      u.about_understood_at      || null,
    current_terms_version:    CURRENT_TERMS_VERSION,
    terms_up_to_date:         termsUpToDate,
    all_agreed: !!(u.privacy_policy_agreed && u.about_understood && termsUpToDate),
  });
}));

router.post('/agreements/agree', auth, [
  body('document').isIn(['privacy','terms','about']).withMessage('Invalid document'),
], validate, asyncH(async (req,res) => {
  const { document } = req.body;
  const now = new Date();
  const update = {};
  if (document === 'privacy')      { update.privacy_policy_agreed = true; update.privacy_policy_agreed_at = now; }
  else if (document === 'terms')   { update.terms_agreed = true; update.terms_agreed_at = now; update.terms_version = CURRENT_TERMS_VERSION; }
  else if (document === 'about')   { update.about_understood = true; update.about_understood_at = now; }
  const user = await User.findByIdAndUpdate(req.user._id, update, { new:true })
    .select('privacy_policy_agreed privacy_policy_agreed_at terms_agreed terms_agreed_at terms_version about_understood about_understood_at');
  await logAdmin(req.user._id, 'agreement_recorded', 'User', req.user._id,
    `User agreed to: ${document}`, { document, version: document==='terms' ? CURRENT_TERMS_VERSION : undefined }, 'web');
  res.json({ ok:true, document });
}));

router.get('/admin/agreements', auth, adminOnly, asyncH(async (req,res) => {
  const { skip, limit, page } = paginate(req);
  const filter = {};
  if (req.query.q) {
    const re = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'), 'i');
    filter.$or = [{ username:re }, { email:re }];
  }
  if (req.query.privacy === 'agreed')   filter.privacy_policy_agreed = true;
  if (req.query.privacy === 'pending')  filter.privacy_policy_agreed = { $ne:true };
  if (req.query.terms === 'agreed')     filter.terms_agreed = true;
  if (req.query.terms === 'pending')    filter.terms_agreed = { $ne:true };
  if (req.query.about === 'agreed')     filter.about_understood = true;
  if (req.query.about === 'pending')    filter.about_understood = { $ne:true };
  if (req.query.outdated === '1')       { filter.terms_agreed = true; filter.terms_version = { $ne:CURRENT_TERMS_VERSION }; }
  const [users, total] = await Promise.all([
    User.find(filter)
      .select('username email role isActive privacy_policy_agreed privacy_policy_agreed_at terms_agreed terms_agreed_at terms_version about_understood about_understood_at createdAt')
      .skip(skip).limit(limit).sort({ createdAt:-1 }).lean(),
    User.countDocuments(filter),
  ]);
  res.json({ users, total, page, pages:Math.ceil(total/limit), current_terms_version:CURRENT_TERMS_VERSION });
}));

const supportTicketSchema = new mongoose.Schema({
  ticketNumber: { type:String, unique:true },
  user:       { type:mongoose.Schema.Types.ObjectId, ref:'User', default:null },
  name:       { type:String, default:'Guest' },
  email:      { type:String, default:'' },
  subject:    { type:String, required:true, maxlength:200 },
  message:    { type:String, required:true, maxlength:5000 },
  attachment: { type:String, default:null },
  status:     { type:String, enum:['open','pending','resolved','closed'], default:'open', index:true },
  priority:   { type:String, enum:['normal','PRIORITY_FOUNDING_MEMBER'], default:'normal', index:true },
  adminReply: { type:String, default:null, maxlength:5000 },
  adminNotes: { type:String, default:null },
  repliedAt:  { type:Date, default:null },
  closedAt:   { type:Date, default:null },
}, { timestamps:true });

supportTicketSchema.pre('save', async function() {
  if (!this.ticketNumber) {

    const rand = Math.random().toString(36).slice(2,5).toUpperCase();
    const ts   = Date.now().toString(36).slice(-3).toUpperCase();
    this.ticketNumber = 'RF-' + rand + ts;
  }
});

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

const SUPPORT_ADDR =  ['n','e','t','l','i','f','e','s','o','c','i','a','l','@','g','m','a','i','l','.','c','o','m'].join('');

const escHtml = (str) => String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

const ticketLimiter = rateLimit({ windowMs:15*60*1000, max:5, standardHeaders:true, legacyHeaders:false,
  message:{ error:'Too many support requests. Please wait 15 minutes.' } });

router.post('/support/tickets', ticketLimiter, uploadSupport.single('attachment'),
  [body('subject').trim().notEmpty().isLength({ max:200 }),
   body('message').trim().isLength({ min:20, max:5000 })],
  validate,
  asyncH(async (req,res) => {

    let userId = null, userName = 'Guest', userEmail = '';
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      try {
        const dec = jwt.verify(authHeader.slice(7), JWT_SECRET);
        const u   = await User.findById(dec.id).select('username email').lean();
        if (u) { userId = u._id; userName = u.username; userEmail = u.email; }
      } catch(_) {}
    }

    if (!userId && req.cookies?.rf_access) {
      try {
        const dec = jwt.verify(req.cookies.rf_access, JWT_SECRET);
        const u   = await User.findById(dec.id).select('username email').lean();
        if (u) { userId = u._id; userName = u.username; userEmail = u.email; }
      } catch(_) {}
    }

    let ticketPriority = 'normal';
    if (userId) {
      const ticketUser = await User.findById(userId).lean();
      if (ticketUser && ticketUser.isEarlyAdopter && ticketUser.earlyAdopterNumber <= FOUNDING_MEMBER_LIMIT) {
        ticketPriority = 'PRIORITY_FOUNDING_MEMBER';
      }
    }
    const ticket = await SupportTicket.create({
      user:       userId,
      name:       userName,
      email:      userEmail,
      subject:    req.body.subject,
      message:    req.body.message,
      attachment: req.file ? `/uploads/${req.file.filename}` : null,
      priority:   ticketPriority,
    });

    const teamHtml = emailBase(`
      <h2>New Support Ticket ${ticket.ticketNumber}</h2>
      <p><strong>From:</strong> ${escHtml(userName)} (${userEmail || 'guest'})</p>
      <p><strong>Subject:</strong> ${escHtml(ticket.subject)}</p>
      <p><strong>Status:</strong> Open</p>
      <div style="background:#1a1a2e;border-radius:8px;padding:16px;margin:16px 0;color:#eeeef8;white-space:pre-wrap;font-size:.875rem;">${escHtml(ticket.message)}</div>
      ${ticket.attachment ? `<p><strong>Attachment:</strong> ${process.env.APP_URL||'http://localhost:5000'}${ticket.attachment}</p>` : ''}
      <p style="color:#8888aa;font-size:.8rem">Ticket ID: ${ticket._id} | Submitted: ${new Date().toUTCString()}</p>
    `);

    sendEmail(SUPPORT_ADDR, { subject:`[RawFlip Support]${ticketPriority === 'PRIORITY_FOUNDING_MEMBER' ? ' 🚀 PRIORITY FM —' : ''} ${ticket.ticketNumber} — ${ticket.subject}`, html:teamHtml }).catch(()=>{});

    if (userEmail) {
      const isPriority = ticketPriority === 'PRIORITY_FOUNDING_MEMBER';
      const ackHtml = emailBase(`
        <h2>We received your request 📨</h2>
        <p>Hi ${escHtml(userName)},</p>
        <p>Thanks for reaching out. Your support ticket has been created successfully.</p>
        <div style="background:#1a1a2e;border-radius:8px;padding:16px;margin:16px 0;">
          <p style="margin:0 0 6px"><strong>Ticket:</strong> ${ticket.ticketNumber}</p>
          <p style="margin:0 0 6px"><strong>Subject:</strong> ${escHtml(ticket.subject)}</p>
          <p style="margin:0;color:#8888aa;font-size:.85rem">${isPriority ? '⚡ As a Founding Member, your ticket has been marked <strong style="color:#f0c040">Priority</strong> — we aim to respond within a few hours.' : 'Our team usually responds within 24 hours.'} You can track your ticket status in the app under Help &amp; Support → My Tickets.</p>
        </div>
        <p style="color:#8888aa;font-size:.8rem">Please do not reply to this email — use the ticket system in the app.</p>
      `);
      sendEmail(userEmail, { subject:`Your support request has been received — ${ticket.ticketNumber}`, html:ackHtml }).catch(()=>{});
    }

    res.status(201).json({
      ok: true,
      ticketNumber: ticket.ticketNumber,
      _id:  ticket._id,
      status: ticket.status,
    });
  })
);

router.get('/support/tickets', auth, asyncH(async (req,res) => {
  const { skip, limit } = paginate(req);
  const filter = { user: req.user._id };
  const [tickets, total] = await Promise.all([
    SupportTicket.find(filter)
      .select('ticketNumber subject message status adminReply repliedAt createdAt attachment')
      .sort({ createdAt:-1 }).skip(skip).limit(Math.min(limit,50)).lean(),
    SupportTicket.countDocuments(filter),
  ]);
  res.json({ tickets, total });
}));

router.get('/support/tickets/:id', auth, [param('id').isMongoId()], validate, asyncH(async (req,res) => {
  const ticket = await SupportTicket.findById(req.params.id).lean();
  if (!ticket) return res.status(404).json({ error:'Ticket not found' });
  const isOwner = ticket.user && ticket.user.toString() === req.user._id.toString();
  const isAdmin = req.user.role === 'admin';
  if (!isOwner && !isAdmin) return res.status(403).json({ error:'Forbidden' });

  if (!isAdmin) delete ticket.adminNotes;
  res.json(ticket);
}));

router.get('/admin/support/tickets', auth, adminOnly, asyncH(async (req,res) => {
  const { skip, limit } = paginate(req);
  const filter = {};
  if (req.query.status) filter.status = req.query.status;
  if (req.query.q) {
    const re = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'), 'i');
    filter.$or = [{ subject:re }, { message:re }, { name:re }, { email:re }, { ticketNumber:re }];
  }
  const [tickets, total] = await Promise.all([
    SupportTicket.find(filter)
      .populate('user','username email')
      .sort({ priority:-1, createdAt:-1 }).skip(skip).limit(limit).lean(),
    SupportTicket.countDocuments(filter),
  ]);
  res.json({ tickets, total });
}));

router.put('/admin/support/tickets/:id/reply', auth, adminOnly,
  [param('id').isMongoId(), body('reply').trim().isLength({ min:1, max:5000 })],
  validate,
  asyncH(async (req,res) => {
    const ticket = await SupportTicket.findById(req.params.id).populate('user','username email');
    if (!ticket) return res.status(404).json({ error:'Ticket not found' });
    ticket.adminReply = req.body.reply;
    ticket.repliedAt  = new Date();
    ticket.status     = 'pending';
    await ticket.save();

    const userEmail = ticket.email || (ticket.user && ticket.user.email);
    const userName  = ticket.name  || (ticket.user && ticket.user.username) || 'User';
    if (userEmail) {
      const replyHtml = emailBase(`
        <h2>Update on your support ticket ${ticket.ticketNumber}</h2>
        <p>Hi ${escHtml(userName)},</p>
        <p>Our support team has replied to your request.</p>
        <div style="background:#1a1a2e;border-radius:8px;padding:16px;margin:16px 0;">
          <p style="margin:0 0 6px"><strong>Ticket:</strong> ${ticket.ticketNumber}</p>
          <p style="margin:0 0 10px"><strong>Subject:</strong> ${escHtml(ticket.subject)}</p>
          <p style="margin:0 0 6px;color:#8888aa;font-size:.8rem">Support reply:</p>
          <p style="margin:0;white-space:pre-wrap">${escHtml(ticket.adminReply)}</p>
        </div>
        <p>You can view the full conversation in the app under <strong>Help &amp; Support → My Tickets</strong>.</p>
      `);
      sendEmail(userEmail, { subject:`[RawFlip Support] Reply to ${ticket.ticketNumber}`, html:replyHtml }).catch(()=>{});
    }

    if (ticket.user) {
      await Notification.create({
        recipient: ticket.user._id || ticket.user,
        type:    'system',
        title:   'Support reply received 💬',
        message: `Your ticket ${ticket.ticketNumber} has a reply from our team.`,
        read:    false,
      }).catch(()=>{});
    }

    res.json({ ok:true, ticket });
  })
);

router.put('/admin/support/tickets/:id/status', auth, adminOnly,
  [param('id').isMongoId(), body('status').isIn(['open','pending','resolved','closed']),
   body('adminNotes').optional().trim().isLength({ max:2000 })],
  validate,
  asyncH(async (req,res) => {
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ error:'Ticket not found' });
    ticket.status = req.body.status;
    if (req.body.adminNotes !== undefined) ticket.adminNotes = req.body.adminNotes;
    if (req.body.status === 'closed' || req.body.status === 'resolved') ticket.closedAt = new Date();
    await ticket.save();
    res.json({ ok:true, status:ticket.status });
  })
);

router.get('/push/vapid-key', (req, res) => {
  if (!VAPID_PUBLIC_KEY)
    return res.status(503).json({ error: 'Push notifications not configured on this server.' });
  res.json({ publicKey: VAPID_PUBLIC_KEY });
});

router.post('/push-subscription', auth, asyncH(async (req, res) => {
  const { endpoint, keys } = req.body || {};
  if (!endpoint || !keys?.p256dh || !keys?.auth)
    return res.status(400).json({ error: 'Invalid push subscription object.' });

  await PushSub.findOneAndUpdate(
    { endpoint },
    { user: req.user._id, endpoint, keys },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
  console.log(`[Push] subscription saved for user ${req.user._id}`);
  res.json({ ok: true });
}));

router.delete('/push-subscription', auth, asyncH(async (req, res) => {
  const { endpoint } = req.body || {};
  if (endpoint) {
    await PushSub.deleteOne({ user: req.user._id, endpoint });
  } else {

    await PushSub.deleteMany({ user: req.user._id });
  }
  res.json({ ok: true });
}));

router.post('/kyc/submit', auth, asyncH(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (user.kycStatus === 'approved')
    return res.status(400).json({ error:'KYC already approved.' });
  if (user.kycStatus === 'pending')
    return res.status(400).json({ error:'KYC submission already under review.' });

  const { fullName, dob, idType, idNumber, idDocUrl, selfieUrl, address } = req.body;
  if (!fullName || !dob || !idType || !idNumber || !idDocUrl || !selfieUrl || !address)
    return res.status(400).json({ error:'All KYC fields are required.' });

  await KycDoc.findOneAndUpdate(
    { user: user._id },
    { fullName, dob, idType, idNumber, idDocUrl, selfieUrl, address,
      status:'pending', adminNote:'', reviewedBy:null, reviewedAt:null },
    { upsert:true, new:true }
  );

  user.kycStatus      = 'pending';
  user.kycSubmittedAt = new Date();
  user.kycReviewedAt  = null;
  user.kycRejectionNote = '';
  await user.save();

  const admins = await User.find({ role:'admin', isActive:true }).select('_id');
  admins.forEach(a => {
    sendNotification({
      recipient: a._id, type:'system',
      title: 'New KYC Submission',
      message: `${user.username} submitted KYC documents for review.`,
      link: '/admin',
    }).catch(() => {});
  });

  res.json({ ok:true, message:'KYC submitted successfully. Under review.' });
}));

router.get('/kyc/status', auth, asyncH(async (req, res) => {
  const user = await User.findById(req.user._id).select('kycStatus kycSubmittedAt kycReviewedAt kycRejectionNote');
  res.json({
    kycStatus:        user.kycStatus,
    kycSubmittedAt:   user.kycSubmittedAt,
    kycReviewedAt:    user.kycReviewedAt,
    kycRejectionNote: user.kycRejectionNote,
  });
}));

router.get('/admin/kyc', auth, adminOnly, asyncH(async (req, res) => {
  const { status = 'pending', page = 1, limit = 20 } = req.query;
  const skip = (parseInt(page) - 1) * parseInt(limit);
  const filter = status === 'all' ? {} : { status };
  const [docs, total] = await Promise.all([
    KycDoc.find(filter)
      .populate('user', 'username email phone avatar createdAt kycStatus')
      .populate('reviewedBy', 'username')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean(),
    KycDoc.countDocuments(filter),
  ]);
  res.json({ docs, total, page: parseInt(page), pages: Math.ceil(total / parseInt(limit)) });
}));

router.post('/admin/kyc/:userId/approve', auth, adminOnly, asyncH(async (req, res) => {
  const kycDoc = await KycDoc.findOne({ user: req.params.userId });
  if (!kycDoc) return res.status(404).json({ error:'KYC submission not found.' });

  kycDoc.status     = 'approved';
  kycDoc.reviewedBy = req.user._id;
  kycDoc.reviewedAt = new Date();
  kycDoc.adminNote  = req.body.note || '';
  await kycDoc.save();

  await User.findByIdAndUpdate(req.params.userId, {
    kycStatus:      'approved',
    kycReviewedAt:  new Date(),
    kycReviewedBy:  req.user._id,
    kycRejectionNote: '',
  });

  await logAdmin(req.user._id, 'kyc_approve', 'User', req.params.userId, req.body.note || 'KYC approved');

  sendNotification({
    recipient: req.params.userId, type:'system',
    title: '✅ KYC Approved',
    message: 'Your KYC verification has been approved. You can now make withdrawals.',
    link: '/wallet',
  }).catch(() => {});

  res.json({ ok:true, message:'KYC approved.' });
}));

router.post('/admin/kyc/:userId/reject', auth, adminOnly, asyncH(async (req, res) => {
  const reason = (req.body.reason || '').trim();
  if (!reason) return res.status(400).json({ error:'Rejection reason is required.' });

  const kycDoc = await KycDoc.findOne({ user: req.params.userId });
  if (!kycDoc) return res.status(404).json({ error:'KYC submission not found.' });

  kycDoc.status     = 'rejected';
  kycDoc.reviewedBy = req.user._id;
  kycDoc.reviewedAt = new Date();
  kycDoc.adminNote  = reason;
  await kycDoc.save();

  await User.findByIdAndUpdate(req.params.userId, {
    kycStatus:        'rejected',
    kycReviewedAt:    new Date(),
    kycReviewedBy:    req.user._id,
    kycRejectionNote: reason,
  });

  await logAdmin(req.user._id, 'kyc_reject', 'User', req.params.userId, reason);

  sendNotification({
    recipient: req.params.userId, type:'system',
    title: '❌ KYC Rejected',
    message: `Your KYC was rejected: ${reason}. Please resubmit with correct documents.`,
    link: '/settings',
  }).catch(() => {});

  res.json({ ok:true, message:'KYC rejected.' });
}));

mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS:5000 })
  .then(async () => {
    console.log('[DB] MongoDB connected');

    try {
      const rateConfig=await Config.findOne({ key:'ngnUsdRate' });
      if (rateConfig?.value) { currencyConfig.rate=Number(rateConfig.value); console.log(`[Config] Rate loaded: ${currencyConfig.rate} NGN/USD`); }
      else console.log(`[Config] Default rate: ${currencyConfig.rate} NGN/USD`);
    } catch(e) { console.warn('[Config] Could not load rate:', e.message); }
    await initES();
    initTelegramBot();
    server.listen(PORT, ()=>console.log(`🚀 RawFlip API v7 → http://localhost:${PORT} | Rate: ${currencyConfig.rate} NGN/USD`));
  })
  .catch(err=>{ console.error('[DB] Error:', err.message); process.exit(1); });

module.exports = { app, server };
