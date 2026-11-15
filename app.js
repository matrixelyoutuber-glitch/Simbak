// Frontend only. Language Schools = 100% English. Government = 100% Arabic.
// Wrong-course ("undefined 'id'") detection is done HERE only — solvers untouched.
// Same-origin only: API overrides and admin keys in URLs/storage are deliberately unsupported.
const API_BASE = '';
const BROWSER_HEADERS = { 'X-Qureo-Browser': '1' };

// Compatible with browsers that do not support native abort timeouts.
async function fetchWithTimeout(url, options = {}, timeoutMs = 20000) {
  if (typeof AbortController === 'undefined') return fetch(url, options);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

const volatileStorage = new Map();
function createSafeStorage(area) {
  const prefix = area + ':';
  return {
    getItem(key) {
      try {
        const value = window[area].getItem(key);
        return value === null ? (volatileStorage.get(prefix + key) ?? null) : value;
      } catch { return volatileStorage.get(prefix + key) ?? null; }
    },
    setItem(key, value) {
      volatileStorage.set(prefix + key, String(value));
      try { window[area].setItem(key, String(value)); } catch {}
    },
    removeItem(key) {
      volatileStorage.delete(prefix + key);
      try { window[area].removeItem(key); } catch {}
    },
  };
}
const storageLocal = createSafeStorage('localStorage');
const storageSession = createSafeStorage('sessionStorage');
storageLocal.removeItem('qureoAdmin');
storageLocal.removeItem('qureoApiBase');
storageSession.removeItem('vip0101Key');
storageSession.removeItem('vip0101AccountId');

function proofHasLeadingZeroBits(buffer, bits) {
  const bytes = new Uint8Array(buffer);
  const wholeBytes = Math.floor(bits / 8);
  const remainingBits = bits % 8;
  for (let index = 0; index < wholeBytes; index += 1) {
    if (bytes[index] !== 0) return false;
  }
  return remainingBits === 0 || bytes[wholeBytes] >> (8 - remainingBits) === 0;
}

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const SHA256_ENCODER = new TextEncoder();

function sha256Bytes(message) {
  const input = SHA256_ENCODER.encode(message);
  const block = new Uint8Array(64);
  block.set(input);
  block[input.length] = 0x80;
  const view = new DataView(block.buffer);
  view.setUint32(60, input.length * 8, false);
  const words = new Uint32Array(64);
  for (let index = 0; index < 16; index += 1) words[index] = view.getUint32(index * 4, false);
  for (let index = 16; index < 64; index += 1) {
    const x = words[index - 15];
    const y = words[index - 2];
    const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
    words[index] = (words[index - 16] + s0 + words[index - 7] + s1) >>> 0;
  }
  let a = 0x6a09e667; let b = 0xbb67ae85; let c = 0x3c6ef372; let d = 0xa54ff53a;
  let e = 0x510e527f; let f = 0x9b05688c; let g = 0x1f83d9ab; let h = 0x5be0cd19;
  for (let index = 0; index < 64; index += 1) {
    const s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const choice = (e & f) ^ (~e & g);
    const temp1 = (h + s1 + choice + SHA256_K[index] + words[index]) >>> 0;
    const s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const majority = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (s0 + majority) >>> 0;
    h = g; g = f; f = e; e = (d + temp1) >>> 0;
    d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
  }
  const output = new Uint8Array(32);
  const outputView = new DataView(output.buffer);
  const state = [a, b, c, d, e, f, g, h].map((value, index) => (value + [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19][index]) >>> 0);
  state.forEach((value, index) => outputView.setUint32(index * 4, value, false));
  return output;
}

async function getBrowserProof(scope) {
  let data = null;
  let lastError = null;
  for (let attempt = 0; attempt < 3 && !data; attempt += 1) {
    try {
      const burst = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const response = await fetchWithTimeout(`${API_BASE}/api/browser/challenge?scope=${encodeURIComponent(scope)}&_=${burst}`, {
        headers: BROWSER_HEADERS,
        cache: 'no-store',
        credentials: 'same-origin',
      });
      const text = await response.text();
      let candidate = {};
      try { candidate = text ? JSON.parse(text) : {}; } catch { candidate = {}; }
      if (!response.ok || !candidate.ok) {
        const error = new Error(candidate.error || 'تعذر التحقق من المتصفح. حاول مرة أخرى.');
        error.code = response.status === 429 ? 'RATE_LIMITED' : 'BROWSER_CHECK';
        throw error;
      }
      if (!/^[a-f0-9]{32}$/.test(String(candidate.challenge || ''))) throw new Error('استجابة التحقق غير صالحة. حاول مرة أخرى.');
      data = candidate;
    } catch (error) {
      lastError = error;
      if (error.code === 'RATE_LIMITED') throw error;
      if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 350 * (attempt + 1)));
    }
  }
  if (!data) throw lastError || new Error('تعذر التحقق من المتصفح. حاول مرة أخرى.');
  const challenge = String(data.challenge || '');
  const difficulty = Number(data.difficulty || 14);
  const started = Date.now();
  for (let nonce = 0; nonce <= 0xffffffff; nonce += 1) {
    const digest = sha256Bytes(`${challenge}:${nonce}`);
    if (proofHasLeadingZeroBits(digest, difficulty)) return { challenge, nonce: String(nonce) };
    if ((nonce & 2047) === 2047) {
      if (Date.now() - started > 110000) throw new Error('انتهت مهلة التحقق من المتصفح. حاول مرة أخرى.');
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
  throw new Error('تعذر إكمال التحقق من المتصفح.');
}

const VIP_MODE = /^\/vip0101\/?$/.test(location.pathname);
const VERIFY_MODE = Boolean(document.querySelector('#browser-verify'));
if (VERIFY_MODE) {
  initBrowserVerification();
} else if (VIP_MODE) {
  initVip0101();
} else {
let currentUser = storageLocal.getItem('qureoUserKey') || '';
let progressToken = storageLocal.getItem('qureoProgressToken') || '';
let deviceFp = storageLocal.getItem('qureoFp');
if (!deviceFp) {
  deviceFp = 'fp-' + Math.random().toString(36).slice(2) + '-' + Date.now().toString(36);
  storageLocal.setItem('qureoFp', deviceFp);
}

const form = document.querySelector('#solve-form');
const button = document.querySelector('#start-button');
const statusBox = document.querySelector('#status');
const chaptersBox = document.querySelector('#chapters');
const activityBox = document.querySelector('#activity');
const activityCount = document.querySelector('#activity-count');
const runningBadge = document.querySelector('#running-badge');
const courseCards = document.querySelector('#course-cards');
const stepIndicator = document.querySelector('#step-indicator');
const btnNext = document.querySelector('#btn-next');
const btnBack = document.querySelector('#btn-back');
const joinModal = document.querySelector('#join-modal');
const categoryModal = document.querySelector('#category-modal');
const yearModal = document.querySelector('#year-modal');
const mismatchModal = document.querySelector('#mismatch-modal');
const credentialsModal = document.querySelector('#credentials-modal');
const credentialCode = document.querySelector('#credential-code');
const credentialPassword = document.querySelector('#credential-password');
const credentialError = document.querySelector('#credential-error');
const credentialRetry = document.querySelector('#credential-retry');
const selectionPill = document.querySelector('#selection-pill');
const confirmNote = document.querySelector('#confirm-note');
const joinedButton = document.querySelector('#joined-button');

let refreshing = false;
let progressFailures = 0;
let lastQueued = false;
let activitySignature = '';
let chaptersSignature = '';
let selectedTrack = storageSession.getItem('qureoTrack') || '';
let selectedYear = storageSession.getItem('qureoYear') || '';
let selectedCourse = '';
let step = 1;
let solveJustStarted = false;
let uiLanguage = 'ar';
let mismatchHandled = '';
let lastActivity = [];
let lastChapters = [];
let solveActivityBaseline = '[]';
let credentialsTrack = '';
let startingSolve = false;
let solveInProgress = false;
let rateLimitedUntil = 0;

const COURSES_BY_TRACK = {
  government: {
    one: [
      { key: 'js_fast_42', label: 'JavaScript', labelAr: 'جافاسكربت', desc: '42 chapters · Government schools', descAr: '42 فصل · مدارس حكومي' },
    ],
    two: [
      { key: 'js_fast', label: 'JavaScript', labelAr: 'جافاسكربت', desc: '54 chapters · Government schools', descAr: '54 فصل · مدارس حكومي' },
      { key: 'pylangs_fast', label: 'Python', labelAr: 'بايثون', desc: 'Complete course · Government schools', descAr: 'الكورس كامل · مدارس حكومي' },
      { key: 'fin', label: 'Financial Literacy', labelAr: 'ثقافة مالية', desc: 'Complete course · Government schools', descAr: 'الكورس كامل · مدارس حكومي' },
    ],
  },
  language: {
    one: [
      { key: 'jslangs_fast_42', label: 'JavaScript — Language Schools', desc: '42 chapters · First year' },
    ],
    two: [
      { key: 'jslangs_fast', label: 'JavaScript — Language Schools', desc: '54 chapters · Second year' },
      { key: 'pylangs', label: 'Python — Language Schools', desc: 'Complete course · Second year' },
      { key: 'sakafa_langs', label: 'Financial Literacy — Language Schools', desc: 'English course · 134 items' },
    ],
  },
};

const TEXT = {
  brandName: ['QUREO', 'حل كيريو'],
  brandSub: ['SOLVER', 'QUREO'],
  brandFooter: ['QUREO SOLVER', 'حل كيريو'],
  joinKicker: ['ONE QUICK STEP', 'خطوة واحدة سريعة'],
  joinTitle: ['Stay in the loop', 'تابع كل جديد'],
  joinBody: ['Get solver updates and new course releases on Telegram, then continue to the platform.', 'تابع تحديثات الحل والكورسات الجديدة على تيليجرام، وبعدها كمل للمنصة.'],
  joinOpen: ['Open Telegram', 'فتح تيليجرام'],
  joinedButton: ['I’ve joined — continue', 'انضمت — متابعة'],
  categoryKicker: ['MOST IMPORTANT STEP', 'أهم خطوة — ظبطها صح'],
  categoryTitle: ['Is your QUREO account in Arabic or English?', 'حسابك على كيريو بالعربي ولا بالإنجليزي؟'],
  categoryIntro: ['Pick Government for an Arabic portal, Language Schools for an English one. A wrong pick stops the solve instantly.', 'دي أهم خطوة! لو حسابك بالعربي اختار «حكومي»، ولو بالإنجليزي اختار «لغات». الاختيار الغلط بيخلي الحل يقف من أوله.'],
  govCard: ['Government', 'حكومي'],
  govCardDesc: ['Arabic QUREO portal · Year 1 & Year 2', 'حساب كيريو بالعربي — أولى وتانية بكالوريا'],
  langCard: ['Language Schools', 'لغات'],
  langCardDesc: ['English QUREO portal · JavaScript, Python & Financial Literacy', 'حساب كيريو بالإنجليزي — جافاسكربت وبايثون وثقافة مالية'],
  yearTitle: ['Choose your year', 'اختار سنتك'],
  yearBack: ['Back to school type', 'رجوع لنوع المدرسة'],
  yearKickerGov: ['GOVERNMENT SCHOOLS', 'مدارس حكومي'],
  yearKickerLang: ['LANGUAGE SCHOOLS', 'مدارس لغات'],
  yearBodyGov: ['Your year sets the right government course and chapter range.', 'سنتك بتحدد الكورس الحكومي وعدد الفصول الصحيح.'],
  yearBodyLang: ['Your year sets the right language-schools course and chapter range.', 'سنتك بتحدد كورس اللغات وعدد الفصول الصحيح.'],
  yearOne: ['First Year', 'أولى بكالوريا'],
  yearTwo: ['Second Year', 'تانية بكالوريا'],
  yearOneGovDesc: ['JavaScript · 42 chapters · Government', 'جافاسكربت · 42 فصل'],
  yearTwoGovDesc: ['JavaScript (54) · Python · Financial Literacy', 'جافاسكربت (54 فصل) · بايثون · ثقافة مالية'],
  yearOneLangDesc: ['JavaScript · 42 chapters · Language Schools', 'JavaScript · 42 فصل · لغات'],
  yearTwoLangDesc: ['JavaScript (54) · Python · Financial · Language Schools', 'JavaScript (54) وPython وFinancial · لغات'],
  trackGov: ['Government', 'حكومي'],
  trackLang: ['Language Schools', 'لغات'],
  yearShortOne: ['Year 1', 'أولى'],
  yearShortTwo: ['Year 2', 'تانية'],
  pickTrack: ['Pick school type & year ✎', 'اختار نوع مدرستك وسنتك ✎'],
  confirmNote: ['Final check — you are solving: {course} · {track} · {year}', 'تأكيد أخير — هتحل: {course} · {track} · {year}'],
  mismatchKicker: ['WRONG COURSE', 'اختيار غير صحيح'],
  mismatchTitleGov: ['You’re Language Schools but picked Government 😅', 'انت لغات لكن مختار حكومي 😅'],
  mismatchTitleLang: ['You’re Government but picked Language Schools 😅', 'انت حكومي لكن مختار لغات 😅'],
  mismatchBodyGov: ['Your QUREO account is on the English portal (Language Schools), but you picked Government. Hit "Edit selection" and choose Language Schools to start the right solve.', 'حسابك على كيريو بالإنجليزي (لغات)، بس انت اخترت «حكومي». دوس «تعديل الاختيار» واختار «لغات» عشان يبدأ الحل الصح.'],
  mismatchBodyLang: ['Your QUREO account is on the Arabic portal (Government), but you picked Language Schools. Hit "Edit selection" and choose Government to start the right solve.', 'حسابك على كيريو بالعربي (حكومي)، بس انت اخترت «لغات». دوس «تعديل الاختيار» واختار «حكومي» عشان يبدأ الحل الصح.'],
  mismatchRetry: ['Edit selection', 'تعديل الاختيار'],
  mismatchClose: ['Dismiss', 'إغلاق'],
  mismatchStatusGov: ['You’re Language Schools but picked Government — hit Edit selection and choose Language Schools.', 'انت لغات لكن مختار حكومي — دوس «تعديل الاختيار» واختار «لغات».'],
  mismatchStatusLang: ['You’re Government but picked Language Schools — hit Edit selection and choose Government.', 'انت حكومي لكن مختار لغات — دوس «تعديل الاختيار» واختار «حكومي».'],
  heroKicker: ['ONE PLATFORM. EVERY COURSE.', 'منصة واحدة. كل الكورسات.'],
  heroLine1: ['Choose it. Solve it.', 'اختارها. حلها.'],
  heroLine2: ['Move forward.', 'وتقدّم للأمام.'],
  heroBody: ['Fast, accurate course completion with a private live feed for every session. No clutter—just the courses that belong to your year.', 'حل سريع ودقيق للكورسات مع نشاط مباشر خاص بكل جلسة. من غير زحمة—بس الكورسات المناسبة لسنتك.'],
  tagActive: ['30 active solvers', '30 حل نشط'],
  tagQueue: ['Smart queue', 'طابور ذكي'],
  tagProgress: ['Live progress', 'تقدم مباشر'],
  startTitle: ['Start a new solve', 'ابدأ حل جديد'],
  startSubtitle: ['Four quick steps. We handle the rest.', 'أربع خطوات سريعة. والباقي علينا.'],
  courseLabel: ['Choose your course', 'اختار الكورس'],
  courseDesc: ['Only courses for your year are shown. Tap the pill above to change school type or year.', 'هتظهر بس الكورسات المناسبة لسنتك. دوس على البطاقة اللي فوق لو عايز تغيّر نوع المدرسة أو السنة.'],
  phoneLabel: ['Phone number', 'رقم الموبايل'],
  phonePlaceholder: ['05xxxxxxxx', '05xxxxxxxx'],
  phoneHint: ['Used only if we need to contact you about your session.', 'هنستخدمه بس لو احتجنا نتواصل معاك بخصوص جلستك.'],
  codeLabel: ['Student ID', 'كود الطالب'],
  codePlaceholder: ['Enter your QUREO student ID', 'اكتب كود الطالب بتاع كيريو'],
  codeHint: ['The student ID assigned to your QUREO account.', 'كود الطالب المخصص لحسابك على كيريو.'],
  passwordLabel: ['Password', 'كلمة السر'],
  passwordPlaceholder: ['Enter your QUREO password', 'اكتب كلمة سر كيريو'],
  passwordHint: ['Your credentials are used only to complete your selected course.', 'بياناتك بتتستخدم بس لإكمال الكورس اللي اخترته.'],
  backButton: ['Back', 'رجوع'],
  nextButton: ['Next', 'التالي'],
  startButton: ['Start solving', 'ابدأ الحل'],
  readyStatus: ['Ready when you are.', 'جاهزين لما تكون جاهز.'],
  privacyNote: ['One active solve per device', 'حل واحد نشط لكل جهاز'],
  progressTitle: ['Live progress', 'التقدم المباشر'],
  progressSubtitle: ['Updates from your current session only.', 'تحديثات من جلستك الحالية بس.'],
  idle: ['Idle', 'متوقف'],
  completedItems: ['Completed items', 'عناصر مكتملة'],
  latestChapter: ['Latest chapter', 'آخر فصل'],
  solverStatus: ['Solver status', 'حالة الحل'],
  activityTitle: ['Activity feed', 'النشاط المباشر'],
  chaptersTitle: ['Chapters', 'الفصول'],
  sessionOnly: ['Your session only', 'جلستك بس'],
  emptyActivity: ['Your session activity will appear here.', 'نشاط جلستك هيظهر هنا.'],
  emptyChapters: ['No progress for this account yet.', 'لسه مفيش تقدم للحساب ده.'],
  footerTagline: ['Less waiting. More learning.', 'انتظار أقل. تعلم أكتر.'],
  stepOf: ['Step {step} of 4', 'الخطوة {step} من 4'],
  courseSelected: ['{course} selected. Click Next to continue.', 'تم اختيار {course}. دوس التالي عشان تكمل.'],
  chooseCourse: ['Choose a course to continue.', 'اختار كورس عشان تكمل.'],
  phoneRequired: ['Enter your phone number first.', 'اكتب رقم موبايلك الأول.'],
  codeRequired: ['Enter your student ID first.', 'اكتب كود الطالب الأول.'],
  passwordRequired: ['Enter your password first.', 'اكتب كلمة السر الأول.'],
  goBackCourse: ['Go back and choose a course first.', 'ارجع واختار الكورس الأول.'],
  joinedSuccess: ['You’re all set. Continue below.', 'تم التفعيل. كمل من تحت.'],
  starting: ['Starting your solve…', 'جارٍ بدء الحل…'],
  started: ['Your solve has started. Watch the live activity below.', 'بدأ الحل. تابع النشاط المباشر تحت.'],
  queueFirst: ['You are number 1 in queue — your solve starts as soon as any request finishes.', 'انت دورك رقم: 1 — هيبدأ الحل أول ما أي طلب يخلص.'],
  queueLater: ['You are number {position} in queue — your solve starts after {remaining} requests.', 'انت دورك رقم: {position} — هيبدأ الحل بعد {remaining} طلبات قبلك.'],
  queueStatus: ['Queue #{position}', 'دورك رقم {position}'],
  solvingNow: ['Solving now', 'يعمل الآن'],
  invalidCredentials: ['Invalid login credentials.', 'بيانات الدخول غير صحيحة.'],
  credentialsTitle: ['Your details are incorrect. Enter the correct ID:', 'معلوماتك غلط! اكتب الكود صح:'],
  credentialCode: ['ID', 'الكود'],
  credentialPassword: ['Password', 'الباسورد'],
  credentialsTrack: ['Are you sure about Government or Language Schools?', 'متاكد حكومي او لغات؟'],
  credentialRetry: ['Start solving now (no queue)', 'أبدا الحل مباشرة (بدون طابور)'],
  rateLimited: ['You’re clicking too quickly — wait 10–20 seconds and try again.', 'انت بتضغط بسرعة ، استني 10-20 ثانية وجرب تاني'],
  connectionSlow: ['Connection is slow — retrying automatically.', 'الاتصال بطيء — بنعيد المحاولة تلقائيًا.'],
  readProgressError: ['Unable to read progress.', 'تعذر قراءة التقدم.'],
  startError: ['Unable to start the solve.', 'تعذر بدء الحل.'],
  serverBusy: ['The server is busy — please try again in a few seconds.', 'السيرفر مشغول — حاول تاني بعد ثواني.'],
  events: ['events', 'أحداث'],
  chapter: ['Chapter', 'الفصل'],
  solved: ['solved', 'تم حله'],
};

function t(key, values = {}) {
  let value = TEXT[key]?.[uiLanguage === 'en' ? 0 : 1] ?? key;
  for (const [name, replacement] of Object.entries(values)) value = value.replaceAll(`{${name}}`, replacement);
  return value;
}

async function readApiJson(response, fallbackKey = 'startError') {
  const body = await response.text();
  const cloudflareRateLimit = /error\s*1015|you are being rate limited/i.test(body)
    || (response.status === 429 && /^\s*</.test(body));
  if (cloudflareRateLimit) {
    const error = new Error(t('rateLimited'));
    error.code = 'RATE_LIMITED';
    throw error;
  }
  try {
    return body ? JSON.parse(body) : {};
  } catch {
    const error = new Error(t(fallbackKey));
    error.code = 'INVALID_RESPONSE';
    throw error;
  }
}

function applyLanguage(forceLang) {
  uiLanguage = forceLang || (selectedTrack === 'language' ? 'en' : 'ar');
  document.documentElement.lang = uiLanguage;
  document.documentElement.dir = uiLanguage === 'ar' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-i18n]').forEach((element) => {
    element.textContent = t(element.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((element) => {
    element.placeholder = t(element.dataset.i18nPlaceholder);
  });
  activitySignature = '';
  chaptersSignature = '';
  renderActivity(lastActivity);
  renderChapters(lastChapters);
  updatePill();
  updateConfirm();
}

function hasValidSelection() {
  return Boolean(COURSES_BY_TRACK[selectedTrack]?.[selectedYear]);
}

function setStatus(message, type = '') {
  statusBox.textContent = message;
  statusBox.className = `status ${type}`;
}

function trackLabel() { return t(selectedTrack === 'language' ? 'trackLang' : 'trackGov'); }
function yearLabel() { return t(selectedYear === 'one' ? 'yearShortOne' : 'yearShortTwo'); }

function updatePill() {
  selectionPill.textContent = hasValidSelection()
    ? `${trackLabel()} · ${yearLabel()} ✎`
    : t('pickTrack');
}

function courseLabelOf(key) {
  for (const track of Object.values(COURSES_BY_TRACK)) {
    for (const year of Object.values(track)) {
      const found = year.find((c) => c.key === key);
      if (found) return found.label;
    }
  }
  return key;
}

function updateConfirm() {
  confirmNote.textContent = (hasValidSelection() && selectedCourse)
    ? t('confirmNote', { course: courseLabelOf(selectedCourse), track: trackLabel(), year: yearLabel() })
    : '';
}

function showStep(n) {
  step = Math.min(Math.max(n, 1), 4);
  document.querySelectorAll('.wizard-step').forEach((el) => {
    el.classList.toggle('active', Number(el.dataset.step) === step);
  });
  stepIndicator.textContent = t('stepOf', { step });
  btnBack.style.display = step === 1 ? 'none' : '';
  btnNext.style.display = step === 4 ? 'none' : '';
  button.style.display = step === 4 ? '' : 'none';
  updateConfirm();
}

function courseIcon(key) {
  if (uiLanguage === 'ar') {
    if (key.startsWith('js')) return 'ج';
    if (key.startsWith('py')) return 'ب';
    return 'ث';
  }
  if (key.startsWith('js')) return 'JS';
  if (key.startsWith('py')) return 'PY';
  return 'FI';
}

function renderCourses() {
  const list = COURSES_BY_TRACK[selectedTrack]?.[selectedYear] || [];
  courseCards.replaceChildren();
  selectedCourse = '';
  for (const course of list) {
    const card = document.createElement('button');
    card.type = 'button';
    card.className = 'course-card';
    card.dataset.course = course.key;
    const icon = document.createElement('span');
    icon.className = 'course-icon';
    icon.textContent = courseIcon(course.key);
    const text = document.createElement('span');
    const title = document.createElement('strong');
    title.textContent = uiLanguage === 'ar' ? (course.labelAr || course.label) : course.label;
    const desc = document.createElement('small');
    desc.textContent = uiLanguage === 'ar' ? (course.descAr || course.desc) : course.desc;
    text.append(title, desc);
    card.append(icon, text);
    card.addEventListener('click', () => {
      courseCards.querySelectorAll('.course-card').forEach((c) => c.classList.remove('selected'));
      card.classList.add('selected');
      selectedCourse = course.key;
      setStatus(t('courseSelected', { course: course.label }), 'success');
      updateConfirm();
    });
    courseCards.appendChild(card);
  }
  updateConfirm();
}

function configureYearModal() {
  const gov = selectedTrack === 'government';
  document.querySelector('#year-kicker').textContent = t(gov ? 'yearKickerGov' : 'yearKickerLang');
  document.querySelector('#year-body').textContent = t(gov ? 'yearBodyGov' : 'yearBodyLang');
  document.querySelector('#year-one-title').textContent = t('yearOne');
  document.querySelector('#year-two-title').textContent = t('yearTwo');
  document.querySelector('#year-one-desc').textContent = t(gov ? 'yearOneGovDesc' : 'yearOneLangDesc');
  document.querySelector('#year-two-desc').textContent = t(gov ? 'yearTwoGovDesc' : 'yearTwoLangDesc');
}

function showSelection() {
  applyLanguage();
  joinModal.classList.add('hidden'); // 👈 تم إضافة هذا السطر لإخفاء نافذة تيليجرام إجباريًا ومنع التداخل
  
  if (hasValidSelection()) {
    categoryModal.classList.add('hidden');
    yearModal.classList.add('hidden');
    renderCourses();
  } else if (!selectedTrack) {
    yearModal.classList.add('hidden');
    categoryModal.classList.remove('hidden');
  } else {
    categoryModal.classList.add('hidden');
    configureYearModal();
    yearModal.classList.remove('hidden');
  }
  updatePill();
  updateConfirm();
}

function persistSelection() {
  storageSession.setItem('qureoTrack', selectedTrack);
  storageSession.setItem('qureoYear', selectedYear);
}

function chooseCategory(track) {
  selectedTrack = track;
  selectedYear = '';
  selectedCourse = '';
  persistSelection();
  showSelection();
}

function chooseYear(year) {
  selectedYear = year;
  selectedCourse = '';
  persistSelection();
  showSelection();
  showStep(1);
}

document.querySelector('#category-government').addEventListener('click', () => chooseCategory('government'));
document.querySelector('#category-language').addEventListener('click', () => chooseCategory('language'));
document.querySelector('#year-one').addEventListener('click', () => chooseYear('one'));
document.querySelector('#year-two').addEventListener('click', () => chooseYear('two'));
document.querySelector('#year-back').addEventListener('click', () => {
  selectedTrack = '';
  selectedYear = '';
  persistSelection();
  showSelection();
});
selectionPill.addEventListener('click', () => categoryModal.classList.remove('hidden'));

btnNext.addEventListener('click', () => {
  if (step === 1) {
    if (!selectedCourse) return setStatus(t('chooseCourse'), 'error');
  } else if (step === 2) {
    if (!document.querySelector('#phone').value.trim()) return setStatus(t('phoneRequired'), 'error');
  } else if (step === 3) {
    if (!document.querySelector('#code').value.trim()) return setStatus(t('codeRequired'), 'error');
  }
  setStatus('');
  showStep(step + 1);
});
btnBack.addEventListener('click', () => showStep(step - 1));

let joinCompleted = storageSession.getItem('qureoJoined') === 'true';
if (joinCompleted) {
  joinModal.classList.add('hidden');
  syncStartButton();
  showSelection();
} else {
  applyLanguage();
}

function completeJoin() {
  joinCompleted = true;
  storageSession.setItem('qureoJoined', 'true');
  joinModal.classList.add('hidden');
  syncStartButton();
  try {
    showSelection();
  } catch {
    categoryModal.classList.remove('hidden');
    yearModal.classList.add('hidden');
  }
  setStatus(t('joinedSuccess'), 'success');
}
joinedButton.addEventListener('click', completeJoin);

function localizeActivityText(rawText) {
  if (uiLanguage !== 'ar') return rawText.replaceAll('المعلومات خاطئة', 'Invalid login credentials');
  let text = rawText.replaceAll('المعلومات خاطئة', 'بيانات الدخول غير صحيحة').replaceAll('Invalid login credentials', 'بيانات الدخول غير صحيحة');
  text = text.replace(/You are number (\d+) in queue — your solve starts after (\d+) requests/, 'انت دورك رقم: $1 — هيبدأ الحل بعد $2 طلبات قبلك');
  text = text.replace('You are number 1 in queue — your solve starts as soon as any request finishes', 'انت دورك رقم: 1 — هيبدأ الحل أول ما أي طلب يخلص');
  return text;
}

function localizeError(message) {
  if (uiLanguage !== 'ar') return message;
  if (message.includes('already have a solve in progress')) return 'عندك حل شغال بالفعل، استنى لما يخلص.';
  if (message.includes('This account already has a solve in progress')) return 'الحساب ده عنده حل شغال بالفعل.';
  if (message.includes('Unable to start')) return t('startError');
  if (message.includes('required')) return 'بيانات ناقصة أو غير صحيحة.';
  if (message.includes('Too many') || message.includes('rate limit')) return 'عدد الطلبات كبير. انتظر قليلًا ثم أعد المحاولة.';
  if (message.includes('browser verification') || message.includes('browser request')) return 'فشل التحقق من المتصفح. أعد المحاولة.';
  if (!/[\u0600-\u06FF]/.test(message)) return 'حصل خطأ غير متوقع أثناء الاتصال بالسيرفر. حاول مرة أخرى.';
  return message;
}

function renderActivity(lines) {
  const signature = JSON.stringify(lines);
  activityCount.textContent = `${lines.length} ${t('events')}`;
  if (signature === activitySignature) return;

  const stickToBottom = !activitySignature || activityBox.scrollHeight - activityBox.scrollTop - activityBox.clientHeight < 45;
  activitySignature = signature;
  activityBox.replaceChildren();

  if (!lines.length) {
    const empty = document.createElement('div');
    empty.className = 'empty compact';
    empty.textContent = t('emptyActivity');
    activityBox.appendChild(empty);
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const rawText of lines) {
    const text = localizeActivityText(rawText);
    const row = document.createElement('div');
    const lower = text.toLowerCase();
    row.className = 'activity-line';
    if (/done|answered|completed|clear|perfect/.test(lower)) row.classList.add('success');
    if (/error|failed|skipped|exception|traceback|خطأ|خاطئة/.test(lower)) row.classList.add('error');
    if (/^(lesson|chapter|course|review)/.test(lower)) row.classList.add('current');
    row.textContent = text;
    fragment.appendChild(row);
  }
  activityBox.appendChild(fragment);
  if (stickToBottom) activityBox.scrollTop = activityBox.scrollHeight;
}

function renderChapters(chapters) {
  const signature = JSON.stringify(chapters);
  if (signature === chaptersSignature) return;
  chaptersSignature = signature;
  chaptersBox.replaceChildren();

  if (!chapters.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = t('emptyChapters');
    chaptersBox.appendChild(empty);
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const item of chapters) {
    const card = document.createElement('div');
    card.className = 'chapter';
    const text = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = `${t('chapter')} ${item.chapter}`;
    const detail = document.createElement('small');
    detail.textContent = item.lessons.join(' · ');
    detail.title = item.lessons.join(' · ');
    text.append(title, detail);
    const count = document.createElement('span');
    count.textContent = `${item.lessons.length} ${t('solved')}`;
    card.append(text, count);
    fragment.appendChild(card);
  }
  chaptersBox.appendChild(fragment);
}

function detectCourseMismatch(activity) {
  const start = Math.max(0, activity.length - 60);
  for (let i = activity.length - 1; i >= start; i--) {
    const line = String(activity[i] || '');
    if (line.includes('COURSE_MISMATCH') || line.includes("reading 'id'") || line.includes('basic_section') || line.includes('course fetch failed')) {
      if (mismatchHandled === line) return;
      mismatchHandled = line;
      solveJustStarted = false;
      const gov = selectedTrack !== 'language';
      document.querySelector('#mismatch-title').textContent = t(gov ? 'mismatchTitleGov' : 'mismatchTitleLang');
      document.querySelector('#mismatch-body').textContent = t(gov ? 'mismatchBodyGov' : 'mismatchBodyLang');
      mismatchModal.classList.remove('hidden');
      setStatus(t(gov ? 'mismatchStatusGov' : 'mismatchStatusLang'), 'error');
      return;
    }
  }
}

document.querySelector('#mismatch-retry').addEventListener('click', () => {
  mismatchModal.classList.add('hidden');
  mismatchHandled = '';
  currentUser = '';
  progressToken = '';
  solveInProgress = false;
  syncStartButton();
  storageLocal.removeItem('qureoUserKey');
  storageLocal.removeItem('qureoProgressToken');
  activitySignature = '';
  chaptersSignature = '';
  selectedCourse = '';
  selectedTrack = '';
  selectedYear = '';
  persistSelection();
  setStatus('');
  showStep(1);
  showSelection();
  refreshProgress();
});
document.querySelector('#mismatch-close').addEventListener('click', () => mismatchModal.classList.add('hidden'));

function updateCredentialsTrack() {
  document.querySelectorAll('[data-credential-track]').forEach((option) => {
    const selected = option.dataset.credentialTrack === credentialsTrack;
    option.classList.toggle('selected', selected);
    option.setAttribute('aria-pressed', String(selected));
  });
}

function equivalentCourseForTrack(track) {
  const kind = selectedCourse.startsWith('js') ? 'js' : selectedCourse.startsWith('py') ? 'py' : 'fin';
  if (kind === 'js') return `${track === 'language' ? 'jslangs' : 'js'}_fast${selectedYear === 'one' ? '_42' : ''}`;
  if (kind === 'py') return track === 'language' ? 'pylangs' : 'pylangs_fast';
  return track === 'language' ? 'sakafa_langs' : 'fin';
}

function showInvalidCredentials() {
  solveJustStarted = false;
  credentialsTrack = selectedTrack || 'government';
  credentialCode.value = document.querySelector('#code').value;
  credentialPassword.value = document.querySelector('#password').value;
  credentialError.textContent = '';
  updateCredentialsTrack();
  setStatus('');
  credentialsModal.classList.remove('hidden');
  requestAnimationFrame(() => {
    credentialCode.focus();
    credentialCode.select();
  });
}

function detectInvalidCredentials(activity) {
  if (!solveJustStarted || JSON.stringify(activity) === solveActivityBaseline) return;
  const start = Math.max(0, activity.length - 60);
  for (let i = activity.length - 1; i >= start; i--) {
    const line = String(activity[i] || '');
    if (/المعلومات\s+(?:خاطئة|خطأ)|invalid credentials|login rejected/i.test(line)) {
      showInvalidCredentials();
      return;
    }
  }
}

function showCredentialError(message) {
  credentialError.textContent = message;
  credentialError.className = 'status error';
}

document.querySelectorAll('[data-credential-track]').forEach((option) => {
  option.addEventListener('click', () => {
    if (startingSolve) return;
    credentialsTrack = option.dataset.credentialTrack;
    updateCredentialsTrack();
  });
});

document.querySelector('#credentials-close').addEventListener('click', () => {
  if (startingSolve) return;
  credentialsModal.classList.add('hidden');
  credentialError.textContent = '';
});

document.querySelector('#credentials-form').addEventListener('submit', (event) => {
  event.preventDefault();
  if (startingSolve) return;
  const code = credentialCode.value.trim();
  const password = credentialPassword.value;
  if (!code) return showCredentialError(t('codeRequired'));
  if (!password) return showCredentialError(t('passwordRequired'));

  document.querySelector('#code').value = code;
  document.querySelector('#password').value = password;
  if (credentialsTrack !== selectedTrack) {
    const nextCourse = equivalentCourseForTrack(credentialsTrack);
    selectedTrack = credentialsTrack;
    selectedCourse = nextCourse;
    persistSelection();
    applyLanguage();
    renderCourses();
    selectedCourse = nextCourse;
    const card = [...courseCards.querySelectorAll('.course-card')].find((item) => item.dataset.course === nextCourse);
    if (card) card.classList.add('selected');
    updateConfirm();
  }
  void startSolve();
});

function syncStartButton() {
  button.disabled = startingSolve || solveInProgress || !joinCompleted;
  credentialRetry.disabled = startingSolve || solveInProgress;
}

async function refreshProgress() {
  if (refreshing) return;
  if (!currentUser) {
    solveInProgress = false;
    syncStartButton();
    document.querySelector('#completed-count').textContent = '0';
    document.querySelector('#last-chapter').textContent = '—';
    document.querySelector('#running').textContent = t('idle');
    runningBadge.textContent = t('idle');
    runningBadge.classList.remove('active');
    lastActivity = [];
    lastChapters = [];
    renderActivity(lastActivity);
    renderChapters(lastChapters);
    return;
  }

  refreshing = true;
  try {
    const response = await fetchWithTimeout(`${API_BASE}/api/progress?user=${encodeURIComponent(currentUser)}`, {
      cache: 'no-store',
      credentials: 'same-origin',
      headers: { ...BROWSER_HEADERS, 'X-Progress-Token': progressToken },
    });
    const data = await readApiJson(response, 'readProgressError');
    if (response.status === 401) {
      currentUser = '';
      progressToken = '';
      solveInProgress = false;
      syncStartButton();
      storageLocal.removeItem('qureoUserKey');
      storageLocal.removeItem('qureoProgressToken');
      throw new Error(uiLanguage === 'ar' ? 'انتهت جلسة المتابعة. ابدأ الحل مرة أخرى.' : 'Your progress session expired. Start the solve again.');
    }
    if (!response.ok) throw new Error(data.error || t('readProgressError'));
    if (progressFailures >= 10 || rateLimitedUntil) setStatus('');
    progressFailures = 0;
    rateLimitedUntil = 0;
    document.querySelector('#completed-count').textContent = data.completed_count;
    document.querySelector('#last-chapter').textContent = data.last_chapter || '—';
    const queued = Boolean(data.queued);
    solveInProgress = queued || Boolean(data.running);
    syncStartButton();
    lastQueued = queued;
    const queuePosition = data.queue_position || 0;
    document.querySelector('#running').textContent = queued ? t('queueStatus', { position: queuePosition }) : data.running ? t('solvingNow') : t('idle');
    runningBadge.textContent = queued ? `● ${t('queueStatus', { position: queuePosition })}` : data.running ? (uiLanguage === 'ar' ? '● مباشر' : '● Live') : t('idle');
    runningBadge.classList.toggle('active', data.running || queued);
    const activity = Array.isArray(data.activity) ? data.activity : [];
    lastActivity = activity;
    lastChapters = Array.isArray(data.chapters) ? data.chapters : [];
    renderActivity(activity);
    detectInvalidCredentials(activity);
    detectCourseMismatch(activity);
    renderChapters(Array.isArray(data.chapters) ? data.chapters : []);
  } catch (error) {
    if (error.code === 'RATE_LIMITED') {
      progressFailures = 0;
      rateLimitedUntil = Date.now() + 20000;
      setStatus(t('rateLimited'), 'error');
    } else {
      progressFailures += 1;
      if (progressFailures >= 10) setStatus(t('connectionSlow'), 'error');
    }
  } finally {
    refreshing = false;
  }
}

async function postSolve(payload) {
  let lastError;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const response = await fetchWithTimeout(`${API_BASE}/api/solve`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', ...BROWSER_HEADERS },
        body: JSON.stringify(payload),
      });
      const data = await readApiJson(response);
      if ((response.status === 409 || response.status === 429) && data.user_key) {
        return { data, already: true };
      }
      if (!response.ok) throw new Error(data.error || t('startError'));
      return { data, already: false };
    } catch (error) {
      if (error.code === 'RATE_LIMITED') throw error;
      lastError = error;
      if (attempt === 0) await new Promise(resolve => setTimeout(resolve, 750));
    }
  }
  throw lastError;
}

async function startSolve() {
  if (startingSolve || solveInProgress) return;
  if (!selectedCourse) return setStatus(t('goBackCourse'), 'error');
  if (!document.querySelector('#password').value) return setStatus(t('passwordRequired'), 'error');
  startingSolve = true;
  button.disabled = true;
  credentialRetry.disabled = true;
  setStatus(t('starting'));
  if (!credentialsModal.classList.contains('hidden')) {
    credentialError.textContent = t('starting');
    credentialError.className = 'status';
  }
  const payload = {
    phone: document.querySelector('#phone').value.trim(),
    code: document.querySelector('#code').value.trim(),
    password: document.querySelector('#password').value,
    course: selectedCourse,
    chapter: null,
    fingerprint: deviceFp,
  };
  try {
    const { data, already } = await postSolve(payload);
    currentUser = data.user_key;
    progressToken = String(data.progress_token || '');
    if (!currentUser || !progressToken) throw new Error(t('startError'));
    solveInProgress = true;
    syncStartButton();
    storageLocal.setItem('qureoUserKey', currentUser);
    storageLocal.setItem('qureoProgressToken', progressToken);
    activitySignature = '';
    mismatchHandled = '';
    mismatchModal.classList.add('hidden');
    credentialsModal.classList.add('hidden');
    credentialError.textContent = '';
    solveActivityBaseline = JSON.stringify(lastActivity);
    solveJustStarted = true;
    lastQueued = Boolean(data.queued);
    document.querySelector('#running').textContent = lastQueued ? t('queueStatus', { position: data.queue_position || 1 }) : t('solvingNow');
    runningBadge.textContent = lastQueued ? `● ${t('queueStatus', { position: data.queue_position || 1 })}` : (uiLanguage === 'ar' ? '● مباشر' : '● Live');
    runningBadge.classList.add('active');
    if (already) {
      setStatus(uiLanguage === 'ar' ? 'عندك حل شغال بالفعل — بنتابع نفس الجلسة.' : 'A solve is already running — following the same session.', 'success');
    } else if (data.queued) {
      setStatus(data.queue_position > 1 ? t('queueLater', { position: data.queue_position, remaining: data.queue_position - 1 }) : t('queueFirst'), 'success');
    } else {
      setStatus(t('started'), 'success');
    }
    void refreshProgress();
  } catch (error) {
    const message = error.name === 'AbortError' ? t('serverBusy') : localizeError(error.message);
    if (error.code === 'RATE_LIMITED') rateLimitedUntil = Date.now() + 20000;
    setStatus(message, 'error');
    if (!credentialsModal.classList.contains('hidden')) showCredentialError(message);
    solveInProgress = false;
    syncStartButton();
  } finally {
    startingSolve = false;
    syncStartButton();
  }
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  void startSolve();
});

async function progressLoop() {
  await refreshProgress();
  const normalDelay = lastQueued ? 10000 : 5000;
  setTimeout(progressLoop, Math.max(normalDelay, rateLimitedUntil - Date.now()));
}

showStep(1);
progressLoop();
}

function initBrowserVerification() {
  document.title = 'التحقق من المتصفح · QUREO';
  const status = document.querySelector('#browser-verify-status');
  const retry = document.querySelector('#browser-verify-retry');
  let running = false;

  async function verify(manual = false) {
    if (running) return;
    const loops = Number(storageSession.getItem('qureoVerifyLoops') || '0');
    if (!manual && loops >= 2) {
      status.textContent = 'التحقق يحتاج تفعيل ملفات تعريف الارتباط (Cookies). فعّلها ثم اضغط إعادة المحاولة.';
      return;
    }
    running = true;
    retry.disabled = true;
    status.textContent = 'جارٍ التحقق من متصفحك… لن يستغرق هذا سوى ثوانٍ.';
    if (!manual) storageSession.setItem('qureoVerifyLoops', String(loops + 1));
    try {
      const proof = await getBrowserProof('public');
      const response = await fetchWithTimeout(`${API_BASE}/api/browser/verify`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', ...BROWSER_HEADERS },
        body: JSON.stringify(proof),
        cache: 'no-store',
      });
      const text = await response.text();
      let data = {};
      try { data = text ? JSON.parse(text) : {}; } catch { data = {}; }
      if (!response.ok || !data.ok) throw new Error(data.error || 'الوصول مرفوض: رمز التحقق غير صالح أو منتهي.');
      storageSession.removeItem('qureoVerifyLoops');
      status.textContent = 'تم التحقق بنجاح. جارٍ فتح الموقع…';
      location.replace('/');
    } catch (error) {
      status.textContent = 'تعذر إكمال التحقق تلقائيًا. اضغط إعادة المحاولة.';
    } finally {
      running = false;
      retry.disabled = false;
    }
  }

  retry.addEventListener('click', () => void verify(true));
  void verify();
}

function initVip0101() {
  document.title = 'QUREO VIP · لوحة الحل الخاصة';
  const $ = (selector) => document.querySelector(selector);
  const gate = $('#vip-gate');
  const dashboard = $('#vip-dashboard');
  const loginButton = $('#vip-login-button');
  const startButton = $('#vip-start-button');
  const solveMessage = $('#vip-solve-message');
  const accountMessage = $('#vip-account-message');
  const courses = {
    gov: [
      ['gov_js1', 'جافاسكربت أولى — 42 فصل'],
      ['gov_js2', 'جافاسكربت تانية — الكورس كامل'],
      ['gov_py', 'بايثون — حكومي'],
      ['gov_fin', 'ثقافة مالية — حكومي'],
      ['gov_all', '⚡ الكل: ثقافة + بايثون + جافاسكربت'],
    ],
    lang: [
      ['lang_js1', 'جافاسكربت أولى لغات — 42 فصل'],
      ['lang_js2', 'جافاسكربت تانية لغات — الكورس كامل'],
      ['lang_py', 'بايثون — لغات'],
      ['lang_fin', 'ثقافة مالية — لغات'],
      ['lang_all', '⚡ الكل: ثقافة + بايثون + جافاسكربت'],
    ],
  };
  const state = {
    csrf: '',
    account: null,
    track: 'gov',
    runs: [],
    selectedRun: '',
    refreshing: false,
    starting: false,
  };

  function authPayload(extra = {}) {
    return { ...extra };
  }

  async function api(action, payload) {
    const response = await fetchWithTimeout(`${API_BASE}/api/vip0101/${action}`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        ...BROWSER_HEADERS,
        ...(state.csrf ? { 'X-CSRF-Token': state.csrf } : {}),
      },
      body: JSON.stringify(payload),
      cache: 'no-store',
    });
    const text = await response.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch { data = { ok: false, error: 'رد غير صالح من السيرفر' }; }
    return { status: response.status, data };
  }

  async function restoreSession() {
    try {
      const response = await fetchWithTimeout(`${API_BASE}/api/vip0101/session`, {
        credentials: 'same-origin',
        headers: BROWSER_HEADERS,
        cache: 'no-store',
        });
      const text = await response.text();
      const data = text ? JSON.parse(text) : {};
      if (!response.ok || !data.ok) return clearSession();
      state.csrf = data.csrf;
      showWorkspace(data.account);
      await refresh();
    } catch {
      clearSession('تعذر استعادة الجلسة. ادخل مرة أخرى.');
    }
  }

  function message(element, text = '', isError = false) {
    element.textContent = text;
    element.classList.toggle('vip-error', isError);
  }

  function friendlyError(error) {
    const text = String(error || 'حصل خطأ، حاول تاني.');
    if (text.includes('running limit reached')) {
      const match = text.match(/\((\d+)/);
      return `وصلت للحد المسموح: ${match ? match[1] : ''} حلول في نفس الوقت. استنى واحدة تخلص.`;
    }
    if (text.includes('already running')) return 'الحساب والكورس دول عندهم حل شغال بالفعل.';
    if (text.includes('wrong password')) return 'كلمة سر حساب VIP غير صحيحة.';
    if (text.includes('already in use')) return 'كلمة السر دي مستخدمة في حساب VIP تاني.';
    if (text.includes('max_running')) return 'أقصى تشغيل لازم يكون رقم من 1 إلى 60.';
    if (text.includes('running jobs before deleting')) return 'مينفعش تمسح الحساب وهو عنده حلول شغالة.';
    if (!/[\u0600-\u06FF]/.test(text)) return 'حصل خطأ أثناء الاتصال بالسيرفر. حاول مرة أخرى.';
    return text;
  }

  function showWorkspace(account) {
    state.account = account;
    gate.classList.add('vip-hidden');
    dashboard.classList.remove('vip-hidden');
    $('#vip-account-chip').textContent = account.name;
    $('#vip-admin-panel').classList.toggle('vip-hidden', !account.admin);
    $('#vip-role-label').textContent = account.admin ? 'MAIN ADMIN · FULL ACCESS' : 'VIP WORKSPACE · PRIVATE ACCESS';
    $('#vip-runs-title').textContent = account.admin ? 'كل العمليات الحالية' : 'عملياتك الحالية';
    $('#vip-runs-subtitle').textContent = account.admin
      ? 'كل حسابات VIP والعمليات — بدون عرض أو تخزين كلمات سر الطلاب.'
      : 'آخر العمليات والنشاط الخاص بحسابك فقط.';
    $('#vip-limit-note').textContent = account.admin
      ? 'إدارة كاملة لكل الحسابات والحلول، مع إمكانية إنشاء حسابات VIP مستقلة.'
      : `الحد الحالي: ${account.max_running} حلول في نفس الوقت · التشغيل فوري وبدون طابور.`;
  }

  function clearSession(error = '') {
    state.csrf = '';
    state.account = null;
    state.runs = [];
    state.selectedRun = '';
    dashboard.classList.add('vip-hidden');
    gate.classList.remove('vip-hidden');
    $('#vip-login-key').value = '';
    message($('#vip-login-error'), error, Boolean(error));
  }

  function renderCourses() {
    const select = $('#vip-course');
    select.replaceChildren();
    for (const [value, label] of courses[state.track]) {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = label;
      select.appendChild(option);
    }
  }

  function statusOf(run) {
    if (run.running) return { className: 'vip-running', label: '● شغال الآن' };
    if (run.exit === 0) return { className: 'vip-done', label: 'مكتمل ✓' };
    return { className: 'vip-failed', label: 'متوقف' };
  }

  function updateLog() {
    const run = state.runs.find((item) => item.id === state.selectedRun);
    const log = $('#vip-log');
    if (!run) {
      $('#vip-log-title').textContent = 'النشاط المباشر';
      log.textContent = state.runs.length ? 'اختار عملية من القائمة لعرض النشاط…' : 'ابدأ عملية أو اختار واحدة من القائمة عشان تشوف النشاط هنا…';
      return;
    }
    $('#vip-log-title').textContent = `${run.username} · ${run.display}`;
    const stickToBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 55;
    log.textContent = (run.logs || []).jo
