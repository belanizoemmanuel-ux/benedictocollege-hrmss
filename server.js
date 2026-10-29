require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');

const app = express();
app.set('trust proxy', 1); // Render runs behind a proxy

// True if the string already looks like a bcrypt hash
function isHashed(str) {
  return /^\$2[aby]\$\d{2}\$/.test(String(str || ''));
}

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error('❌ JWT_SECRET is missing or too short (use 32+ chars).');
  process.exit(1);
}

app.use(helmet({ contentSecurityPolicy: false }));

// ── CORS: only your own sites ──
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://hrbenedicto.com,https://www.hrbenedicto.com')
  .split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => (!origin || allowedOrigins.includes(origin))
    ? cb(null, true) : cb(new Error('Not allowed by CORS')),
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '15mb' }));

// ── Serve ONLY the public folder (never the whole project) ──
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));
app.use('/public', express.static(PUBLIC_DIR));

// ═══════════ AUTH + ROLE PROTECTION ═══════════
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' } });
app.use('/api/auth/login', loginLimiter);

function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Only these routes work without a token
const PUBLIC_PATHS = ['/time', '/auth/login'];
app.use('/api', (req, res, next) => PUBLIC_PATHS.includes(req.path) ? next() : requireAuth(req, res, next));

// Routes an employee may call. Everything else is admin-only.
const EMPLOYEE_ROUTES = [
  ['GET',  /^\/employees$/],
  ['PUT',  /^\/employees\/[^/]+$/],
  ['GET',  /^\/announcements$/],
  ['GET',  /^\/leave-requests$/],
  ['POST', /^\/leave-requests\/submit$/],
  ['GET',  /^\/complaints$/],
  ['POST', /^\/complaints$/],
  ['GET',  /^\/attendance$/],
  ['GET',  /^\/attendance\/status-today$/],
  ['POST', /^\/attendance\/time-in$/],
  ['POST', /^\/attendance\/time-out$/],
  ['GET',  /^\/attendance\/employee\/[^/]+\/[^/]+$/],
  ['GET',  /^\/reports$/],
  ['POST', /^\/auth\/change-password$/]
];

app.use('/api', async (req, res, next) => {
  if (PUBLIC_PATHS.includes(req.path) || req.user.role === 'admin') return next();
  try {
    const m = req.method, p = req.path;
    if (!EMPLOYEE_ROUTES.some(([method, rx]) => method === m && rx.test(p))) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    const account = await User.findById(req.user.id);
    const me = account && await Employee.findOne({ email: emailMatch(account.email) });
    if (!me) return res.status(403).json({ error: 'Employee record not found or deactivated' });

    // keep only the caller's own rows in any list response
    const only = fn => { const j = res.json.bind(res); res.json = d => j(Array.isArray(d) ? d.filter(fn) : d); };
    const mine = v => String(v || '').trim().toLowerCase() === me.email.trim().toLowerCase();

    if (m === 'GET' && p === '/employees') return res.json([me]);
    if (m === 'PUT' && /^\/employees\/[^/]+$/.test(p)) {
      if (p.split('/')[2] !== me.id) return res.status(403).json({ error: 'You can only edit your own profile' });
      const SAFE = ['first', 'middle', 'last', 'dob', 'gender', 'phone', 'photo']; // no salary/position/department/email
      req.body = Object.fromEntries(SAFE.filter(k => k in (req.body || {})).map(k => [k, req.body[k]]));
    }
    if (m === 'GET' && p === '/leave-requests') only(l => mine(l.email));
    if (m === 'POST' && p === '/leave-requests/submit') {
      req.body.email = me.email; req.body.name = `${me.first} ${me.last}`; req.body.dept = me.department;
    }
    if (m === 'GET' && p === '/complaints') only(c => mine(c.employee));
    if (m === 'POST' && p === '/complaints') {
      const b = req.body || {};
      req.body = { subject: b.subject, priority: b.priority, date: b.date, status: 'Pending', employee: me.email };
    }
    if (m === 'GET' && (p === '/attendance' || p === '/attendance/status-today')) only(l => l.employeeId === me.id);
    if (m === 'GET' && p === '/reports') only(r => r.employeeId === me.id);
    if ((m === 'POST') && (p === '/attendance/time-in' || p === '/attendance/time-out')) req.body.employeeId = me.id;
    if (m === 'GET' && p.startsWith('/attendance/employee/') && p.split('/')[3] !== me.id) {
      return res.status(403).json({ error: 'Not your attendance records' });
    }
    next();
  } catch (err) {
    console.error('Scope error:', err.message);
    res.status(500).json({ error: 'Authorization failed' });
  }
});

// Change your own password (works for admin and employees)
app.post('/api/auth/change-password', async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (String(newPassword || '').length < 10) return res.status(400).json({ error: 'New password must be at least 10 characters' });
    const user = await User.findById(req.user.id);
    if (!user || !(await bcrypt.compare(String(currentPassword || ''), user.password))) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to change password' }); }
});
// ═══════════ END AUTH BLOCK ═══════════
// ─────────────────────────────────────
const DB_NAME = 'HR-Admin-Database';

console.log('MongoDB URI exists:', !!process.env.MONGODB_URI);

if (!process.env.MONGODB_URI) {
  console.error('❌ MONGODB_URI is missing from your .env file.');
  console.error('   Create a .env file in this same folder with:');
  console.error('   MONGODB_URI=mongodb://localhost:27017/HR-Admin-Database');
  console.error('   Or use your MongoDB Atlas connection string.');
  console.error('   Server will start, but data features will not work without a database.');
}

mongoose.connect(process.env.MONGODB_URI || '', {
  serverSelectionTimeoutMS: 10000
})
.then(() => {
  console.log(`✅ MongoDB Connected: ${DB_NAME}`);
})
.catch((error) => {
  console.error('❌ MongoDB Connection Error:', error.message);
  console.log('⚠️  Running without database — APIs will return errors.');
});

// ─── Schemas ───
// Generates an easy-to-remember password: Word + 4-digit number (8+ chars)
const PASSWORD_WORDS = ['Sunny','Happy','Eagle','Tiger','River','Cloud','Maple','Coral','Amber','Comet','Delta','Ember','Falcon','Grove','Harbor','Ivory','Jolly','Koala','Lemon','Mango','Nova','Ocean','Pearl','Quartz','Ridge','Storm','Talon','Unity','Violet'];
function generateEasyPassword() {
  const letters = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz';
  const digits = '23456789';
  const all = letters + digits;
  const pick = s => s[Math.floor(Math.random() * s.length)];
  const chars = [pick(letters), pick(digits)];
  while (chars.length < 8) chars.push(pick(all));
  return chars.sort(() => Math.random() - 0.5).join('');
}

// "8:05 AM" -> 8.083 (for comparing biometric times against cutoffs)
function parseTimeToHourFloat(str) {
  const m = String(str).trim().match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
  if (!m) return 0;
  let h = parseInt(m[1], 10);
  const min = parseInt(m[2], 10);
  const ampm = m[3].toUpperCase();
  if (ampm === 'PM' && h !== 12) h += 12;
  if (ampm === 'AM' && h === 12) h = 0;
  return h + min / 60;
}

// ─── Philippine Time (Asia/Manila) — never depends on any laptop or server timezone ───
function manilaNow() {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Manila', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false
  }).formatToParts(new Date());
  const p = {};
  parts.forEach(x => { p[x.type] = x.value; });
  const hour = parseInt(p.hour, 10) % 24;
  const minute = parseInt(p.minute, 10);
  const h12 = hour % 12 || 12;
  return {
    date: `${p.year}-${p.month}-${p.day}`,
    hour, minute,
    hourFloat: hour + minute / 60,
    timeStr: `${h12}:${p.minute} ${hour >= 12 ? 'PM' : 'AM'}`
  };
}

// Clients sync their clock from here
app.get('/api/time', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ serverMs: Date.now(), ...manilaNow() });
});

const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  role: {
    type: String,
    enum: ['admin', 'employee']
  },
  phone: String,
  position: String,
  photo: String
}));

const Employee = mongoose.model('Employee', new mongoose.Schema({
  id: String, first: String, middle: String, last: String,
  dob: String, gender: String, position: String, department: String,
  dateHired: String, salary: String, status: String, type: String,
  email: String, phone: String, regularization: String, yearsOfService: Number,
  resignDate: String,
  leaveBalance: { type: Number, default: 15 },
  sss: String,
  philhealth: String,
  pagibig: String,
  pin: String,
  duties: String,
  photo: String
}));

const Separated = mongoose.model('Separated', new mongoose.Schema({
  id: String, first: String, middle: String, last: String,
  dob: String, gender: String, position: String, department: String,
  dateHired: String, salary: String, status: String, type: String,
  email: String, phone: String, regularization: String, yearsOfService: Number,
  resignDate: String, resignedBy: String,
  leaveBalance: Number,
  sss: String, philhealth: String, pagibig: String, pin: String,
  duties: String, photo: String
}));

const Department = mongoose.model('Department', new mongoose.Schema({
  name: String, count: Number, detail: String, status: String, group: String, head: String
}));

const LeaveRequest = mongoose.model('LeaveRequest', new mongoose.Schema({
  id: Number, name: String, email: String, dept: String, type: String, dates: String, reason: String, status: String,
  daysRequested: { type: Number, default: 1 }
}));

const Complaint = mongoose.model('Complaint', new mongoose.Schema({
  subject: String, date: String, priority: String, status: String, employee: String, reply: String
}));

const AttendanceLog = mongoose.model('AttendanceLog', new mongoose.Schema({
  employeeId: String, name: String, department: String,
  date: String, timeIn: String, timeOut: String, status: String,
  source: { type: String, default: 'Manual' }
}));

const Announcement = mongoose.model('Announcement', new mongoose.Schema({
  title: String, meta: String, when: String, icon: String, color: String, bg: String
}));

const Activity = mongoose.model('Activity', new mongoose.Schema({
  icon: String, text: String, when: String
}));

const Report = mongoose.model('Report', new mongoose.Schema({
  employeeId: String,
  employeeName: String,
  department: String,
  period: String,
  evaluationDate: String,
  overallRating: { type: Number, min: 1, max: 5 },
  categories: [{
    name: String,
    rating: { type: Number, min: 1, max: 5 },
    comment: String
  }],
  strengths: String,
  improvements: String,
  goals: String,
  evaluator: String,
  status: { type: String, enum: ['Draft', 'Finalized'], default: 'Draft' },
  attendanceSummary: {
    attendanceRate: Number,
    punctualityRate: Number,
    present: Number,
    late: Number,
    absent: Number,
    totalDays: Number
  }
}));

// ─── Seed Data ───
async function seed() {
  try {
    const userCount = await User.countDocuments();
    if (userCount === 0) {
      await User.insertMany([
      { name: 'HR Admin', email: 'admin@benedicto.edu', password: bcrypt.hashSync(process.env.ADMIN_INITIAL_PASSWORD || require('crypto').randomBytes(12).toString('hex'), 12), role: 'admin', phone: '0917-555-0000', position: 'HR Manager' },
      { name: 'Emma Santos', email: 'emma.santos@benedicto.edu', password: bcrypt.hashSync(process.env.EMPLOYEE_INITIAL_PASSWORD || require('crypto').randomBytes(12).toString('hex'), 12), role: 'employee' }
      ]);
      console.log('✅ Default users created');
    }

    const empCount = await Employee.countDocuments();
    if (empCount === 0) {
      await Employee.insertMany([
        { id: 'BC-2023-001', first: 'Emma', middle: 'R', last: 'Santos', dob: '1992-03-11', gender: 'Female', position: 'Librarian', department: 'Arts and Science Department', dateHired: '2019-08-01', salary: 'SG-10', status: 'Active', type: 'Regular', email: 'emma.santos@benedicto.edu', phone: '0917-555-0101', leaveBalance: 15, sss: '34-1234567-8', philhealth: '12-345678901-2', pagibig: '1234-5678-9012', pin: '2023001', duties: 'Manages library operations, cataloging, and student research assistance.' },
        { id: 'BC-2023-002', first: 'Carlos', middle: 'D', last: 'Reyes', dob: '1988-11-22', gender: 'Male', position: 'Library Assistant', department: 'Arts and Science Department', dateHired: '2021-02-15', salary: 'SG-6', status: 'Active', type: 'Regular', email: 'carlos.reyes@benedicto.edu', phone: '0917-555-0102', leaveBalance: 10, sss: '34-7654321-0', philhealth: '12-987654321-0', pagibig: '9876-5432-1098', pin: '2023002', duties: 'Assists with circulation desk, shelving, and library inventory.' },
        { id: 'BC-2023-003', first: 'Maria', middle: 'L', last: 'Cruz', dob: '1985-06-30', gender: 'Female', position: 'Registrar Officer', department: 'Education Department', dateHired: '2017-01-10', salary: 'SG-11', status: 'Active', type: 'Regular', email: 'maria.cruz@benedicto.edu', phone: '0917-555-0103', leaveBalance: 12, sss: '34-1111111-1', philhealth: '12-111111111-1', pagibig: '1111-1111-1111', pin: '2023003', duties: 'Handles student records, enrollment, and academic documentation.' },
        { id: 'BC-2023-004', first: 'Jose', middle: 'P', last: 'Villanueva', dob: '1990-09-05', gender: 'Male', position: 'Accountant', department: 'Business and Accountancy Department', dateHired: '2020-05-18', salary: 'SG-12', status: 'On Leave', type: 'Regular', email: 'jose.v@benedicto.edu', phone: '0917-555-0104', leaveBalance: 8, sss: '34-2222222-2', philhealth: '12-222222222-2', pagibig: '2222-2222-2222', pin: '2023004', duties: 'Oversees payroll, budgeting, and financial reporting for the department.' },
        { id: 'BC-2023-005', first: 'Wilma', middle: 'S', last: 'Mondragon', dob: '1990-05-15', gender: 'Female', position: 'Instructor', department: 'Business and Accountancy Department', dateHired: '2020-04-12', salary: 'SG-12', status: 'Active', type: 'Regular', email: 'wilma.m@benedicto.edu', phone: '0917-123-4567', leaveBalance: 15, sss: '34-3333333-3', philhealth: '12-333333333-3', pagibig: '3333-3333-3333', pin: '2023005', duties: 'Teaches business subjects and mentors student org activities.' },
        { id: 'BC-2023-006', first: 'Anton', middle: 'F', last: 'Bautista', dob: '1993-01-19', gender: 'Male', position: 'IT Support', department: 'IT Department', dateHired: '2022-03-01', salary: 'SG-9', status: 'Active', type: 'Contractual', email: 'anton.b@benedicto.edu', phone: '0917-555-0106', leaveBalance: 5, sss: '34-4444444-4', philhealth: '12-444444444-4', pagibig: '4444-4444-4444', pin: '2023006', duties: 'Maintains campus network, hardware, and staff technical support.' },
        { id: 'BC-2023-007', first: 'Lorna', middle: 'T', last: 'Del Rosario', dob: '1989-04-12', gender: 'Female', position: 'Secretary', department: 'Education Department', dateHired: '2018-03-15', salary: 'SG-8', status: 'Active', type: 'Regular', email: 'lorna.d@benedicto.edu', phone: '0917-555-0107', leaveBalance: 10, sss: '34-5555555-5', philhealth: '12-555555555-5', pagibig: '5555-5555-5555', pin: '2023007', duties: 'Handles department correspondence, scheduling, and filing.' },
        { id: 'BC-2023-008', first: 'Ricardo', middle: 'L', last: 'Fernandez', dob: '1987-08-22', gender: 'Male', position: 'Engineering Instructor', department: 'Engineering Department', dateHired: '2019-06-10', salary: 'SG-13', status: 'Active', type: 'Regular', email: 'ricardo.f@benedicto.edu', phone: '0917-555-0108', leaveBalance: 14, sss: '34-6666666-6', philhealth: '12-666666666-6', pagibig: '6666-6666-6666', pin: '2023008', duties: 'Teaches engineering courses and supervises laboratory work.' },
        { id: 'BC-2023-009', first: 'Sarah', middle: 'J', last: 'Lim', dob: '1991-12-05', gender: 'Female', position: 'Nursing Instructor', department: 'Arts and Science Department', dateHired: '2021-01-20', salary: 'SG-13', status: 'Active', type: 'Regular', email: 'sarah.l@benedicto.edu', phone: '0917-555-0109', leaveBalance: 12, sss: '34-7777777-7', philhealth: '12-777777777-7', pagibig: '7777-7777-7777', pin: '2023009', duties: 'Teaches nursing subjects and supervises clinical training.' },
                { id: 'BC-2023-010', first: 'Mark', middle: 'A', last: 'Tan', dob: '1994-04-18', gender: 'Male', position: 'SHS Teacher', department: 'Education Department', dateHired: '2022-06-01', salary: 'SG-9', status: 'Active', type: 'Regular', email: 'mark.t@benedicto.edu', phone: '0917-555-0110', leaveBalance: 10, sss: '34-8888888-8', philhealth: '12-888888888-8', pagibig: '8888-8888-8888', pin: '2023010', duties: 'Teaches senior high school subjects and advises a section.' },
        { id: 'BC-2023-011', first: 'Ramon', middle: 'D', last: 'Torres', dob: '1980-07-09', gender: 'Male', position: 'Maintenance Head', department: 'Facilities', dateHired: '2016-09-01', salary: 'SG-6', status: 'Active', type: 'Regular', email: 'ramon.t@benedicto.edu', phone: '0917-555-0111', leaveBalance: 15, sss: '34-9999999-9', philhealth: '12-999999999-9', pagibig: '9999-9999-9999', pin: '2023011', duties: 'Oversees campus maintenance, repairs, and custodial operations.' },
        { id: 'BC-2023-012', first: 'Pedro', middle: 'M', last: 'Aquino', dob: '1991-02-27', gender: 'Male', position: 'Janitor', department: 'Facilities', dateHired: '2021-04-05', salary: 'SG-2', status: 'Active', type: 'Regular', email: 'pedro.a@benedicto.edu', phone: '0917-555-0112', leaveBalance: 15, sss: '34-1010101-0', philhealth: '12-101010101-0', pagibig: '1010-1010-1010', pin: '2023012', duties: 'Performs daily cleaning and upkeep of campus facilities.' }
      ]);
      console.log('✅ Employees seeded');
    }

    
    const desiredDepartments = [
      { name: 'Tourism Department', detail: 'Tourism Management, Hospitality, Culinary Arts', status: 'Active', group: 'academic', head: 'Not Assigned' },
      { name: 'Information Technology Department', detail: 'Information Technology, Computer Science, Animation, Multimedia', status: 'Active', group: 'academic', head: 'Not Assigned' },
      { name: 'Accountancy Department', detail: 'Accountancy, Management Accounting, Internal Auditing', status: 'Active', group: 'academic', head: 'Not Assigned' },
      { name: 'Business Department', detail: 'Business Administration, Marketing, HRM, Entrepreneurship', status: 'Active', group: 'academic', head: 'Not Assigned' },
      { name: 'Engineering Department', detail: 'Industrial, Mechanical, Civil, Electrical, Electronics Engineering', status: 'Active', group: 'academic', head: 'Not Assigned' },
      { name: 'Educational Department', detail: 'Elementary Education, Secondary Education, Early Childhood', status: 'Active', group: 'academic', head: 'Not Assigned' }
    ];
            // Only create the default departments on a brand-new database
    if ((await Department.countDocuments()) === 0) {
      for (const dept of desiredDepartments) {
        await Department.updateOne(
          { name: dept.name },
          { $set: { detail: dept.detail, group: 'academic' }, $setOnInsert: { name: dept.name, count: 0, status: dept.status, head: dept.head } },
          { upsert: true }
        );
      }
    }
    

    // Auto-register any employee department not already tracked, as an
    // administrative/support unit.
    const academicNames = desiredDepartments.map(d => d.name);
    const distinctEmpDepts = await Employee.distinct('department');
    for (const deptName of distinctEmpDepts) {
      if (!deptName || academicNames.includes(deptName)) continue;
      await Department.updateOne(
        { name: deptName },
        { $set: { group: 'admin' }, $setOnInsert: { name: deptName, count: 0, detail: 'Administrative / Support Unit', status: 'Active', head: 'Not Assigned' } },
        { upsert: true }
      );
    }
    // Make sure any pre-existing dept doc without a group tag gets one.
    const untagged = await Department.find({ group: { $exists: false } });
    for (const d of untagged) {
      d.group = academicNames.includes(d.name) ? 'academic' : 'admin';
      await d.save();
    }

    const leaveCount = await LeaveRequest.countDocuments();
    if (leaveCount === 0) {
      await LeaveRequest.insertMany([
        { id: 1, name: 'Emma Santos', email: 'emma.santos@benedicto.edu', dept: 'Arts and Science Department', type: 'Sick Leave', dates: 'June 5 - June 6, 2028', reason: 'Doctor\'s appointment', status: 'Pending', daysRequested: 2 },
        { id: 2, name: 'Jose Villanueva', email: 'jose.v@benedicto.edu', dept: 'Business and Accountancy Department', type: 'Vacation Leave', dates: 'June 10 - June 14, 2028', reason: 'Family vacation', status: 'Pending', daysRequested: 5 },
        { id: 3, name: 'Wilma Mondragon', email: 'wilma.m@benedicto.edu', dept: 'Business and Accountancy Department', type: 'Emergency Leave', dates: 'August 18 - August 19, 2028', reason: 'Family emergency', status: 'Pending', daysRequested: 2 }
      ]);
      console.log('✅ Leave requests seeded');
    }

    const sepCount = await Separated.countDocuments();
    if (sepCount === 0) {
      await Separated.insertMany([
        { id: 'BC-2023-099', first: 'Diana', middle: 'R', last: 'Gonzales', dob: '1986-02-14', gender: 'Female', position: 'HR Assistant', department: 'Business and Accountancy Department', dateHired: '2017-07-01', salary: 'SG-7', status: 'Inactive', type: 'Regular', email: 'diana.g@benedicto.edu', phone: '0917-555-0199', regularization: '2018-07-01', yearsOfService: 8, resignDate: '2025-11-15', resignedBy: 'HR Admin' }
      ]);
      console.log('✅ Separated employees seeded');
    }

    const compCount = await Complaint.countDocuments();
    if (compCount === 0) {
      await Complaint.insertMany([
        { subject: 'Request for schedule adjustment', date: 'June 2, 2028', priority: 'Medium', status: 'Pending', employee: 'emma.santos@benedicto.edu' },
        { subject: 'Payslip discrepancy - May 2028', date: 'May 30, 2028', priority: 'High', status: 'Pending', employee: 'jose.v@benedicto.edu' },
        { subject: 'Update profile information', date: 'August 15, 2028', priority: 'Low', status: 'Pending', employee: 'wilma.m@benedicto.edu' }
      ]);
      console.log('✅ Complaints seeded');
    }

    const annCount = await Announcement.countDocuments();
    if (annCount === 0) {
      await Announcement.insertMany([
        { title: 'Faculty Meeting Schedule', meta: 'June 10, 2026 - 14:00 PM', when: '16 hours ago', icon: 'fa-bullhorn', color: '#2c4ba3', bg: '#e6ecfb' }
      ]);
      console.log('✅ Announcements seeded');
    }

    const actCount = await Activity.countDocuments();
    if (actCount === 0) {
      await Activity.insertMany([
        { icon: 'fa-user-clock', text: 'Attendance updated', when: '1 hour ago' }
      ]);
      console.log('✅ Activities seeded');
    }

    const reportCount = await Report.countDocuments();
    if (reportCount === 0) {
      await Report.insertMany([
        {
          employeeId: 'BC-2023-001', employeeName: 'Emma R. Santos', department: 'Library',
          period: 'Q2 2026', evaluationDate: '2026-06-30', overallRating: 4,
          categories: [
            { name: 'Job Knowledge', rating: 5, comment: 'Excellent knowledge of library systems and cataloging.' },
            { name: 'Punctuality', rating: 4, comment: 'Consistently on time, minor late arrival in May.' },
            { name: 'Professionalism', rating: 4, comment: 'Strong professional conduct with colleagues.' },
            { name: 'Collaboration', rating: 4, comment: 'Actively participates in faculty meetings.' }
          ],
          strengths: 'Attendance Rate: 96%. Present: 24 days, Late: 1 days, Absent: 0 days. Strong subject knowledge, excellent student rapport, innovative teaching methods.',
          improvements: 'Attendance consistency during peak traffic hours, earlier submission of grade sheets.',
          goals: 'Maintain or improve attendance rate above 100%. Complete advanced certification by Q4 2026.',
          evaluator: 'Dr. Maria Cruz', status: 'Finalized',
          attendanceSummary: { attendanceRate: 96, punctualityRate: 100, present: 24, late: 1, absent: 0, totalDays: 25 }
        },
        {
          employeeId: 'BC-2023-002', employeeName: 'Carlos D. Reyes', department: 'Library',
          period: 'Q2 2026', evaluationDate: '2026-06-30', overallRating: 3,
          categories: [
            { name: 'Job Knowledge', rating: 3, comment: 'Adequate knowledge of library systems.' },
            { name: 'Punctuality', rating: 3, comment: 'Occasional tardiness observed.' },
            { name: 'Professionalism', rating: 3, comment: 'Professional but room for growth.' },
            { name: 'Collaboration', rating: 3, comment: 'Works well when directed.' }
          ],
          strengths: 'Attendance Rate: 82%. Present: 20 days, Late: 3 days, Absent: 2 days. Reliable in daily operations, friendly with students.',
          improvements: 'Employee was late 3 time(s). Punctuality needs improvement. Need more initiative in organizing library events.',
          goals: 'Maintain or improve attendance rate above 87%. Complete library management training by Q3 2026.',
          evaluator: 'HR Admin', status: 'Finalized',
          attendanceSummary: { attendanceRate: 82, punctualityRate: 92, present: 20, late: 3, absent: 2, totalDays: 25 }
        }
      ]);
      console.log('✅ Reports seeded');
    }

    // Seed today's attendance
   // Seed today's attendance
  } catch (error) {
    console.error('Seed error:', error);
  }
}
seed();

// One-time cleanup: anyone still marked Inactive in Employees moves to Separated
async function cleanupInactiveEmployees() {
  try {
    const inactive = await Employee.find({ status: 'Inactive' });
    for (const emp of inactive) {
      const existing = await Separated.findOne({ id: emp.id });
      const data = emp.toObject();
      delete data._id; delete data.__v;
      data.resignDate = data.resignDate || (existing && existing.resignDate) || new Date().toISOString().slice(0, 10);
      data.resignedBy = (existing && existing.resignedBy) || 'HR Admin';
      await Separated.findOneAndUpdate({ id: emp.id }, data, { upsert: true, new: true });
      await Employee.deleteOne({ id: emp.id });
    }
    if (inactive.length) console.log(`✅ Moved ${inactive.length} inactive employee(s) to Separated`);
  } catch (err) {
    console.error('Cleanup error:', err.message);
  }
}
seed().then(cleanupInactiveEmployees);

// Helper: case/whitespace-insensitive exact email match.
// Prevents "record not found" / failed lookups caused by casing or stray
// spaces between the User record and the Employee record.
function emailMatch(email) {
  const clean = String(email || '').trim();
  return { $regex: new RegExp('^' + clean.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i') };
}

// Next employee ID: 1, 2, 3... (looks at active AND separated so IDs are never reused)
async function nextEmployeeId() {
  const [a, b] = await Promise.all([Employee.find({}, { id: 1 }), Separated.find({}, { id: 1 })]);
  const nums = [...a, ...b].map(x => String(x.id || '')).filter(s => /^\d+$/.test(s)).map(Number);
  return String((nums.length ? Math.max(...nums) : 0) + 1);
}

// ─── Auth Routes ───
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(401).json({ error: 'Invalid email or password.' });

    const user = await User.findOne({ email: emailMatch(email) });
    if (!user) return res.status(401).json({ error: 'Invalid email or password.' });

    let ok = false;
    if (isHashed(user.password)) {
      ok = await bcrypt.compare(password, user.password);
    } else if (user.password === password) {
      // Old plain-text account: let them in once, then upgrade it to a hash
      ok = true;
      user.password = await bcrypt.hash(password, 12);
      await user.save();
    }

    if (!ok) return res.status(401).json({ error: 'Invalid email or password.' });
    const isSeparated = await Separated.findOne({ email: emailMatch(user.email) });
    if (isSeparated) return res.status(403).json({ error: 'This account is deactivated. Please contact HR.' });

        const token = jwt.sign(
      { id: user._id.toString(), role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '8h', algorithm: 'HS256' }
    );
    res.json({
      user: { name: user.name, email: user.email, role: user.role, phone: user.phone, position: user.position, photo: user.photo },
      token
    });
    } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Update a User account's own profile (used by the admin/HR "Edit Profile"
// screen, which has no matching Employee record to update instead).
app.put('/api/users/:email', async (req, res) => {
  try {
    const { name, email, phone, position, photo } = req.body;
    const update = {};
    if (name) update.name = name;
    if (email) update.email = email;
    if (phone !== undefined) update.phone = phone;
    if (position !== undefined) update.position = position;
    if (photo) update.photo = photo;
    const updated = await User.findOneAndUpdate({ email: emailMatch(req.params.email) }, update, { new: true });
    if (!updated) return res.status(404).json({ error: 'User account not found' });
    res.json({ user: { name: updated.name, email: updated.email, role: updated.role, phone: updated.phone, position: updated.position, photo: updated.photo } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update user profile' });
  }
});

// ─── Employee Routes ───
app.get('/api/employees', async (req, res) => {
  try {
    res.json(await Employee.find());
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch employees' });
  }
});

app.get('/api/employees/by-email/:email', async (req, res) => {
  try {
    const emp = await Employee.findOne({ email: emailMatch(req.params.email) });
    if (!emp) return res.status(404).json({ error: 'Employee not found' });
    res.json(emp);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch employee' });
  }
});

app.post('/api/admin/renumber-employee-ids', async (req, res) => {
  try {
    const all = [...await Employee.find(), ...await Separated.find()];
    const isNum = s => /^\d+$/.test(String(s));
    let next = Math.max(0, ...all.filter(x => isNum(x.id)).map(x => Number(x.id))) + 1;
    const todo = all.filter(x => !isNum(x.id))
      .sort((a, b) => String(a.id).localeCompare(String(b.id), undefined, { numeric: true }));
    const map = {};
    for (const x of todo) map[x.id] = String(next++);
    for (const [oldId, newId] of Object.entries(map)) {
      await Employee.updateMany({ id: oldId }, { id: newId });
      await Separated.updateMany({ id: oldId }, { id: newId });
      await AttendanceLog.updateMany({ employeeId: oldId }, { employeeId: newId });
      await Report.updateMany({ employeeId: oldId }, { employeeId: newId });
    }
    res.json({ success: true, map });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/employees', async (req, res) => {
  try {
    const { password, id: _ignoreId, ...empData } = req.body;   // ignore any ID sent by the browser
    empData.id = await nextEmployeeId();                         // auto 1, 2, 3...
    const emp = new Employee(empData);
    await emp.save();
    await Department.updateOne({ name: emp.department }, { $inc: { count: 1 } });
    await Activity.create({ icon: 'fa-user-plus', text: `${emp.first} ${emp.last} added to ${emp.department}`, when: 'just now' });

    // Create the portal login using the password HR saw on the form (8–16 letters/numbers)
    let generatedPassword = null;
    if (emp.email && emp.email !== '-') {
      const existingUser = await User.findOne({ email: emailMatch(emp.email) });
      if (!existingUser) {
        generatedPassword = /^[A-Za-z0-9]{8,16}$/.test(password || '') ? password : generateEasyPassword();
        await User.create({
  name: `${emp.first} ${emp.last}`,
  email: emp.email,
  password: await bcrypt.hash(generatedPassword, 12),   // ← hashed
  role: 'employee'
});
      }
    }

    res.json({ ...emp.toObject(), generatedPassword });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add employee' });
  }
});

app.put('/api/employees/:id/password', async (req, res) => {
  try {
    const password = String((req.body && req.body.password) || '').trim();
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    const emp = await Employee.findOne({ id: req.params.id });
    if (!emp || !emp.email || emp.email === '-') {
      return res.status(404).json({ error: 'This employee has no email on file. Add an email first.' });
    }

    const hash = await bcrypt.hash(password, 12);

    // 1) find the login account by the employee's email
    let user = await User.findOne({ email: emailMatch(emp.email) });

    // 2) fallback: find it by the employee's full name
    if (!user) {
      const fullName = `${emp.first} ${emp.last}`.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      user = await User.findOne({ role: 'employee', name: new RegExp('^' + fullName + '$', 'i') });
    }

    if (user) {
      user.password = hash;
      user.email = emp.email.trim();      // keep login email in sync with the employee record
      await user.save();
    } else {
      // 3) no account exists at all: create one
      await User.create({
        name: `${emp.first} ${emp.last}`,
        email: emp.email.trim(),
        password: hash,
        role: 'employee'
      });
    }

    await Activity.create({ icon: 'fa-key', text: `Password reset for ${emp.first} ${emp.last}`, when: 'just now' });
    res.json({ success: true, loginEmail: emp.email.trim() });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ error: 'Failed to update password' });
  }
});

// HR attaches a photo (optionally with attendance rows read from it)
app.post('/api/attendance/biometric-import', async (req, res) => {
  try {
    const { fileName, image, rawText, importedBy, rows = [], assignedTo = [] } = req.body;
    if (!image) return res.status(400).json({ error: 'Please attach a photo' });

    let saved = 0;
    const storedRows = [];

    for (const r of rows) {
      const row = {
        employeeId: r.employeeId || '', name: r.name || '', department: r.department || '',
        position: r.position || '', date: r.date || '', timeIn: r.timeIn || '', timeOut: r.timeOut || '',
        status: '', matched: false
      };
      try {
        const emp = r.include && r.employeeId ? await Employee.findOne({ id: r.employeeId }) : null;
        if (emp && r.date && (r.timeIn || r.timeOut)) {
          let log = await AttendanceLog.findOne({ employeeId: emp.id, date: r.date });
          if (!log) {
            log = new AttendanceLog({ employeeId: emp.id, name: `${emp.first} ${emp.last}`, department: emp.department, date: r.date, timeIn: null, timeOut: null, status: 'Present' });
          }
          if (r.timeIn) log.timeIn = r.timeIn;
          if (r.timeOut) log.timeOut = r.timeOut;
          if (log.timeIn) log.status = parseTimeToHourFloat(log.timeIn) > 8 ? 'Late' : 'Present';
          if (log.timeOut && parseTimeToHourFloat(log.timeOut) < 18) log.status = 'Undertime';
          log.source = 'Biometric Photo';
          await log.save();
          row.status = log.status;
          row.matched = true;
          row.name = `${emp.first} ${emp.last}`;
          row.department = emp.department;
          row.position = emp.position;
          saved++;
        }
      } catch (rowErr) {
        console.error('Biometric row skipped:', rowErr.message);
      }
      storedRows.push(row);
    }

    await BiometricImport.create({
      fileName: fileName || 'biometric-photo',
      image, rawText: rawText || '', importedBy: importedBy || 'HR Admin',
      savedCount: saved, assignedTo, rows: storedRows
    });

    try {
      await Activity.create({
        icon: 'fa-fingerprint',
        text: 'Biometric photo attached' + (saved ? ` — ${saved} attendance record(s) updated` : '') + (assignedTo.length ? `, shown to ${assignedTo.length} employee(s)` : ''),
        when: 'just now'
      });
    } catch (e) {}

    res.json({ success: true, saved });
  } catch (error) {
    console.error('Biometric import error:', error);
    res.status(500).json({ error: 'Failed to import biometric photo: ' + error.message });
  }
});

// List of attached photos (without the heavy image data)
app.get('/api/attendance/biometric-imports', async (req, res) => {
  try {
    res.json(await BiometricImport.find({}, { image: 0, rawText: 0 }).sort({ createdAt: -1 }).limit(100));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch biometric imports' });
  }
});

// Serves just the photo itself (used for the thumbnail in the HR list)

app.get('/api/attendance/biometric-imports/:id/image', async (req, res) => {
  try {
    const doc = await BiometricImport.findById(req.params.id, { image: 1 });
    if (!doc || !doc.image) return res.status(404).end();
    const m = doc.image.match(/^data:(.+?);base64,(.+)$/);
    if (!m) return res.status(404).end();
    res.set('Content-Type', m[1]);
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(Buffer.from(m[2], 'base64'));
  } catch (error) {
    res.status(500).end();
  }
});

// One attached photo with its image and all rows
app.get('/api/attendance/biometric-imports/:id', async (req, res) => {
  try {
    const doc = await BiometricImport.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(doc);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch biometric import' });
  }
});

// Removes only the saved photo record (attendance logs stay)
app.delete('/api/attendance/biometric-imports/:id', async (req, res) => {
  try {
    await BiometricImport.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete biometric import' });
  }
});

// Bulk save: many employees' time in / out read from a biometric photo.
// Same rules as the single biometric log (after 8:00 = Late, out before 6:00 PM = Undertime).
app.post('/api/attendance/biometric-bulk', async (req, res) => {
  try {
    const { entries } = req.body;
    if (!Array.isArray(entries) || !entries.length) {
      return res.status(400).json({ error: 'No entries provided' });
    }
    let saved = 0;
    const skipped = [];
    for (const { employeeId, date, timeIn, timeOut } of entries) {
      const emp = await Employee.findOne({ id: employeeId });
      if (!emp || !date || (!timeIn && !timeOut)) { skipped.push(employeeId); continue; }

      let log = await AttendanceLog.findOne({ employeeId, date });
      if (!log) {
        log = new AttendanceLog({ employeeId, name: `${emp.first} ${emp.last}`, department: emp.department, date, timeIn: null, timeOut: null, status: 'Present' });
      }
      if (timeIn) log.timeIn = timeIn;
      if (timeOut) log.timeOut = timeOut;

      if (log.timeIn) {
        log.status = parseTimeToHourFloat(log.timeIn) > 8 ? 'Late' : 'Present';
      }
      if (log.timeOut && parseTimeToHourFloat(log.timeOut) < 18) {
        log.status = 'Undertime';
      }
      log.source = 'Biometric Photo';
      await log.save();
      saved++;
    }
    await Activity.create({ icon: 'fa-fingerprint', text: `Biometric photo attached — ${saved} attendance record(s) updated`, when: 'just now' });
    res.json({ success: true, saved, skipped });
  } catch (error) {
    console.error('Biometric bulk error:', error);
    res.status(500).json({ error: 'Failed to save biometric data' });
  }
});

app.put('/api/employees/:id', async (req, res) => {
  try {
    const old = await Employee.findOne({ id: req.params.id });
    const updated = await Employee.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
    if (!updated) return res.status(404).json({ error: 'Employee not found' });

    if (old && old.department !== updated.department) {
      await Department.updateOne({ name: old.department }, { $inc: { count: -1 } });
      await Department.updateOne({ name: updated.department }, { $inc: { count: 1 } });
    }

    // If the email changed, move the login account to the new email too
    const oldEmail = (old && old.email || '').trim().toLowerCase();
    const newEmail = (updated.email || '').trim();
    if (oldEmail && newEmail && newEmail !== '-' && oldEmail !== newEmail.toLowerCase()) {
      await User.updateOne({ email: emailMatch(old.email) }, { email: newEmail });
    }

    await Activity.create({ icon: 'fa-user-pen', text: `${updated.first} ${updated.last}'s record was updated`, when: 'just now' });
    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update employee' });
  }
});

// Admin manually update leave balance
app.put('/api/employees/:id/leave-balance', async (req, res) => {
  try {
    const { leaveBalance } = req.body;
    const updated = await Employee.findOneAndUpdate(
      { id: req.params.id },
      { leaveBalance: parseInt(leaveBalance) || 0 },
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'Employee not found' });
    await Activity.create({ 
      icon: 'fa-calendar-check', 
      text: `${updated.first} ${updated.last}'s leave balance updated to ${updated.leaveBalance}`, 
      when: 'just now' 
    });
    res.json({ success: true, leaveBalance: updated.leaveBalance, employee: updated });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update leave balance' });
  }
});

// Resign employee: move the FULL record to Separated and remove from Employees
app.put('/api/employees/:id/resign', async (req, res) => {
  try {
    const { resignDate, resignedBy } = req.body;
    const emp = await Employee.findOne({ id: req.params.id });
    if (!emp) return res.status(404).json({ error: 'Employee not found' });

    const data = emp.toObject();
    delete data._id; delete data.__v;
    data.status = 'Inactive';
    data.resignDate = resignDate || new Date().toISOString().slice(0, 10);
    data.resignedBy = resignedBy || 'HR Admin';

    const sepRecord = await Separated.findOneAndUpdate({ id: emp.id }, data, { upsert: true, new: true });
    await Employee.deleteOne({ id: emp.id });

    await Activity.create({ icon: 'fa-user-xmark', text: `${emp.first} ${emp.last} moved to Separated`, when: 'just now' });
    res.json({ success: true, message: 'Employee resigned and archived', data: sepRecord });
  } catch (error) {
    console.error('Resign error:', error);
    res.status(500).json({ error: 'Failed to resign employee: ' + error.message });
  }
});

// Reactivate: move a separated person back to Employees with everything they had
app.put('/api/separated/:id/reactivate', async (req, res) => {
  try {
    const sep = await Separated.findOne({ id: req.params.id });
    if (!sep) return res.status(404).json({ error: 'Separated record not found' });

    const data = sep.toObject();
    delete data._id; delete data.__v; delete data.resignedBy;
    data.status = 'Active';
    data.resignDate = '';

    const emp = await Employee.findOneAndUpdate({ id: sep.id }, data, { upsert: true, new: true });
    await Separated.deleteOne({ id: sep.id });

    await Activity.create({ icon: 'fa-user-check', text: `${emp.first} ${emp.last} was reactivated`, when: 'just now' });
    res.json({ success: true, employee: emp });
  } catch (error) {
    console.error('Reactivate error:', error);
    res.status(500).json({ error: 'Failed to reactivate employee: ' + error.message });
  }
});

// ─── Separated Routes ───
app.get('/api/separated', async (req, res) => {
  try {
    res.json(await Separated.find().sort({ resignDate: -1 }));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch separated records' });
  }
});

// ─── Department Routes ───
// Counts are computed live from current Employee records rather than a
// stored counter, so they can never drift out of sync.
app.get('/api/departments', async (req, res) => {
  try {
    const depts = await Department.find();
    const emps = await Employee.find({ status: { $ne: 'Inactive' } });
    const result = depts.map(d => {
      const obj = d.toObject();
      obj.count = emps.filter(e => e.department === d.name).length;
      if (!obj.group) obj.group = ['Tourism Department','Information Technology Department','Accountancy Department','Business Department','Engineering Department','Educational Department'].includes(d.name) ? 'academic' : 'admin';
      return obj;
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch departments' });
  }
});

// Create a new department (used by the "+ Add Department" button)
app.post('/api/departments', async (req, res) => {
  try {
    const { name, detail, status, head, group } = req.body;
    if (!name) return res.status(400).json({ error: 'Department name is required' });
    const existing = await Department.findOne({ name });
    if (existing) return res.status(400).json({ error: 'A department with that name already exists' });
    const dept = new Department({
      name, detail: detail || '', status: status || 'Active',
      head: head || 'Not Assigned', group: group || 'admin', count: 0
    });
    await dept.save();
    await Activity.create({ icon: 'fa-building', text: `New department "${name}" was added`, when: 'just now' });
    res.status(201).json(dept);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create department' });
  }
});

// Edit a department: rename, description, status, head
app.put('/api/departments/:name', async (req, res) => {
  try {
    const { detail, status, head, group, newName } = req.body;
    const oldName = req.params.name;
    const dept = await Department.findOne({ name: oldName });
    if (!dept) return res.status(404).json({ error: 'Department not found' });

    if (detail !== undefined) dept.detail = detail;
    if (status !== undefined) dept.status = status;
    if (head !== undefined) dept.head = head;
    if (group !== undefined) dept.group = group;

    const cleanNew = (newName || '').trim();
    if (cleanNew && cleanNew !== oldName) {
      const escaped = cleanNew.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const dup = await Department.findOne({ name: new RegExp('^' + escaped + '$', 'i'), _id: { $ne: dept._id } });
      if (dup) return res.status(400).json({ error: 'A department with that name already exists' });

      dept.name = cleanNew;
      // Keep everything that points to the old name in sync
      await Employee.updateMany({ department: oldName }, { department: cleanNew });
      await Separated.updateMany({ department: oldName }, { department: cleanNew });
      await AttendanceLog.updateMany({ department: oldName }, { department: cleanNew });
      await Report.updateMany({ department: oldName }, { department: cleanNew });
      await LeaveRequest.updateMany({ dept: oldName }, { dept: cleanNew });
      await Activity.create({ icon: 'fa-building', text: `Department "${oldName}" was renamed to "${cleanNew}"`, when: 'just now' });
    } else if (status !== undefined) {
      await Activity.create({ icon: 'fa-building', text: `Department "${oldName}" was set to ${status}`, when: 'just now' });
    }

    await dept.save();
    res.json(dept);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update department' });
  }
});

// Remove a department (its employees become Unassigned, records are kept)
app.delete('/api/departments/:name', async (req, res) => {
  try {
    const name = req.params.name;
    const dept = await Department.findOne({ name });
    if (!dept) return res.status(404).json({ error: 'Department not found' });

    const moved = await Employee.updateMany({ department: name }, { department: 'Unassigned' });
    await Department.deleteOne({ _id: dept._id });
    await Activity.create({ icon: 'fa-building', text: `Department "${name}" was removed`, when: 'just now' });
    res.json({ success: true, unassigned: moved.modifiedCount || 0 });
  } catch (error) {
    res.status(500).json({ error: 'Failed to remove department' });
  }
});

// ─── Leave Routes ───
app.get('/api/leave-requests', async (req, res) => {
  try {
    const requests = await LeaveRequest.find().sort({ id: -1 });
    res.json(requests);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch leave requests' });
  }
});

app.get('/api/leave-requests/employee/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const requests = await LeaveRequest.find({ email: emailMatch(email) }).sort({ id: -1 });
    res.json(requests);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch employee leave requests' });
  }
});

app.get('/api/leave-requests/:id', async (req, res) => {
  try {
    const request = await LeaveRequest.findById(req.params.id);
    if (!request) return res.status(404).json({ error: 'Leave request not found' });
    res.json(request);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch leave request' });
  }
});

app.post('/api/leave-requests/submit', async (req, res) => {
  console.log('📝 Received leave request:', req.body);
  try {
    const { name, email, dept, type, dates, reason, startDate, endDate } = req.body;

    if (!name || !email || !dept || !type || !dates) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: { name, email, dept, type, dates }
      });
    }

    let daysRequested = 1;
    if (startDate && endDate) {
      const start = new Date(startDate);
      const end = new Date(endDate);
      const diffTime = Math.abs(end - start);
      daysRequested = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;
    }

    // Case/whitespace-insensitive lookup — this is what was causing
    // "Employee not found" and silently blocking the submission before.
    const emp = await Employee.findOne({ email: emailMatch(email) });
    if (!emp) return res.status(404).json({ error: 'Employee not found for email: ' + email });

    if (emp.leaveBalance < daysRequested) {
      return res.status(400).json({ 
        error: `Insufficient leave balance. You have ${emp.leaveBalance} day(s) left, but requested ${daysRequested} day(s).` 
      });
    }

    emp.leaveBalance -= daysRequested;
    await emp.save();

    const lastRequest = await LeaveRequest.findOne().sort({ id: -1 });
    const newId = lastRequest ? lastRequest.id + 1 : 1;

    const leaveRequest = new LeaveRequest({
      id: newId,
      name,
      email,
      dept,
      type,
      dates,
      reason: reason || 'No reason provided',
      status: 'Pending',
      daysRequested
    });

    await leaveRequest.save();

    await Activity.create({ 
      icon: 'fa-file-lines', 
      text: `${name} submitted a ${type} leave request (${daysRequested} day(s))`, 
      when: 'just now' 
    });

    res.status(201).json({ 
      success: true, 
      message: 'Leave request submitted successfully',
      remainingBalance: emp.leaveBalance,
      data: leaveRequest 
    });
  } catch (error) {
    console.error('❌ Submit leave error:', error);
    res.status(500).json({ 
      error: 'Failed to submit leave request: ' + error.message,
      stack: error.stack 
    });
  }
});

app.put('/api/leave-requests/:id', async (req, res) => {
  try {
    const { status } = req.body;
    const updated = await LeaveRequest.findByIdAndUpdate(
      req.params.id, 
      { status }, 
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'Leave request not found' });

    await Activity.create({ 
      icon: status === 'Approved' ? 'fa-check-circle' : 'fa-times-circle', 
      text: `${updated.name}'s leave request was ${status.toLowerCase()}`, 
      when: 'just now' 
    });
    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update leave request' });
  }
});

app.post('/api/leave-requests', async (req, res) => {
  try {
    const lr = new LeaveRequest(req.body);
    await lr.save();
    await Activity.create({ icon: 'fa-file-lines', text: `${lr.name} submitted a leave request`, when: 'just now' });
    res.status(201).json(lr);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create leave request' });
  }
});

app.delete('/api/leave-requests/:id', async (req, res) => {
  try {
    await LeaveRequest.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete leave request' });
  }
});

// ─── Complaint Routes ───
app.get('/api/complaints', async (req, res) => {
  try {
    res.json(await Complaint.find());
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch complaints' });
  }
});

app.post('/api/complaints', async (req, res) => {
  try {
    const comp = new Complaint(req.body);
    await comp.save();
    res.status(201).json(comp);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create complaint' });
  }
});

app.put('/api/complaints/:id', async (req, res) => {
  try {
    const updated = await Complaint.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update complaint' });
  }
});

// ─── Attendance Routes ───
app.get('/api/attendance', async (req, res) => {
  try {
    const { date } = req.query;
    const query = date ? { date } : {};
    res.json(await AttendanceLog.find(query));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch attendance' });
  }
});

app.get('/api/attendance/stats/:employeeId', async (req, res) => {
  try {
    const { employeeId } = req.params;
    const logs = await AttendanceLog.find({ employeeId }).sort({ date: -1 });

    const total = logs.length;
    const present = logs.filter(l => l.status === 'Present').length;
    const late = logs.filter(l => l.status === 'Late').length;
    const absent = logs.filter(l => l.status === 'Absent').length;

    const attendanceRate = total > 0 ? (present / total) * 100 : 0;
    const punctualityRate = total > 0 ? ((present + late) / total) * 100 : 0;

    const rateToScore = (rate) => {
      if (rate >= 95) return 5;
      if (rate >= 85) return 4;
      if (rate >= 75) return 3;
      if (rate >= 60) return 2;
      return 1;
    };

    const stats = {
      totalDays: total,
      present,
      late,
      absent,
      attendanceRate: Math.round(attendanceRate),
      punctualityRate: Math.round(punctualityRate),
      suggestedRatings: {
        punctuality: rateToScore(100 - ((late / (total || 1)) * 100)),
        professionalism: rateToScore(attendanceRate),
        reliability: rateToScore(attendanceRate),
        collaboration: 3
      }
    };

    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch attendance stats' });
  }
});

app.get('/api/attendance/overview', async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const activeCount = await Employee.countDocuments({ status: { $ne: 'Inactive' } });
    const todayPH = manilaNow().date;
    const base = new Date(todayPH + 'T00:00:00Z');
    const dateList = [];
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(base);
      d.setUTCDate(d.getUTCDate() - i);
      dateList.push(d.toISOString().slice(0, 10));
    }
    const logs = await AttendanceLog.find({ date: { $in: dateList } });
    const overview = dateList.map(date => {
      const dayLogs = logs.filter(l => l.date === date);
      const present = dayLogs.filter(l => l.status === 'Present').length;
      const late = dayLogs.filter(l => l.status === 'Late').length;
      const loggedCount = dayLogs.length;
      const absent = Math.max(activeCount - present - late, 0);
      return { date, present, late, absent: loggedCount > 0 || date === todayPH ? absent : 0 };
    });
    res.json(overview);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch attendance overview' });
  }
});

app.post('/api/attendance/scan', async (req, res) => {
  try {
    const { employeeId } = req.body;
    const emp = await Employee.findOne({ id: employeeId });
    if (!emp) return res.status(404).json({ error: 'Employee not found' });
    const ph = manilaNow();
    const date = ph.date;
    const timeStr = ph.timeStr;
    let log = await AttendanceLog.findOne({ employeeId, date });
    let action;
    if (!log) {
      log = new AttendanceLog({ employeeId, name: `${emp.first} ${emp.last}`, department: emp.department, date, timeIn: null, timeOut: null, status: 'Present' });
    }
    if (!log.timeIn) {
      log.timeIn = timeStr;
      log.status = ph.hourFloat > 8 ? 'Late' : 'Present';
      action = 'Time In Recorded';
      await Activity.create({ icon: 'fa-fingerprint', text: `${log.name} clocked in (${log.status})`, when: 'just now' });
    } else if (!log.timeOut) {
      log.timeOut = timeStr;
      const isUndertime = ph.hourFloat < 18;
      if (isUndertime) log.status = 'Undertime';
      action = 'Time Out Recorded';
      await Activity.create({ icon: 'fa-fingerprint', text: `${log.name} clocked out${isUndertime ? ' (Undertime)' : ''}`, when: 'just now' });
    } else {
      action = 'Already Completed Today';
    }
    await log.save();
    res.json({ action, name: log.name, time: timeStr, log });
  } catch (error) {
    res.status(500).json({ error: 'Failed to process scan' });
  }
});

app.get('/api/attendance/today/:employeeId', async (req, res) => {
  try {
    const log = await AttendanceLog.findOne({ employeeId: req.params.employeeId, date: manilaNow().date });
    res.json(log || null);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch today\'s attendance' });
  }
});

app.get('/api/attendance/status-today', async (req, res) => {
  try {
    const ph = manilaNow();
    const date = ph.date;
    const pastCutoff = ph.hour >= 17; // 5:00 PM Philippine time

    const emps = await Employee.find({ status: { $ne: 'Inactive' } });
    const logs = await AttendanceLog.find({ date });
    const logMap = {};
    logs.forEach(l => { logMap[l.employeeId] = l; });

    const result = emps.map(e => {
      const log = logMap[e.id];
      if (e.status === 'On Leave') {
        return { employeeId: e.id, name: `${e.first} ${e.last}`, department: e.department, timeIn: null, timeOut: null, status: 'On Leave' };
      }
      if (log && log.timeIn) {
        return { employeeId: e.id, name: log.name, department: log.department, timeIn: log.timeIn, timeOut: log.timeOut, status: log.status };
      }
      if (pastCutoff) {
        return { employeeId: e.id, name: `${e.first} ${e.last}`, department: e.department, timeIn: null, timeOut: null, status: 'Absent' };
      }
      return { employeeId: e.id, name: `${e.first} ${e.last}`, department: e.department, timeIn: null, timeOut: null, status: 'Not Yet Timed In' };
    });

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch attendance status' });
  }
});

app.post('/api/attendance/time-in', async (req, res) => {
  try {
    const { employeeId } = req.body;
    const emp = await Employee.findOne({ id: employeeId });
    if (!emp) return res.status(404).json({ error: 'Employee not found' });

    const ph = manilaNow();
    const date = ph.date;
    let log = await AttendanceLog.findOne({ employeeId, date });
    if (log && log.timeIn) {
      return res.status(400).json({ error: 'You have already timed in today.', log });
    }
    const timeStr = ph.timeStr;
    if (!log) {
      log = new AttendanceLog({ employeeId, name: `${emp.first} ${emp.last}`, department: emp.department, date, timeIn: null, timeOut: null, status: 'Present' });
    }
    log.timeIn = timeStr;
    log.status = ph.hourFloat > 8.25 ? 'Late' : 'Present';
    await log.save();
    await Activity.create({ icon: 'fa-fingerprint', text: `${log.name} timed in (${log.status})`, when: 'just now' });
    res.json({ action: 'Time In Recorded', name: log.name, time: timeStr, status: log.status, log });
  } catch (error) {
    res.status(500).json({ error: 'Failed to record time in' });
  }
});

app.post('/api/attendance/time-out', async (req, res) => {
  try {
    const { employeeId } = req.body;
    const emp = await Employee.findOne({ id: employeeId });
    if (!emp) return res.status(404).json({ error: 'Employee not found' });

    const ph = manilaNow();
    const date = ph.date;
    let log = await AttendanceLog.findOne({ employeeId, date });
    if (!log || !log.timeIn) {
      return res.status(400).json({ error: 'You need to time in first before timing out.' });
    }
    if (log.timeOut) {
      return res.status(400).json({ error: 'You have already timed out today.', log });
    }
    const timeStr = ph.timeStr;
    log.timeOut = timeStr;
    const isUndertime = ph.hourFloat < 18;
    if (isUndertime) log.status = 'Undertime';
    await log.save();
    await Activity.create({ icon: 'fa-fingerprint', text: `${log.name} timed out${isUndertime ? ' (Undertime)' : ''}`, when: 'just now' });
    res.json({ action: 'Time Out Recorded', name: log.name, time: timeStr, status: log.status, log });
  } catch (error) {
    res.status(500).json({ error: 'Failed to record time out' });
  }
});

// Employee: how many records they have per month (all years)
app.get('/api/attendance/employee/:employeeId/months', async (req, res) => {
  try {
    const logs = await AttendanceLog.find({ employeeId: req.params.employeeId }, { date: 1 });
    const counts = {};
    logs.forEach(l => {
      const key = (l.date || '').slice(0, 7); // "YYYY-MM"
      if (key) counts[key] = (counts[key] || 0) + 1;
    });
    res.json(counts);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch attendance months' });
  }
});

// Employee: all records for one month
app.get('/api/attendance/employee/:employeeId/:month', async (req, res) => {
  try {
    const { employeeId, month } = req.params;
    if (!/^\d{4}-\d{2}$/.test(month)) return res.status(400).json({ error: 'Invalid month format, expected YYYY-MM' });
    const logs = await AttendanceLog.find({ employeeId, date: { $regex: '^' + month } }).sort({ date: -1 });
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch attendance' });
  }
});

// ─── Attendance Archive (by month) ───
// Counts of attendance rows per month, for the "Jan–Dec" archive dropdown.
app.get('/api/attendance/archive/months', async (req, res) => {
  try {
    const year = parseInt(req.query.year) || new Date().getFullYear();
    const logs = await AttendanceLog.find({ date: { $regex: '^' + year } }, { date: 1 });
    const counts = {};
    logs.forEach(l => {
      const key = (l.date || '').slice(0, 7); // "YYYY-MM"
      if (key) counts[key] = (counts[key] || 0) + 1;
    });
    res.json({ year, counts });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch attendance archive months' });
  }
});

// Full attendance records for one specific "YYYY-MM" month.
app.get('/api/attendance/archive/:month', async (req, res) => {
  try {
    const month = req.params.month;
    if (!/^\d{4}-\d{2}$/.test(month)) return res.status(400).json({ error: 'Invalid month format, expected YYYY-MM' });
    const logs = await AttendanceLog.find({ date: { $regex: '^' + month } }).sort({ date: -1 });
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch archived attendance' });
  }
});

function formatTime(d) {
  let h = d.getHours();
  const ampm = h >= 12 ? 'PM' : 'AM';
  h = h % 12 || 12;
  const m = String(d.getMinutes()).padStart(2, '0');
  return `${h}:${m} ${ampm}`;
}

// ─── Announcement Routes ───
app.get('/api/announcements', async (req, res) => {
  try {
    res.json(await Announcement.find().sort({ _id: -1 }));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch announcements' });
  }
});

app.post('/api/announcements', async (req, res) => {
  try {
    const ann = new Announcement(req.body);
    await ann.save();
    res.status(201).json(ann);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create announcement' });
  }
});

// ─── Activity Routes ───
app.get('/api/activities', async (req, res) => {
  try {
    res.json(await Activity.find().sort({ _id: -1 }));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch activities' });
  }
});

// ─── Report Routes ───
app.get('/api/reports', async (req, res) => {
  try {
    const { employeeId } = req.query;
    const query = employeeId ? { employeeId } : {};
    res.json(await Report.find(query).sort({ evaluationDate: -1 }));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

app.post('/api/reports', async (req, res) => {
  try {
    const report = new Report(req.body);
    await report.save();
    await Activity.create({ icon: 'fa-file-lines', text: `Performance report created for ${report.employeeName}`, when: 'just now' });
    res.status(201).json(report);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create report' });
  }
});

app.put('/api/reports/:id', async (req, res) => {
  try {
    const updated = await Report.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update report' });
  }
});

app.delete('/api/reports/:id', async (req, res) => {
  try {
    await Report.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete report' });
  }
});

// TEMPORARY: renumber old IDs (BC-2023-001 -> 1 ...). Delete after running once.
app.post('/api/admin/renumber-employee-ids', async (req, res) => {
  try {
    const all = [...await Employee.find(), ...await Separated.find()];
    const isNum = s => /^\d+$/.test(String(s));
    let next = Math.max(0, ...all.filter(x => isNum(x.id)).map(x => Number(x.id))) + 1;
    const todo = all.filter(x => !isNum(x.id))
      .sort((a, b) => String(a.id).localeCompare(String(b.id), undefined, { numeric: true }));
    const map = {};
    for (const x of todo) map[x.id] = String(next++);
    for (const [oldId, newId] of Object.entries(map)) {
      await Employee.updateMany({ id: oldId }, { id: newId });
      await Separated.updateMany({ id: oldId }, { id: newId });
      await AttendanceLog.updateMany({ employeeId: oldId }, { employeeId: newId });
      await Report.updateMany({ employeeId: oldId }, { employeeId: newId });
    }
    res.json({ success: true, map });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Test endpoint ───
app.get('/api/test', (req, res) => {
  res.json({ message: 'Server is running!' });
});

// ─── Start ───
app.get('/', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ HR System running on port ${PORT}`);
});

module.exports = app;