const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 10;
const MAX_PIN_LENGTH = 128;
const MAX_BODY_BYTES = 1024 * 1024;
const COOKIE_NAME = 'waterhub_session';
const SMS_API_URL = process.env.AT_ENVIRONMENT === 'sandbox'
  ? 'https://api.sandbox.africastalking.com/version1/messaging'
  : 'https://api.africastalking.com/version1/messaging';

const dataDirectory = path.join(ROOT, 'data');
fs.mkdirSync(dataDirectory, { recursive:true });
const database = new DatabaseSync(path.join(dataDirectory, 'waterhub.sqlite'));
database.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS students (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    age INTEGER NOT NULL,
    guardian TEXT NOT NULL,
    guardian_phone TEXT NOT NULL,
    sms_consent INTEGER NOT NULL DEFAULT 0,
    registered TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    date TEXT NOT NULL,
    time TEXT NOT NULL,
    place TEXT NOT NULL,
    info TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS checkins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT NOT NULL,
    name TEXT NOT NULL,
    time TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    type TEXT NOT NULL,
    student_id TEXT NOT NULL,
    phone TEXT NOT NULL,
    guardian TEXT NOT NULL,
    message TEXT NOT NULL,
    delivery_status TEXT NOT NULL DEFAULT 'not_sent',
    delivery_error TEXT NOT NULL DEFAULT ''
  );
  CREATE TABLE IF NOT EXISTS user_accounts (
    role TEXT PRIMARY KEY CHECK (role IN ('admin','student')),
    username TEXT NOT NULL UNIQUE,
    salt BLOB NOT NULL,
    password_hash BLOB NOT NULL,
    pin_salt BLOB,
    pin_hash BLOB,
    updated TEXT NOT NULL
  );
`);

const studentColumns = new Set(database.prepare('PRAGMA table_info(students)').all().map(column => column.name));
if(!studentColumns.has('sms_consent')) database.exec('ALTER TABLE students ADD COLUMN sms_consent INTEGER NOT NULL DEFAULT 0');
const logColumns = new Set(database.prepare('PRAGMA table_info(logs)').all().map(column => column.name));
if(!logColumns.has('delivery_status')) database.exec("ALTER TABLE logs ADD COLUMN delivery_status TEXT NOT NULL DEFAULT 'not_sent'");
if(!logColumns.has('delivery_error')) database.exec("ALTER TABLE logs ADD COLUMN delivery_error TEXT NOT NULL DEFAULT ''");

const accountColumns = new Set(database.prepare('PRAGMA table_info(user_accounts)').all().map(column => column.name));
if(!accountColumns.has('pin_salt')) database.exec('ALTER TABLE user_accounts ADD COLUMN pin_salt BLOB');
if(!accountColumns.has('pin_hash')) database.exec('ALTER TABLE user_accounts ADD COLUMN pin_hash BLOB');

const dummySalt = crypto.randomBytes(16);
const dummyDigest = crypto.scryptSync(crypto.randomBytes(32).toString('hex'), dummySalt, 64);
let setupToken = null;
let pinResetToken = null;

function validPin(value){
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_PIN_LENGTH;
}

function makePinRecord(pin){
  const salt = crypto.randomBytes(16);
  return { salt, hash:crypto.scryptSync(pin, salt, 64) };
}

function verifyPin(account, pin){
  const supplied = typeof pin === 'string' ? pin : '';
  const salt = account && account.pin_salt ? account.pin_salt : dummySalt;
  const expected = account && account.pin_hash ? account.pin_hash : dummyDigest;
  const candidate = crypto.scryptSync(supplied.slice(0, MAX_PIN_LENGTH), salt, 64);
  return Boolean(account && account.pin_hash) && validPin(supplied) && crypto.timingSafeEqual(candidate, expected);
}

function accountForRole(role){
  return database.prepare('SELECT * FROM user_accounts WHERE role=?').get(role);
}

function setupIsRequired(){
  return ['admin','student'].some(role => {
    const account = accountForRole(role);
    return !account || !account.pin_hash;
  });
}

if(setupIsRequired()){
  setupToken = crypto.randomBytes(32).toString('hex');
  console.log(`PIN setup code (enter this on the PIN setup screen): ${setupToken}`);
}else{
  pinResetToken = crypto.randomBytes(32).toString('hex');
  console.log(`One-time PIN recovery code (enter this on the PIN reset screen): ${pinResetToken}`);
}

function transaction(work){
  database.exec('BEGIN IMMEDIATE');
  try{
    const result = work();
    database.exec('COMMIT');
    return result;
  }catch(error){
    database.exec('ROLLBACK');
    throw error;
  }
}

const sessions = new Map();
const loginAttempts = new Map();
const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for(const [token, session] of sessions){
    if(session.expiresAt <= now) sessions.delete(token);
  }
  for(const [ip, attempt] of loginAttempts){
    if(attempt.resetAt <= now) loginAttempts.delete(ip);
  }
}, 10 * 60 * 1000);
cleanupTimer.unref();
const mimeTypes = {
  '.html':'text/html; charset=utf-8',
  '.css':'text/css; charset=utf-8',
  '.js':'text/javascript; charset=utf-8',
  '.svg':'image/svg+xml'
};

function sendJson(response, status, value, headers = {}){
  response.writeHead(status, {
    'Content-Type':'application/json; charset=utf-8',
    'Cache-Control':'no-store',
    'X-Content-Type-Options':'nosniff',
    'X-Frame-Options':'DENY',
    'Referrer-Policy':'same-origin',
    ...headers
  });
  response.end(JSON.stringify(value));
}

function sendError(response, status, message){
  sendJson(response, status, { error:message });
}

function parseCookies(header = ''){
  return Object.fromEntries(header.split(';').map(part => {
    const separator = part.indexOf('=');
    if(separator < 0) return ['', ''];
    return [part.slice(0, separator).trim(), decodeURIComponent(part.slice(separator + 1).trim())];
  }).filter(([key]) => key));
}

function getSession(request){
  const token = parseCookies(request.headers.cookie)[COOKIE_NAME];
  const session = token && sessions.get(token);
  if(!session) return null;
  if(session.expiresAt <= Date.now()){
    sessions.delete(token);
    return null;
  }
  session.expiresAt = Date.now() + SESSION_TTL_MS;
  return { token, ...session };
}

function requireRole(session, allowedRoles){
  return Boolean(session && allowedRoles.includes(session.role));
}

function isSameOrigin(request){
  const origin = request.headers.origin;
  if(!origin || !request.headers.host) return false;
  try{
    const parsed = new URL(origin);
    return ['http:', 'https:'].includes(parsed.protocol) && parsed.host === request.headers.host;
  }catch(error){
    return false;
  }
}

function readJson(request){
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    request.on('data', chunk => {
      size += chunk.length;
      if(size > MAX_BODY_BYTES){
        const error = new Error('Request body is too large.');
        error.status = 413;
        reject(error);
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      try{
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      }catch(error){
        error.status = 400;
        reject(error);
      }
    });
    request.on('error', reject);
  });
}

function makeStudentId(){
  let id;
  do{
    id = 'STU-' + crypto.randomInt(1000, 10000);
  }while(database.prepare('SELECT 1 FROM students WHERE id=?').get(id));
  return id;
}

function recordLog(student, type, message, time = new Date().toISOString()){
  const result = database.prepare(`
    INSERT INTO logs (time, type, student_id, phone, guardian, message, delivery_status)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(time, type, student.id, student.guardianPhone, student.guardian, message, 'not_sent');
  const row = database.prepare('SELECT delivery_status, delivery_error FROM logs WHERE id=?').get(Number(result.lastInsertRowid));
  return {
    id:Number(result.lastInsertRowid),
    time,
    type,
    studentId:student.id,
    to:student.guardianPhone,
    guardian:student.guardian,
    message,
    deliveryStatus:row.delivery_status,
    deliveryError:row.delivery_error
  };
}

function smsProviderConfigured(){
  return Boolean(process.env.AT_USERNAME && process.env.AT_API_KEY);
}

async function sendSMS(log){
  if(!log || !log.to || !smsProviderConfigured()){
    return { status:'not_configured', error:'' };
  }

  const form = new URLSearchParams({
    username:process.env.AT_USERNAME,
    to:log.to,
    message:log.message
  });
  if(process.env.AT_SENDER_ID) form.set('from', process.env.AT_SENDER_ID);

  try{
    const response = await fetch(SMS_API_URL, {
      method:'POST',
      headers:{
        Accept:'application/json',
        apiKey:process.env.AT_API_KEY,
        'Content-Type':'application/x-www-form-urlencoded'
      },
      body:form,
      signal:AbortSignal.timeout(15000)
    });
    const body = await response.json().catch(() => null);
    const recipient = body && body.SMSMessageData && Array.isArray(body.SMSMessageData.Recipients)
      ? body.SMSMessageData.Recipients.find(item => item.number === log.to) || body.SMSMessageData.Recipients[0]
      : null;
    if(!response.ok || !recipient || Number(recipient.statusCode) !== 101){
      const providerMessage = recipient && recipient.status
        ? `SMS provider status: ${recipient.status}`
        : body && body.SMSMessageData && body.SMSMessageData.Message
          ? String(body.SMSMessageData.Message).slice(0, 300)
          : `SMS provider returned HTTP ${response.status}.`;
      throw new Error(providerMessage);
    }
    return { status:'accepted', error:'' };
  }catch(error){
    console.error(`SMS delivery failed for notification ${log.id}:`, error.message);
    return { status:'failed', error:String(error.message || 'SMS delivery failed.').slice(0, 300) };
  }
}

async function deliverSMS(log){
  const result = await sendSMS(log);
  database.prepare('UPDATE logs SET delivery_status=?, delivery_error=? WHERE id=?')
    .run(result.status, result.error, log.id);
  return { ...log, deliveryStatus:result.status, deliveryError:result.error };
}

function studentFromRow(row){
  return {
    id:row.id,
    name:row.name,
    age:row.age,
    guardian:row.guardian,
    guardianPhone:row.guardian_phone,
    registered:row.registered
  };
}

function logFromRow(row){
  return {
    id:row.id,
    time:row.time,
    type:row.type,
    studentId:row.student_id,
    to:row.phone,
    guardian:row.guardian,
    message:row.message,
    deliveryStatus:row.delivery_status,
    deliveryError:row.delivery_error
  };
}

function loadState(role){
  const todayCheckins = database.prepare(`
    SELECT student_id, name, time FROM checkins
    WHERE date(time, 'localtime') = date('now', 'localtime')
    ORDER BY id DESC
  `).all().map(row => ({ studentId:row.student_id, name:row.name, time:row.time }));
  if(role !== 'admin') return { students:[], events:[], checkins:todayCheckins, logs:[] };

  return {
    students:database.prepare('SELECT * FROM students ORDER BY registered DESC').all().map(studentFromRow),
    events:database.prepare('SELECT * FROM events ORDER BY id DESC').all(),
    checkins:database.prepare('SELECT student_id, name, time FROM checkins ORDER BY id DESC LIMIT 500')
      .all().map(row => ({ studentId:row.student_id, name:row.name, time:row.time })),
    logs:database.prepare('SELECT * FROM logs ORDER BY id DESC LIMIT 100').all().map(logFromRow)
  };
}

function staticFile(response, pathname){
  const files = new Map([
    ['/', 'index.html'],
    ['/index.html', 'index.html'],
    ['/style.css', 'style.css'],
    ['/script.js', 'script.js'],
    ['/desk-arduino.svg', 'desk-arduino.svg'],
    ['/motherboard.svg', 'motherboard.svg']
  ]);
  const filename = files.get(pathname);
  if(!filename){
    sendError(response, 404, 'Not found.');
    return;
  }
  const filePath = path.join(ROOT, filename);
  fs.readFile(filePath, (error, content) => {
    if(error){
      console.error(`Unable to read ${filename}:`, error);
      sendError(response, 500, 'The requested page could not be served.');
      return;
    }
    response.writeHead(200, {
      'Content-Type':mimeTypes[path.extname(filename)] || 'application/octet-stream',
      'Cache-Control':'no-cache',
      'X-Content-Type-Options':'nosniff',
      'X-Frame-Options':'DENY',
      'Referrer-Policy':'same-origin'
    });
    response.end(content);
  });
}

async function handleApi(request, response, url){
  const { pathname } = url;
  const mutating = ['POST','PUT','PATCH','DELETE'].includes(request.method);
  if(mutating && !isSameOrigin(request)){
    sendError(response, 403, 'Request origin was not allowed.');
    return;
  }

  if(request.method === 'GET' && pathname === '/api/session'){
    const session = getSession(request);
    sendJson(response, 200, { role:session ? session.role : null, setupRequired:setupIsRequired() });
    return;
  }

  if(request.method === 'POST' && pathname === '/api/setup'){
    if(!(request.headers['content-type'] || '').toLowerCase().startsWith('application/json')){
      sendError(response, 415, 'Setup requests must use JSON.');
      return;
    }
    const body = await readJson(request);
    const suppliedToken = typeof body.setupCode === 'string' ? body.setupCode : '';
    const expectedHash = crypto.createHash('sha256').update(setupToken || '').digest();
    const suppliedHash = crypto.createHash('sha256').update(suppliedToken).digest();
    const setupCodeValid = crypto.timingSafeEqual(expectedHash, suppliedHash) && Boolean(setupToken);
    if(!setupCodeValid){
      sendError(response, 403, 'The setup code is invalid or setup is already complete.');
      return;
    }
    const adminPin = typeof body.adminPin === 'string' ? body.adminPin : '';
    const studentPin = typeof body.studentPin === 'string' ? body.studentPin : '';
    if(!validPin(adminPin) || !validPin(studentPin)){
      sendError(response, 400, `Each PIN must contain 1 to ${MAX_PIN_LENGTH} characters.`);
      return;
    }
    if(adminPin === studentPin){
      sendError(response, 400, 'Admin and Student PINs must be different.');
      return;
    }
    const records = {
      admin:makePinRecord(adminPin),
      student:makePinRecord(studentPin)
    };
    try{
      transaction(() => {
        if(!setupIsRequired()) throw new Error('Setup has already been completed.');
        const updated = new Date().toISOString();
        for(const role of ['admin','student']){
          const account = accountForRole(role);
          const record = records[role];
          if(account){
            database.prepare('UPDATE user_accounts SET pin_salt=?, pin_hash=?, updated=? WHERE role=?')
              .run(record.salt, record.hash, updated, role);
          }else{
            const placeholderSalt = crypto.randomBytes(16);
            const placeholderHash = crypto.scryptSync(crypto.randomBytes(32).toString('hex'), placeholderSalt, 64);
            const username = `internal-${role}-${crypto.randomBytes(16).toString('hex')}`;
            database.prepare(`
              INSERT INTO user_accounts (role, username, salt, password_hash, pin_salt, pin_hash, updated)
              VALUES (?, ?, ?, ?, ?, ?, ?)
            `).run(role, username, placeholderSalt, placeholderHash, record.salt, record.hash, updated);
          }
        }
      });
    }catch(error){
      if(error.message === 'Setup has already been completed.'){
        sendError(response, 409, error.message);
        return;
      }
      throw error;
    }
    setupToken = null;
    sendJson(response, 201, { ok:true });
    return;
  }

  if(request.method === 'POST' && pathname === '/api/reset-pin'){
    if(setupIsRequired()){
      sendError(response, 409, 'Complete first-run account setup before resetting a PIN.');
      return;
    }
    if(!(request.headers['content-type'] || '').toLowerCase().startsWith('application/json')){
      sendError(response, 415, 'PIN reset requests must use JSON.');
      return;
    }
    const body = await readJson(request);
    const suppliedCode = typeof body.recoveryCode === 'string' ? body.recoveryCode : '';
    const expectedHash = crypto.createHash('sha256').update(pinResetToken || '').digest();
    const suppliedHash = crypto.createHash('sha256').update(suppliedCode).digest();
    if(!pinResetToken || !crypto.timingSafeEqual(expectedHash, suppliedHash)){
      sendError(response, 403, 'The recovery code is invalid or has already been used.');
      return;
    }
    const targetRole = typeof body.role === 'string' ? body.role : '';
    if(!['admin','student'].includes(targetRole)){
      sendError(response, 400, 'Choose an Admin or Student account to reset.');
      return;
    }
    const pin = typeof body.pin === 'string' ? body.pin : '';
    if(!validPin(pin)){
      sendError(response, 400, `PINs must contain 1 to ${MAX_PIN_LENGTH} characters.`);
      return;
    }
    const otherRole = targetRole === 'admin' ? 'student' : 'admin';
    if(verifyPin(accountForRole(otherRole), pin)){
      sendError(response, 400, 'Admin and Student PINs must be different.');
      return;
    }
    const record = makePinRecord(pin);
    transaction(() => {
      database.prepare('UPDATE user_accounts SET pin_salt=?, pin_hash=?, updated=? WHERE role=?')
        .run(record.salt, record.hash, new Date().toISOString(), targetRole);
    });
    pinResetToken = null;
    const resetSession = getSession(request);
    for(const [token, activeSession] of sessions){
      if(activeSession.role === targetRole) sessions.delete(token);
    }
    const headers = resetSession && resetSession.role === targetRole ? {
      'Set-Cookie':`${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`
    } : {};
    sendJson(response, 200, { ok:true, role:targetRole }, headers);
    return;
  }

  if(request.method === 'POST' && pathname === '/api/login'){
    if(setupIsRequired()){
      sendError(response, 409, 'Complete first-run account setup before signing in.');
      return;
    }
    const now = Date.now();
    const ip = request.socket.remoteAddress || 'unknown';
    const attempt = loginAttempts.get(ip);
    if(attempt && attempt.resetAt > now && attempt.count >= MAX_LOGIN_ATTEMPTS){
      sendError(response, 429, 'Too many sign-in attempts. Try again in 15 minutes.');
      return;
    }
    const contentType = request.headers['content-type'] || '';
    if(!contentType.toLowerCase().startsWith('application/json')){
      sendError(response, 415, 'Sign-in requests must use JSON.');
      return;
    }
    const body = await readJson(request);
    const requestedRole = typeof body.role === 'string' ? body.role : '';
    const pin = typeof body.pin === 'string' ? body.pin : '';
    const role = ['admin','student'].includes(requestedRole) ? requestedRole : null;
    const account = role ? accountForRole(role) : null;
    const valid = verifyPin(account, pin);
    if(!role || !account || !valid){
      const current = attempt && attempt.resetAt > now ? attempt : { count:0, resetAt:now + LOGIN_WINDOW_MS };
      current.count += 1;
      loginAttempts.set(ip, current);
      sendError(response, 401, 'Incorrect PIN.');
      return;
    }

    loginAttempts.delete(ip);
    const token = crypto.randomBytes(32).toString('base64url');
    sessions.set(token, { role, expiresAt:now + SESSION_TTL_MS });
    const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    sendJson(response, 200, { role }, {
      'Set-Cookie':`${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}${secure}`
    });
    return;
  }

  const session = getSession(request);
  if(request.method === 'POST' && pathname === '/api/logout'){
    if(session) sessions.delete(session.token);
    sendJson(response, 200, { ok:true }, {
      'Set-Cookie':`${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`
    });
    return;
  }

  if(request.method === 'GET' && pathname === '/api/state'){
    if(!session){
      sendError(response, 401, 'Enter a PIN to access the application.');
      return;
    }
    sendJson(response, 200, loadState(session.role));
    return;
  }

  if(request.method === 'POST' && pathname.startsWith('/api/accounts/')){
    if(!requireRole(session, ['admin'])){
      sendError(response, session ? 403 : 401, 'Only an admin can change account PINs.');
      return;
    }
    if(!(request.headers['content-type'] || '').toLowerCase().startsWith('application/json')){
      sendError(response, 415, 'PIN updates must use JSON.');
      return;
    }
    const targetRole = pathname.slice('/api/accounts/'.length);
    if(!['admin','student'].includes(targetRole)){
      sendError(response, 404, 'Account role not found.');
      return;
    }
    const body = await readJson(request);
    const pin = typeof body.pin === 'string' ? body.pin : '';
    const currentAdminPin = typeof body.currentAdminPin === 'string' ? body.currentAdminPin : '';
    if(!validPin(pin)){
      sendError(response, 400, `PINs must contain 1 to ${MAX_PIN_LENGTH} characters.`);
      return;
    }
    if(!verifyPin(accountForRole('admin'), currentAdminPin)){
      sendError(response, 401, 'Enter the current Admin PIN to confirm this change.');
      return;
    }
    const otherRole = targetRole === 'admin' ? 'student' : 'admin';
    const otherAccount = accountForRole(otherRole);
    if(verifyPin(otherAccount, pin)){
      sendError(response, 400, 'Admin and Student PINs must be different.');
      return;
    }
    const record = makePinRecord(pin);
    transaction(() => {
      database.prepare('UPDATE user_accounts SET pin_salt=?, pin_hash=?, updated=? WHERE role=?')
        .run(record.salt, record.hash, new Date().toISOString(), targetRole);
    });
    for(const [token, activeSession] of sessions){
      if(activeSession.role === targetRole) sessions.delete(token);
    }
    const headers = targetRole === 'admin' ? {
      'Set-Cookie':`${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`
    } : {};
    sendJson(response, 200, { ok:true }, headers);
    return;
  }

  if(request.method === 'POST' && pathname === '/api/register'){
    if(!requireRole(session, ['admin','student'])){
      sendError(response, session ? 403 : 401, 'You are not allowed to register students.');
      return;
    }
    if(!(request.headers['content-type'] || '').toLowerCase().startsWith('application/json')){
      sendError(response, 415, 'Registration requests must use JSON.');
      return;
    }
    const body = await readJson(request);
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    const age = Number(body.age);
    const guardian = typeof body.guardian === 'string' ? body.guardian.trim() : '';
    const guardianPhoneInput = typeof body.guardianPhone === 'string' ? body.guardianPhone.trim() : '';
    const guardianPhone = guardianPhoneInput.replace(/[\s-]/g, '');
    const smsConsent = body.smsConsent === true;
    if(!name || name.length > 120 || !guardian || guardian.length > 120){
      sendError(response, 400, 'Enter valid student and guardian names.');
      return;
    }
    if(!smsConsent){
      sendError(response, 400, 'Confirm that the guardian agrees to receive student registration and check-in SMS messages.');
      return;
    }
    if(!Number.isInteger(age) || age < 3 || age > 25){
      sendError(response, 400, 'Enter a valid age from 3 to 25.');
      return;
    }
    if(!/^\+?[0-9]{9,15}$/.test(guardianPhone)){
      sendError(response, 400, 'Enter a valid guardian phone number.');
      return;
    }
    const student = {
      id:makeStudentId(), name, age, guardian, guardianPhone,
      registered:new Date().toISOString()
    };
    const log = transaction(() => {
      database.prepare(`
        INSERT INTO students (id, name, age, guardian, guardian_phone, sms_consent, registered)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(student.id, student.name, student.age, student.guardian, student.guardianPhone, 1, student.registered);
      return recordLog(student, 'register',
        `Hello ${guardian}, ${name} is now registered. Student ID: ${student.id}. Registration and check-in alerts will be sent by SMS.`,
        student.registered);
    });
    const delivery = await deliverSMS(log);
    sendJson(response, 201, { student, log:delivery });
    return;
  }

  if(request.method === 'POST' && pathname === '/api/checkins'){
    if(!requireRole(session, ['admin','student'])){
      sendError(response, session ? 403 : 401, 'You are not allowed to check students in.');
      return;
    }
    if(!(request.headers['content-type'] || '').toLowerCase().startsWith('application/json')){
      sendError(response, 415, 'Check-in requests must use JSON.');
      return;
    }
    const body = await readJson(request);
    const studentId = typeof body.studentId === 'string' ? body.studentId.trim().toUpperCase() : '';
    const row = database.prepare('SELECT * FROM students WHERE id=?').get(studentId);
    if(!row){
      sendError(response, 404, `Unknown student ID: ${studentId || '(empty)'}.`);
      return;
    }
    const student = studentFromRow(row);
    const time = new Date().toISOString();
    const message = `Hello ${student.guardian}, ${student.name} checked in at ${new Date(time).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' })} on ${new Date(time).toLocaleDateString()}.`;
    const log = transaction(() => {
      database.prepare('INSERT INTO checkins (student_id, name, time) VALUES (?, ?, ?)')
        .run(student.id, student.name, time);
      return recordLog(student, 'checkin', message, time);
    });
    const delivery = row.sms_consent
      ? await deliverSMS(log)
      : { ...log, deliveryStatus:'not_consented', deliveryError:'' };
    if(!row.sms_consent){
      database.prepare('UPDATE logs SET delivery_status=?, delivery_error=? WHERE id=?')
        .run(delivery.deliveryStatus, delivery.deliveryError, log.id);
    }
    sendJson(response, 201, {
      checkin:{ studentId:student.id, name:student.name, time },
      log:delivery
    });
    return;
  }

  if(request.method === 'POST' && pathname === '/api/events'){
    if(!requireRole(session, ['admin'])){
      sendError(response, session ? 403 : 401, 'Only an admin can manage events.');
      return;
    }
    if(!(request.headers['content-type'] || '').toLowerCase().startsWith('application/json')){
      sendError(response, 415, 'Event requests must use JSON.');
      return;
    }
    const body = await readJson(request);
    const title = typeof body.title === 'string' ? body.title.trim() : '';
    const date = typeof body.date === 'string' ? body.date : '';
    const time = typeof body.time === 'string' ? body.time : '';
    const place = typeof body.place === 'string' ? body.place.trim() : '';
    const info = typeof body.info === 'string' ? body.info.trim() : '';
    const parsedDate = /^\d{4}-\d{2}-\d{2}$/.test(date) ? new Date(`${date}T00:00:00Z`) : null;
    if(!title || title.length > 160 || !parsedDate || Number.isNaN(parsedDate.getTime()) || parsedDate.toISOString().slice(0,10) !== date){
      sendError(response, 400, 'Enter a valid event title and date.');
      return;
    }
    if(time && (!/^\d{2}:\d{2}$/.test(time) || Number(time.slice(0,2)) > 23 || Number(time.slice(3,5)) > 59)){
      sendError(response, 400, 'Enter a valid event time.');
      return;
    }
    if(place.length > 200 || info.length > 4000){
      sendError(response, 400, 'Event venue or details are too long.');
      return;
    }
    const students = database.prepare('SELECT * FROM students').all().map(studentFromRow);
    if(!students.length){
      sendError(response, 400, 'Register students first so there are guardians to notify.');
      return;
    }
    const when = new Date(date + 'T00:00').toLocaleDateString([], { dateStyle:'full' }) + (time ? ' at ' + time : '');
    const { event, logs } = transaction(() => {
      const result = database.prepare(`
        INSERT INTO events (title, date, time, place, info) VALUES (?, ?, ?, ?, ?)
      `).run(title, date, time, place, info);
      const newEvent = { id:Number(result.lastInsertRowid), title, date, time, place, info };
      const newLogs = students.map(student => {
        const message = `Hello ${student.guardian}, new school event for ${student.name}: ${title}. When: ${when}.${place ? ' Where: ' + place + '.' : ''}${info ? ' Details: ' + info : ''}`;
        return recordLog(student, 'event', message);
      });
      return { event:newEvent, logs:newLogs };
    });
    sendJson(response, 201, { event, logs, notified:students.length });
    return;
  }

  if(request.method === 'DELETE' && pathname.startsWith('/api/students/')){
    if(!requireRole(session, ['admin'])){
      sendError(response, session ? 403 : 401, 'Only an admin can remove students.');
      return;
    }
    const studentId = decodeURIComponent(pathname.slice('/api/students/'.length));
    const result = database.prepare('DELETE FROM students WHERE id=?').run(studentId);
    if(!result.changes){
      sendError(response, 404, 'Student not found.');
      return;
    }
    sendJson(response, 200, { ok:true });
    return;
  }

  if(request.method === 'DELETE' && pathname === '/api/logs'){
    if(!requireRole(session, ['admin'])){
      sendError(response, session ? 403 : 401, 'Only an admin can clear notifications.');
      return;
    }
    database.prepare('DELETE FROM logs').run();
    sendJson(response, 200, { ok:true });
    return;
  }

  sendError(response, 404, 'API route not found.');
}

const server = http.createServer(async (request, response) => {
  try{
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
    if(url.pathname.startsWith('/api/')){
      await handleApi(request, response, url);
    }else if(request.method === 'GET'){
      staticFile(response, url.pathname);
    }else{
      sendError(response, 405, 'Method not allowed.');
    }
  }catch(error){
    if(response.headersSent) return;
    if(error.status){
      sendError(response, error.status, error.status === 400 ? 'Invalid JSON request.' : error.message);
      return;
    }
    console.error('Request failed:', error);
    sendError(response, 500, 'The server could not complete the request.');
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Ubuntu Waterhub is running at http://${HOST}:${PORT}`);
  if(smsProviderConfigured()){
    console.log(`Guardian SMS is enabled via Africa's Talking (${process.env.AT_ENVIRONMENT === 'sandbox' ? 'sandbox' : 'live'}).`);
  }else{
    console.warn('Guardian SMS is disabled. Set AT_USERNAME and AT_API_KEY before starting the server.');
  }
});

for(const signal of ['SIGINT','SIGTERM']){
  process.on(signal, () => {
    clearInterval(cleanupTimer);
    database.close();
    server.close(() => process.exit(0));
  });
}
