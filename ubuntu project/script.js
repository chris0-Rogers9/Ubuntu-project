/* ===================== JAVASCRIPT ===================== */
const $ = selector => document.querySelector(selector);
const esc = value => String(value).replace(/[&<>"']/g, char => ({
  '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'
}[char]));
let db = { students: [], events: [], checkins: [], logs: [] };
let role = null;

function toast(message){
  const element = $('#toast');
  element.textContent = message;
  element.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => element.classList.remove('show'), 3200);
}

function smsFeedback(log){
  if(log.deliveryStatus === 'accepted') return 'Guardian SMS accepted by provider.';
  if(log.deliveryStatus === 'failed') return `SMS failed: ${log.deliveryError || 'check provider settings.'}`;
  if(log.deliveryStatus === 'not_consented') return 'Guardian has not consented to SMS.';
  return 'SMS not sent: configure Africa’s Talking credentials on the server.';
}

const fmt = iso => new Date(iso).toLocaleString([], { dateStyle:'medium', timeStyle:'short' });

async function api(path, options = {}){
  let response;
  try{
    response = await fetch(path, {
      credentials:'same-origin',
      ...options,
      headers:{
        ...(options.body ? { 'Content-Type':'application/json' } : {}),
        ...options.headers
      }
    });
  }catch(error){
    if(error instanceof TypeError){
      throw new Error('Cannot reach the Waterhub server. Start it with "npm start" and open http://localhost:3000 (do not open index.html directly).', { cause:error });
    }
    throw error;
  }
  let result;
  try{
    result = await response.json();
  }catch(error){
    if(location.protocol === 'file:'){
      throw new Error('You opened index.html directly. Start the app with "npm start", then open http://localhost:3000 to sign in.', { cause:error });
    }
    throw new Error(`The Waterhub server returned an invalid response (HTTP ${response.status}). Restart it with "npm start" and reload the page.`, { cause:error });
  }
  if(!response.ok) throw new Error(result.error || `The request failed (HTTP ${response.status}).`);
  return result;
}

function render(){
  renderStudents();
  renderChecks();
  renderEvents();
  renderLogs();
}

function updateAccess(nextRole){
  role = nextRole;
  const isAdmin = role === 'admin';
  $('#loginCredentials').hidden = true;
  $('#loginRole').value = '';
  $('#loginPin').value = '';
  $('#loginCard').hidden = false;
  document.querySelectorAll('.role-choice').forEach(button => {
    button.setAttribute('aria-pressed', 'false');
  });
  $('#loginView').hidden = Boolean(role);
  $('#loginForm').hidden = false;
  $('#setupCard').hidden = Boolean(role);
  $('#resetPinCard').hidden = true;
  $('#appNav').hidden = !role;
  $('#appMain').hidden = !role;
  $('#sessionBar').hidden = !role;
  $('#currentRole').textContent = isAdmin ? 'Admin' : 'Student';

  document.querySelectorAll('#appNav button').forEach(button => {
    const allowed = isAdmin || ['register','checkin'].includes(button.dataset.tab);
    button.hidden = !allowed;
  });
  if(role){
    const defaultTab = 'register';
    document.querySelectorAll('#appNav button').forEach(button => {
      button.setAttribute('aria-selected', button.dataset.tab === defaultTab);
    });
    document.querySelectorAll('#appMain section').forEach(section => {
      section.classList.toggle('active', section.id === defaultTab);
    });
  }
}

function showSetup(){
  updateAccess(null);
  $('#loginView').hidden = false;
  $('#loginCard').hidden = true;
  $('#loginForm').hidden = true;
  $('#resetPinCard').hidden = true;
  $('#setupCard').hidden = false;
  $('#appNav').hidden = true;
  $('#appMain').hidden = true;
  $('#sessionBar').hidden = true;
}

function showLogin(message){
  updateAccess(null);
  $('#loginView').hidden = false;
  $('#loginCard').hidden = false;
  $('#loginForm').hidden = false;
  $('#setupCard').hidden = true;
  $('#resetPinCard').hidden = true;
  if(message) $('#loginMessage').textContent = message;
}

async function loadState(){
  db = await api('/api/state');
  render();
}

$('#setupForm').addEventListener('submit', async event => {
  event.preventDefault();
  const adminPin = $('#setupAdminPin').value;
  const studentPin = $('#setupStudentPin').value;
  if(adminPin !== $('#setupAdminConfirm').value || studentPin !== $('#setupStudentConfirm').value){
    $('#setupMessage').textContent = 'Each PIN and its confirmation must match.';
    return;
  }
  if(adminPin === studentPin){
    $('#setupMessage').textContent = 'Choose different PINs for Admin and Student.';
    return;
  }
  $('#setupMessage').textContent = 'Saving PINs…';
  try{
    await api('/api/setup', {
      method:'POST',
      body:JSON.stringify({
        setupCode:$('#setupCode').value.trim(),
        adminPin,
        studentPin
      })
    });
    $('#setupForm').reset();
    showLogin('PINs saved. Choose Admin or Student and enter its PIN.');
  }catch(error){
    $('#setupMessage').textContent = error.message;
  }
});

$('#showResetPin').addEventListener('click', () => {
  $('#loginCard').hidden = true;
  $('#resetPinCard').hidden = false;
  $('#resetPinMessage').textContent = '';
  $('#resetCode').focus();
});

$('#cancelResetPin').addEventListener('click', () => {
  $('#resetPinForm').reset();
  showLogin();
});

$('#resetPinForm').addEventListener('submit', async event => {
  event.preventDefault();
  const pin = $('#resetNewPin').value;
  if(pin !== $('#resetConfirmPin').value){
    $('#resetPinMessage').textContent = 'The new PIN and confirmation do not match.';
    return;
  }
  $('#resetPinMessage').textContent = 'Resetting PIN…';
  try{
    const result = await api('/api/reset-pin', {
      method:'POST',
      body:JSON.stringify({
        role:$('#resetRole').value,
        recoveryCode:$('#resetCode').value.trim(),
        pin
      })
    });
    $('#resetPinForm').reset();
    showLogin(`${result.role === 'admin' ? 'Admin' : 'Student'} PIN reset. Sign in with the new PIN.`);
  }catch(error){
    $('#resetPinMessage').textContent = error.message;
  }
});

$('#loginForm').addEventListener('submit', async event => {
  event.preventDefault();
  $('#loginMessage').textContent = 'Signing in…';
  try{
    const result = await api('/api/login', {
      method:'POST',
      body:JSON.stringify({
        role:$('#loginRole').value,
        pin:$('#loginPin').value
      })
    });
    updateAccess(result.role);
    await loadState();
  }catch(error){
    $('#loginMessage').textContent = error.message;
  }
});

$('#loginPin').addEventListener('keydown', event => {
  if(event.key === 'Enter'){
    event.preventDefault();
    $('#loginForm').requestSubmit();
  }
});

document.querySelectorAll('.role-choice').forEach(button => button.addEventListener('click', () => {
  $('#loginRole').value = button.dataset.role;
  document.querySelectorAll('.role-choice').forEach(choice => {
    choice.setAttribute('aria-pressed', String(choice === button));
  });
  $('#loginCredentials').hidden = false;
  $('#loginMessage').textContent = '';
  $('#loginPin').focus();
}));

$('#logoutBtn').addEventListener('click', async () => {
  await stopScan();
  try{
    await api('/api/logout', { method:'POST' });
  }catch(error){
    toast(error.message);
    return;
  }
  db = { students: [], events: [], checkins: [], logs: [] };
  updateAccess(null);
  $('#loginMessage').textContent = 'You have signed out.';
});

document.querySelectorAll('[data-account-role]').forEach(form => form.addEventListener('submit', async event => {
  event.preventDefault();
  const targetRole = form.dataset.accountRole;
  const prefix = targetRole === 'admin' ? 'Admin' : 'Student';
  const pin = $('#new' + prefix + 'Pin').value;
  const confirmPin = $('#confirm' + prefix + 'Pin').value;
  const currentAdminPin = $('#' + (targetRole === 'admin' ? 'adminCurrentPin' : 'studentCurrentPin')).value;
  if(pin !== confirmPin){
    toast('The new PIN and confirmation do not match.');
    return;
  }
  try{
    await api('/api/accounts/' + targetRole, {
      method:'POST',
      body:JSON.stringify({ pin, currentAdminPin })
    });
    form.reset();
    if(targetRole === 'admin'){
      db = { students:[], events:[], checkins:[], logs:[], accounts:[] };
      showLogin('Admin PIN changed. Enter the new PIN to sign in again.');
      toast('Admin PIN changed.');
      return;
    }
    toast('Student PIN changed.');
  }catch(error){
    toast(error.message);
  }
}));

document.querySelectorAll('#appNav button').forEach(button => button.addEventListener('click', () => {
  if(button.hidden) return;
  document.querySelectorAll('#appNav button').forEach(item => item.setAttribute('aria-selected', item === button));
  document.querySelectorAll('#appMain section').forEach(section => {
    section.classList.toggle('active', section.id === button.dataset.tab);
  });
  if(button.dataset.tab !== 'checkin') stopScan();
}));

/* ---------- QR ---------- */
function makeQR(element, text, size){
  element.innerHTML = '';
  new QRCode(element, { text, width:size, height:size, correctLevel:QRCode.CorrectLevel.M });
}
function downloadQR(id){
  const holder = document.createElement('div');
  makeQR(holder, id, 320);
  setTimeout(() => {
    const canvas = holder.querySelector('canvas');
    const image = holder.querySelector('img');
    const link = document.createElement('a');
    link.download = id + '.png';
    link.href = canvas ? canvas.toDataURL('image/png') : image.src;
    link.click();
  }, 150);
}
function showNewQR(student){
  $('#newQR').hidden = false;
  $('#newQRBody').innerHTML = `<div class="qr" id="nq"></div>
    <div class="meta"><strong>${esc(student.name)}, age ${student.age}</strong><span>ID: ${esc(student.id)}</span>
    <span>Guardian: ${esc(student.guardian)} (${esc(student.guardianPhone)})</span>
    <div class="row"><button class="btn small" id="nqDl">Download QR</button></div></div>`;
  makeQR($('#nq'), student.id, 140);
  $('#nqDl').onclick = () => downloadQR(student.id);
}

/* ---------- Register ---------- */
$('#regBtn').addEventListener('click', async () => {
  if(!$('#guardianSmsConsent').checked){
    toast('Get the guardian’s consent for registration and check-in SMS messages first.');
    return;
  }
  const student = {
    name:$('#sName').value.trim(),
    age:Number($('#sAge').value),
    guardian:$('#gName').value.trim(),
    guardianPhone:$('#gPhone').value.trim().replace(/[\s-]/g,''),
    smsConsent:$('#guardianSmsConsent').checked
  };
  try{
    const result = await api('/api/register', { method:'POST', body:JSON.stringify(student) });
    if(role === 'admin') db.logs.unshift(result.log);
    ['sName','sAge','gName','gPhone'].forEach(id => $('#'+id).value = '');
    $('#guardianSmsConsent').checked = false;
    showNewQR(result.student);
    toast(`Student registered. ${smsFeedback(result.log)}`);
  }catch(error){
    toast(error.message);
  }
});

/* ---------- Students ---------- */
function renderStudents(){
  if(!role || role !== 'admin') return;
  const query = $('#search').value.toLowerCase();
  const students = db.students.filter(student => (student.name + student.guardian).toLowerCase().includes(query));
  $('#count').textContent = db.students.length;
  const box = $('#studentList');
  if(!students.length){
    box.innerHTML = '<div class="empty">No students yet. Register one to get started.</div>';
    return;
  }
  box.innerHTML = students.map(student => `<div class="card stu"><div class="qr" data-qr="${esc(student.id)}"></div>
    <div class="meta"><strong>${esc(student.name)}</strong><span>${esc(student.id)} · age ${student.age}</span>
    <span>${esc(student.guardian)}</span><span>${esc(student.guardianPhone)}</span>
    <div class="row"><button class="btn alt small" data-dl="${esc(student.id)}">Download</button>
    <button class="btn alt small" data-del="${esc(student.id)}">Remove</button></div></div></div>`).join('');
  box.querySelectorAll('[data-qr]').forEach(element => makeQR(element, element.dataset.qr, 96));
  box.querySelectorAll('[data-dl]').forEach(button => button.onclick = () => downloadQR(button.dataset.dl));
  box.querySelectorAll('[data-del]').forEach(button => button.onclick = async () => {
    if(!confirm('Remove this student?')) return;
    try{
      await api('/api/students/' + encodeURIComponent(button.dataset.del), { method:'DELETE' });
      await loadState();
    }catch(error){
      toast(error.message);
    }
  });
}
$('#search').addEventListener('input', renderStudents);

/* ---------- Check-in ---------- */
let scanner = null;
let lastScan = { id:'', time:0 };
async function checkIn(raw){
  const id = String(raw).trim().toUpperCase();
  if(id === lastScan.id && Date.now() - lastScan.time < 4000) return;
  lastScan = { id, time:Date.now() };
  try{
    const result = await api('/api/checkins', { method:'POST', body:JSON.stringify({ studentId:id }) });
    db.checkins.unshift(result.checkin);
    if(role === 'admin') db.logs.unshift(result.log);
    renderChecks();
    toast(`${result.checkin.name} checked in. ${smsFeedback(result.log)}`);
  }catch(error){
    toast(error.message);
  }
}
async function startScan(){
  try{
    if(scanner) return;
    scanner = new Html5Qrcode('reader');
    await scanner.start({ facingMode:'environment' }, { fps:10, qrbox:220 }, text => checkIn(text));
  }catch(error){
    scanner = null;
    toast('Camera unavailable. Use the student ID box or upload a QR image.');
  }
}
async function stopScan(){
  if(!scanner) return;
  const activeScanner = scanner;
  scanner = null;
  try{
    await activeScanner.stop();
    activeScanner.clear();
  }catch(error){
    toast('Could not stop the camera cleanly. Close the camera permission prompt if it remains open.');
  }
}
$('#startScan').onclick = startScan;
$('#stopScan').onclick = stopScan;
$('#manualBtn').onclick = async () => {
  const value = $('#manualId').value;
  if(value){
    await checkIn(value);
    $('#manualId').value = '';
  }
};
$('#manualId').addEventListener('keydown', event => {
  if(event.key === 'Enter') $('#manualBtn').click();
});

async function decodeUploadedQR(file, input){
  if(!file) return toast('Select a QR code image first.');
  let uploader;
  try{
    await stopScan();
    uploader = new Html5Qrcode('reader');
    const decoded = await uploader.scanFile(file, true);
    await checkIn(decoded);
  }catch(error){
    toast('Could not read a QR code from that image. Try another file.');
  }finally{
    if(uploader) await uploader.clear();
    input.value = '';
  }
}
$('#uploadQRBtn').onclick = () => $('#qrUpload').click();
$('#captureQRBtn').onclick = () => $('#qrCamera').click();
['qrUpload','qrCamera'].forEach(id => {
  const input = $('#'+id);
  input.addEventListener('change', event => {
    const file = event.target.files && event.target.files[0];
    if(file) decodeUploadedQR(file, input);
  });
});

function renderChecks(){
  const today = new Date().toDateString();
  const checkins = db.checkins.filter(item => new Date(item.time).toDateString() === today);
  $('#checkList').innerHTML = checkins.length
    ? checkins.map(item => `<div class="log"><strong>${esc(item.name)}</strong><small>${esc(item.studentId)} · ${fmt(item.time)}</small></div>`).join('')
    : '<div class="empty">No check-ins yet today.</div>';
}

/* ---------- Events ---------- */
$('#eventBtn').addEventListener('click', async () => {
  const eventData = {
    title:$('#eTitle').value.trim(),
    date:$('#eDate').value,
    time:$('#eTime').value,
    place:$('#ePlace').value.trim(),
    info:$('#eInfo').value.trim()
  };
  try{
    const result = await api('/api/events', { method:'POST', body:JSON.stringify(eventData) });
    ['eTitle','eDate','eTime','ePlace','eInfo'].forEach(id => $('#'+id).value = '');
    db.events.unshift(result.event);
    db.logs = result.logs.concat(db.logs);
    render();
    toast(`Event added. ${result.notified} guardian(s) notified.`);
  }catch(error){
    toast(error.message);
  }
});
function renderEvents(){
  const box = $('#eventList');
  if(!box) return;
  box.innerHTML = db.events.length
    ? db.events.map(event => `<div class="log event"><strong>${esc(event.title)}</strong>
        <small>${esc(event.date)} ${esc(event.time || '')} ${event.place ? '· ' + esc(event.place) : ''}</small>
        ${event.info ? '<div>' + esc(event.info) + '</div>' : ''}</div>`).join('')
    : '<div class="empty">No events yet. Add one above and every guardian gets the details.</div>';
}

/* ---------- Notification log ---------- */
function renderLogs(){
  const box = $('#logList');
  if(!box) return;
  if(!db.logs.length){
    box.innerHTML = '<div class="empty">No notifications yet.</div>';
    return;
  }
  box.innerHTML = db.logs.slice(0,100).map(log => `<div class="log ${log.type === 'event' ? 'event' : ''}">
    <span class="badge">${esc(log.type)}</span> <strong>${esc(log.guardian)}</strong> · ${esc(log.to)}
    <small>${fmt(log.time)} · SMS: ${esc(log.deliveryStatus || 'not_sent')}${log.deliveryError ? ' · ' + esc(log.deliveryError) : ''}</small><div>${esc(log.message)}</div>
    <div class="row"><a class="btn alt small" style="text-decoration:none" href="sms:${encodeURIComponent(log.to)}?&body=${encodeURIComponent(log.message)}">Open SMS app</a></div></div>`).join('');
}

$('#clearLog').onclick = async () => {
  if(!confirm('Clear the notification log?')) return;
  try{
    await api('/api/logs', { method:'DELETE' });
    db.logs = [];
    renderLogs();
  }catch(error){
    toast(error.message);
  }
};

async function restoreSession(){
  try{
    const result = await api('/api/session');
    if(result.role){
      updateAccess(result.role);
      await loadState();
    }else if(result.setupRequired){
      showSetup();
    }else{
      showLogin();
    }
  }catch(error){
    $('#loginMessage').textContent = error.message;
  }
}
restoreSession();
