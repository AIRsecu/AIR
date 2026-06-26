/* ============================================================
 *  app.js  - SPA 라우터 + 역할별 화면
 *  역할: super_admin / admin / customer
 * ============================================================ */

// ── 공통 헬퍼 ─────────────────────────────────────────────
const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const app = () => $('#app');

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const money = (n) => (n == null ? '-' : Number(n).toLocaleString('ko-KR') + '원');
const fmtDate = (s) => s ? String(s).replace('T', ' ').slice(0, 19) : '-';
const shortId = (s) => s ? String(s).slice(0, 8) + '…' : '-';

function toast(msg, type = 'info', title) {
  const box = document.createElement('div');
  box.className = 'toast ' + type;
  box.innerHTML = (title ? `<div class="t-title">${esc(title)}</div>` : '') + esc(msg);
  $('#toasts').appendChild(box);
  setTimeout(() => { box.style.opacity = '0'; box.style.transition = 'opacity .3s'; }, 3200);
  setTimeout(() => box.remove(), 3600);
}
const ok   = (m, t) => toast(m, 'success', t);
const fail = (m, t) => toast(m, 'error', t || '오류');

function roleBadge(role) {
  const map = { super_admin: 'indigo', admin: 'cyan', customer: 'gray' };
  return `<span class="badge ${map[role] || 'gray'}">${esc(role)}</span>`;
}
function activeBadge(active) {
  return active
    ? '<span class="badge green">● 활성</span>'
    : '<span class="badge gray">○ 비활성</span>';
}
const ORDER_STATUS = [
  { value: 'pending',   ko: '대기' },
  { value: 'paid',      ko: '결제완료' },
  { value: 'shipped',   ko: '배송완료' },
  { value: 'cancelled', ko: '취소' },
];
const statusKo = (s) => (ORDER_STATUS.find(x => x.value === s) || {}).ko || s;

function statusBadge(s) {
  const map = { pending: 'amber', paid: 'green', shipped: 'cyan', cancelled: 'red' };
  return `<span class="badge ${map[s] || 'gray'}">${esc(statusKo(s))}</span>`;
}

// ── 모달 / 폼 ─────────────────────────────────────────────
function closeModal() { $('#modal-root').innerHTML = ''; }

function openModal({ title, body, footer }) {
  $('#modal-root').innerHTML = `
    <div class="modal-back" data-close>
      <div class="modal" role="dialog">
        <div class="modal-head"><h3>${esc(title)}</h3><button class="x" data-close>×</button></div>
        <div class="modal-body">${body}</div>
        ${footer ? `<div class="modal-foot">${footer}</div>` : ''}
      </div>
    </div>`;
  $$('[data-close]').forEach(e => e.addEventListener('click', ev => {
    if (ev.target.hasAttribute('data-close')) closeModal();
  }));
}

/* 필드 정의로 폼 모달 생성.
   fields: [{name,label,type,value,required,hint,options:[{value,label}],min}] */
function openFormModal({ title, fields, submitLabel = '저장', onSubmit }) {
  const fieldHtml = fields.map(f => {
    const req = f.required ? 'required' : '';
    if (f.type === 'select') {
      const opts = (f.options || []).map(o =>
        `<option value="${esc(o.value)}" ${String(o.value) === String(f.value) ? 'selected' : ''}>${esc(o.label)}</option>`).join('');
      return `<div class="field"><label>${esc(f.label)}</label><select name="${f.name}" ${req}>${opts}</select>${f.hint ? `<div class="hint">${esc(f.hint)}</div>` : ''}</div>`;
    }
    if (f.type === 'textarea') {
      return `<div class="field"><label>${esc(f.label)}</label><textarea name="${f.name}" rows="3" ${req}>${esc(f.value || '')}</textarea></div>`;
    }
    if (f.type === 'checkbox') {
      return `<div class="field"><label style="display:flex;gap:8px;align-items:center;cursor:pointer"><input type="checkbox" name="${f.name}" style="width:auto" ${f.value ? 'checked' : ''}/> ${esc(f.label)}</label></div>`;
    }
    return `<div class="field"><label>${esc(f.label)}</label>
      <input name="${f.name}" type="${f.type || 'text'}" value="${esc(f.value ?? '')}" ${f.min != null ? `min="${f.min}"` : ''} ${req}/>
      ${f.hint ? `<div class="hint">${esc(f.hint)}</div>` : ''}</div>`;
  }).join('');

  openModal({
    title,
    body: `<div class="err-box" id="modal-err"></div><form id="modal-form">${fieldHtml}</form>`,
    footer: `<button class="btn btn-ghost" data-close>취소</button>
             <button class="btn btn-primary" id="modal-submit">${esc(submitLabel)}</button>`,
  });

  const submit = async () => {
    const form = $('#modal-form');
    const data = {};
    fields.forEach(f => {
      const elr = form.elements[f.name];
      if (!elr) return;
      if (f.type === 'checkbox') data[f.name] = elr.checked;
      else if (f.type === 'number') data[f.name] = elr.value === '' ? null : Number(elr.value);
      else data[f.name] = elr.value.trim();
    });
    const btn = $('#modal-submit');
    btn.disabled = true; btn.textContent = '처리 중…';
    try {
      await onSubmit(data);
      closeModal();
    } catch (e) {
      const box = $('#modal-err');
      box.textContent = e.message || '실패했습니다.';
      box.classList.add('show');
      btn.disabled = false; btn.textContent = esc(submitLabel);
    }
  };
  $('#modal-submit').addEventListener('click', submit);
  $('#modal-form').addEventListener('submit', e => { e.preventDefault(); submit(); });
}

async function confirmModal(message, { danger = true, confirmLabel = '확인' } = {}) {
  return new Promise(resolve => {
    openModal({
      title: '확인',
      body: `<p style="margin:0">${esc(message)}</p>`,
      footer: `<button class="btn btn-ghost" data-close>취소</button>
               <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" id="cf-yes">${esc(confirmLabel)}</button>`,
    });
    $('#cf-yes').addEventListener('click', () => { closeModal(); resolve(true); });
    $('#modal-root').addEventListener('click', e => {
      if (e.target.hasAttribute('data-close')) resolve(false);
    }, { once: false });
  });
}

const loadingHtml = (msg = '불러오는 중…') => `<div class="loading"><div class="spinner"></div>${esc(msg)}</div>`;
const emptyHtml = (icon, msg) => `<div class="empty"><div class="icon">${icon}</div>${esc(msg)}</div>`;

// ── 인증 상태 ─────────────────────────────────────────────
const session = () => API.getSession();
const isSuper = () => session()?.role === 'super_admin';
const isAdmin = () => session()?.role === 'admin';
const isCust  = () => session()?.role === 'customer';

function requireAuth() {
  if (!session()) { location.hash = '#/login'; return false; }
  return true;
}
function defaultRoute() {
  const r = session()?.role;
  if (r === 'customer') return '#/shop';
  if (r === 'admin') return '#/my-tenants';
  return '#/dashboard';
}

// ============================================================
//  로그인 화면
// ============================================================
function viewLogin() {
  const base = API.getBase();
  const local = API.isLocalHost();
  const serverField = local
    ? `<div class="field">
         <label>서버 주소</label>
         <input name="base" value="${esc(base)}" placeholder="http://서버주소:8080" />
         <div class="hint">로컬 개발 모드 — EC2 주소 입력. 예) http://서버주소:8080</div>
       </div>`
    : `<div class="field">
         <label>서버</label>
         <input value="현재 접속 서버 (자동)" disabled />
         <div class="hint">통합 서버를 통해 접속 중입니다. (별도 주소 입력 불필요)</div>
       </div>`;
  app().innerHTML = `
    <div class="login-wrap">
      <div class="login-card">
        <div class="brand-badge">🛍️ Multitenant Shop</div>
        <h1>관리 콘솔 로그인</h1>
        <p class="sub">테스트베드 백엔드에 접속합니다.</p>
        <div class="err-box" id="login-err"></div>
        <form id="login-form">
          ${serverField}
          <div class="field">
            <label>아이디</label>
            <input name="username" autocomplete="username" placeholder="admin" required />
          </div>
          <div class="field">
            <label>비밀번호</label>
            <input name="password" type="password" autocomplete="current-password" required />
          </div>
          <button class="btn btn-primary btn-block" id="login-btn" type="submit">로그인</button>
        </form>
        <div style="margin-top:14px;display:flex;gap:8px;justify-content:center">
          <button class="btn btn-ghost btn-sm" id="ping-btn" type="button">서버 상태 확인</button>
          <button class="btn btn-ghost btn-sm" id="signup-btn" type="button">회원가입 요청</button>
        </div>
      </div>
    </div>`;

  const errBox = $('#login-err');
  const showErr = (m) => { errBox.textContent = m; errBox.classList.add('show'); };

  $('#ping-btn').addEventListener('click', async () => {
    const bf = $('input[name=base]');
    if (bf) API.setBase(bf.value);
    try { const h = await API.health(); ok('서버 정상: ' + (h.app || h.status), '연결 OK'); }
    catch (e) { showErr(e.message); }
  });

  $('#signup-btn').addEventListener('click', () => {
    const bf = $('input[name=base]');
    if (bf) API.setBase(bf.value);
    openSignupModal();
  });

  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    errBox.classList.remove('show');
    const f = e.target;
    if (f.base) API.setBase(f.base.value);
    const btn = $('#login-btn');
    btn.disabled = true; btn.textContent = '로그인 중…';
    try {
      const s = await API.login(f.username.value.trim(), f.password.value);
      ok(`${s.username} (${s.role}) 로그인`, '환영합니다');
      startNotifPolling();
      location.hash = defaultRoute();
    } catch (err) {
      showErr(err.message);
      btn.disabled = false; btn.textContent = '로그인';
    }
  });
}

// ── 회원가입 요청 모달 (공개) ─────────────────────────────
async function openSignupModal() {
  let tenants;
  try { tenants = (await API.listTenants()).data; }
  catch (e) { fail(e.message); return; }
  if (!tenants.length) { fail('가입 가능한 상점이 없습니다.'); return; }
  openFormModal({
    title: '회원가입 요청',
    fields: [
      { name: 'tenantId', label: '가입할 상점', type: 'select', value: tenants[0].id,
        options: tenants.map(t => ({ value: t.id, label: t.name })) },
      { name: 'username', label: '아이디', required: true, hint: '3~30자' },
      { name: 'password', label: '비밀번호', type: 'password', required: true, hint: '4자 이상' },
      { name: 'displayName', label: '이름 (표시명)' },
    ],
    submitLabel: '가입 요청',
    onSubmit: async (d) => {
      const { tenantId, ...body } = d;
      await API.submitSignup(tenantId, body);
      ok('가입 요청이 접수되었습니다. 관리자 승인 후 로그인할 수 있습니다.', '요청 완료');
    },
  });
}

// ── 알림 폴링 (가입요청 + 충전요청) ───────────────────────
let notif = { items: [], total: 0, inited: false };
let notifTimer = null;

const notifEligible = () => isSuper() || isAdmin();
const findNotif = (tid) => notif.items.find(i => i.tenantId === tid) || {};
const signupCountFor = (tid) => findNotif(tid).signupCount || 0;
const chargeCountFor = (tid) => findNotif(tid).chargeCount || 0;
const orderCountFor  = (tid) => findNotif(tid).orderCount  || 0;

async function refreshNotif(allowToast) {
  if (!session() || !notifEligible()) return;
  let items;
  try { items = (await API.pendingNotifications()).data || []; }
  catch { return; }
  const total = items.reduce((a, x) => a + (x.signupCount || 0) + (x.chargeCount || 0) + (x.orderCount || 0), 0);
  if (allowToast && notif.inited && total > notif.total)
    toast(`새 요청 ${total - notif.total}건이 접수되었습니다.`, 'info', '🔔 알림');
  notif = { items, total, inited: true };
  renderBell();
}

function renderBell() {
  const c = $('#notif-count');
  if (c) {
    if (notif.total > 0) { c.textContent = notif.total > 99 ? '99+' : notif.total; c.style.display = ''; }
    else c.style.display = 'none';
  }
  const dd = $('#bell-dd');
  if (dd) dd.innerHTML =
    `<div class="bd-head">대기 중인 요청</div>` +
    (notif.items.length
      ? notif.items.map(i => `
          ${i.orderCount ? `<a href="#/tenant/${i.tenantId}/orders"><span>${esc(i.tenantName)} · 주문</span><span class="badge green">${i.orderCount}</span></a>` : ''}
          ${i.signupCount ? `<a href="#/tenant/${i.tenantId}/signups"><span>${esc(i.tenantName)} · 가입</span><span class="badge amber">${i.signupCount}</span></a>` : ''}
          ${i.chargeCount ? `<a href="#/tenant/${i.tenantId}/charges"><span>${esc(i.tenantName)} · 충전</span><span class="badge cyan">${i.chargeCount}</span></a>` : ''}`).join('')
      : `<div class="empty-bd">대기 중인 요청이 없습니다.</div>`);
}

// 고객용: 본인 주문/충전요청 상태 변경 감지 → 토스트
let custSnap = null;
async function refreshCustomerNotif(allowToast) {
  if (!session() || !isCust()) return;
  const tid = session().tenantId;
  if (!tid) return;
  let orders = [], charges = [];
  try { orders = (await API.myOrders(tid)).data || []; } catch { /* ignore */ }
  try { charges = (await API.listMyCharges(tid)).data || []; } catch { /* ignore */ }
  const snap = { orders: {}, charges: {} };
  orders.forEach(o => { snap.orders[o.id] = o.status; });
  charges.forEach(c => { snap.charges[c.id] = c.status; });

  if (allowToast && custSnap) {
    orders.forEach(o => {
      const prev = custSnap.orders[o.id];
      if (prev && prev !== o.status)
        toast(`주문 상태가 '${statusKo(o.status)}'(으)로 변경되었습니다.`, 'info', '🔔 주문 알림');
    });
    charges.forEach(c => {
      const prev = custSnap.charges[c.id];
      if (prev && prev !== c.status)
        toast(`충전 요청이 ${c.status === 'approved' ? '승인' : '반려'}되었습니다.`,
              c.status === 'approved' ? 'success' : 'info', '🔔 충전 알림');
    });
  }
  custSnap = snap;
  refreshBalance();
}

function startNotifPolling() {
  stopNotifPolling();
  if (notifEligible()) {
    refreshNotif(false);
    notifTimer = setInterval(() => refreshNotif(true), 20000);
  } else if (isCust()) {
    refreshCustomerNotif(false);
    notifTimer = setInterval(() => refreshCustomerNotif(true), 20000);
  }
}
function stopNotifPolling() {
  if (notifTimer) { clearInterval(notifTimer); notifTimer = null; }
  notif = { items: [], total: 0, inited: false };
  custSnap = null;
}

// ── 고객 보유 잔액 (상단바 상시 표시) ─────────────────────
let myBalance = null;
const balanceEligible = () => isCust() || isAdmin();   // 고객(충전/구매) + admin(배송 정산)
async function refreshBalance() {
  if (!session() || !balanceEligible()) return;
  try { myBalance = (await API.me()).data.balance; } catch { return; }
  const el = $('#my-balance');
  if (el) el.textContent = '잔액 ' + money(myBalance);
}

// ── 앱 셸(상단바) ─────────────────────────────────────────
function shell(activeKey, contentHtml) {
  const s = session();
  let nav = [];
  if (isSuper()) nav = [
    ['dashboard', '#/dashboard', '대시보드'],
    ['tenants',   '#/tenants',   '테넌트'],
    ['users',     '#/users',     '사용자'],
    ['audit',     '#/audit',     '감사로그'],
  ];
  else if (isAdmin()) nav = [
    ['mytenants', '#/my-tenants', '내 상점'],
  ];
  else nav = [
    ['shop',     '#/shop',      '쇼핑'],
    ['myorders', '#/my-orders', '내 주문'],
    ['wallet',   '#/wallet',    '충전'],
  ];

  const navHtml = nav.map(([k, href, label]) =>
    `<a href="${href}" class="${k === activeKey ? 'active' : ''}">${label}</a>`).join('');

  app().innerHTML = `
    <div class="app">
      <header class="topbar">
        <div class="logo"><span class="dot"></span> Shop Console</div>
        <nav>${navHtml}</nav>
        <div class="user">
          ${notifEligible() ? `<div class="bell" id="bell" title="대기 중인 요청 알림">🔔
            <span class="count" id="notif-count" style="display:none">0</span>
            <div class="bell-dropdown" id="bell-dd" style="display:none"></div>
          </div>` : ''}
          ${isCust() ? `<a class="balance-chip" id="my-balance" href="#/wallet" title="보유 잔액 (클릭 시 충전)">잔액 ${myBalance != null ? money(myBalance) : '…'}</a>`
            : isAdmin() ? `<span class="balance-chip" id="my-balance" title="정산 잔액">잔액 ${myBalance != null ? money(myBalance) : '…'}</span>` : ''}
          <span class="server-pill" id="server-pill" title="${API.isLocalHost() ? '서버 주소 변경' : '통합 서버'}">${esc(API.isLocalHost() ? (API.getBase().replace(/^https?:\/\//, '') || '주소 미설정') : '🔗 ' + location.host)}</span>
          <span class="uname">${esc(s.username)}</span>
          ${roleBadge(s.role)}
          <button class="btn btn-sm btn-ghost" id="logout-btn" style="color:#cbd5e1;border-color:#334155">로그아웃</button>
        </div>
      </header>
      <main class="main" id="content">${contentHtml}</main>
    </div>`;

  $('#logout-btn').addEventListener('click', async () => {
    stopNotifPolling();
    await API.logout();
    ok('로그아웃되었습니다.');
    location.hash = '#/login';
  });

  const bell = $('#bell');
  if (bell) {
    bell.addEventListener('click', (e) => {
      e.stopPropagation();
      const dd = $('#bell-dd');
      dd.style.display = dd.style.display === 'none' ? 'block' : 'none';
    });
    renderBell();
  }
  if (balanceEligible()) refreshBalance();
  $('#server-pill').addEventListener('click', () => {
    if (!API.isLocalHost()) { ok('통합 서버(같은 호스트)를 통해 접속 중입니다.'); return; }
    openFormModal({
      title: '서버 주소 변경',
      fields: [{ name: 'base', label: '서버 주소', value: API.getBase(), required: true, hint: 'http://<EC2-IP>:8080' }],
      submitLabel: '적용',
      onSubmit: (d) => { API.setBase(d.base); ok('서버 주소가 변경되었습니다. 다시 로그인하세요.'); API.clearAuth(); location.hash = '#/login'; },
    });
  });
}

const content = () => $('#content');

// ============================================================
//  대시보드
// ============================================================
async function viewDashboard() {
  shell('dashboard', loadingHtml());
  const s = session();
  try {
    if (isSuper()) {
      const [tenants, users, audit] = await Promise.all([
        API.listTenantsAll().then(r => r.data).catch(() => []),
        API.listUsers().then(r => r.data).catch(() => []),
        API.auditRecent(8).then(r => r.data).catch(() => []),
      ]);
      const activeT = tenants.filter(t => t.active).length;
      content().innerHTML = `
        <div class="page-head"><h2>대시보드</h2></div>
        <div class="stat-cards">
          <div class="stat"><div class="k">전체 테넌트</div><div class="v">${tenants.length}</div></div>
          <div class="stat"><div class="k">활성 테넌트</div><div class="v">${activeT}</div></div>
          <div class="stat"><div class="k">전체 사용자</div><div class="v">${users.length}</div></div>
        </div>
        <div class="card">
          <h3>최근 활동 (감사 로그)</h3>
          ${audit.length ? auditTable(audit) : emptyHtml('🗒️', '기록된 활동이 없습니다.')}
        </div>`;
    } else if (isAdmin()) {
      const [products, orders] = await Promise.all([
        API.listProducts(s.tenantId, true).then(r => r.data).catch(() => []),
        API.listOrders(s.tenantId).then(r => r.data).catch(() => []),
      ]);
      const revenue = orders.filter(o => o.status !== 'cancelled').reduce((a, o) => a + o.totalAmount, 0);
      content().innerHTML = `
        <div class="page-head"><h2>대시보드</h2><span class="badge cyan">내 테넌트</span></div>
        <div class="stat-cards">
          <div class="stat"><div class="k">상품 수</div><div class="v">${products.length}</div></div>
          <div class="stat"><div class="k">주문 수</div><div class="v">${orders.length}</div></div>
          <div class="stat"><div class="k">매출(취소제외)</div><div class="v" style="font-size:20px">${money(revenue)}</div></div>
        </div>
        <div class="card"><h3>바로가기</h3>
          <a class="btn btn-primary" href="#/tenant/${s.tenantId}/products">상품 관리</a>
          <a class="btn btn-ghost" href="#/tenant/${s.tenantId}/orders">주문 관리</a>
        </div>`;
    } else {
      location.hash = '#/shop';
    }
  } catch (e) { content().innerHTML = errPage(e); }
}

function auditTable(rows) {
  return `<div class="table-wrap"><table>
    <thead><tr><th>시각</th><th>행위자</th><th>액션</th><th>리소스</th><th>IP</th></tr></thead>
    <tbody>${rows.map(a => `<tr>
      <td class="nowrap mono">${fmtDate(a.createdAt)}</td>
      <td>${esc(a.actorUsername || shortId(a.actorId))}</td>
      <td><span class="badge indigo">${esc(a.action)}</span></td>
      <td class="muted">${esc(a.resourceType || '')} ${a.resourceId ? `<span class="mono">${shortId(a.resourceId)}</span>` : ''}</td>
      <td class="mono muted">${esc(a.ipAddress || '-')}</td>
    </tr>`).join('')}</tbody></table></div>`;
}

// ============================================================
//  테넌트 (super_admin)
// ============================================================
async function viewTenants() {
  shell('tenants', loadingHtml());
  try {
    const tenants = (await API.listTenantsAll()).data;
    content().innerHTML = `
      <div class="page-head">
        <h2>테넌트</h2><span class="badge gray">${tenants.length}개</span>
        <div class="spacer"></div>
        <button class="btn btn-primary" id="new-tenant">+ 새 테넌트</button>
      </div>
      ${tenants.length ? `<div class="table-wrap"><table>
        <thead><tr><th>이름</th><th>슬러그</th><th>상태</th><th>생성</th><th></th></tr></thead>
        <tbody>${tenants.map(t => `<tr>
          <td><strong>${esc(t.name)}</strong>${t.description ? `<div class="muted" style="font-size:12px">${esc(t.description)}</div>` : ''}</td>
          <td class="mono">${esc(t.slug)}</td>
          <td>${activeBadge(t.active)}</td>
          <td class="nowrap mono muted">${fmtDate(t.createdAt)}</td>
          <td><div class="actions-cell">
            <a class="btn btn-sm btn-primary" href="#/tenant/${t.id}/products">관리</a>
            <button class="btn btn-sm" data-edit="${t.id}">수정</button>
            <button class="btn btn-sm" data-admins="${t.id}">관리자</button>
            <button class="btn btn-sm ${t.active ? '' : 'btn-ghost'}" data-toggle="${t.id}" data-active="${t.active}">${t.active ? '비활성화' : '활성화'}</button>
            <button class="btn btn-sm btn-danger" data-del="${t.id}">삭제</button>
          </div></td>
        </tr>`).join('')}</tbody></table></div>`
        : emptyHtml('🏪', '테넌트가 없습니다. 새로 만들어 보세요.')}`;

    $('#new-tenant').addEventListener('click', () => openFormModal({
      title: '새 테넌트 만들기',
      fields: [
        { name: 'name', label: '이름', required: true },
        { name: 'slug', label: '슬러그 (접속 주소)', required: true, hint: '소문자/숫자/하이픈만 (예: my-shop)' },
        { name: 'domain', label: '커스텀 도메인 (선택)', hint: '예: myshop.example.com' },
        { name: 'description', label: '설명', type: 'textarea' },
      ],
      submitLabel: '생성',
      onSubmit: async (d) => { if (!d.domain) delete d.domain; await API.createTenant(d); ok('테넌트가 생성되었습니다.'); viewTenants(); },
    }));

    $$('[data-edit]').forEach(b => b.addEventListener('click', () => {
      const t = tenants.find(x => x.id === b.dataset.edit);
      openFormModal({
        title: '테넌트 수정',
        fields: [
          { name: 'name', label: '이름', value: t.name, required: true },
          { name: 'slug', label: '슬러그 (접속 주소)', value: t.slug, hint: '소문자/숫자/하이픈만' },
          { name: 'domain', label: '커스텀 도메인', value: t.domain, hint: '예: myshop.example.com (비우면 제거)' },
          { name: 'description', label: '설명', type: 'textarea', value: t.description },
          { name: 'isActive', label: '활성 상태', type: 'checkbox', value: t.active },
        ],
        onSubmit: async (d) => { await API.updateTenant(t.id, d); ok('수정되었습니다.'); viewTenants(); },
      });
    }));

    $$('[data-toggle]').forEach(b => b.addEventListener('click', async () => {
      const active = b.dataset.active === 'true';
      try { await API.updateTenant(b.dataset.toggle, { isActive: !active }); ok(active ? '비활성화됨' : '활성화됨'); viewTenants(); }
      catch (e) { fail(e.message); }
    }));

    $$('[data-del]').forEach(b => b.addEventListener('click', async () => {
      const t = tenants.find(x => x.id === b.dataset.del);
      if (await confirmModal(`'${t.name}' 테넌트를 삭제할까요? (soft delete)`)) {
        try { await API.deleteTenant(t.id); ok('삭제되었습니다.'); viewTenants(); }
        catch (e) { fail(e.message); }
      }
    }));

    $$('[data-admins]').forEach(b => b.addEventListener('click', () => {
      openTenantAdminsModal(tenants.find(x => x.id === b.dataset.admins));
    }));
  } catch (e) { content().innerHTML = errPage(e); }
}

// 테넌트 관리자 배정 모달 (super_admin)
async function openTenantAdminsModal(tenant) {
  let admins, allUsers;
  try {
    [admins, allUsers] = await Promise.all([
      API.listTenantAdmins(tenant.id).then(r => r.data),
      API.listUsers().then(r => r.data),
    ]);
  } catch (e) { fail(e.message); return; }
  const adminIds = new Set(admins.map(a => a.id));
  const candidates = allUsers.filter(u => u.role === 'admin' && !adminIds.has(u.id));

  openModal({
    title: `관리자 배정 — ${esc(tenant.name)}`,
    body: `
      <p class="muted" style="margin-top:0">이 상점을 관리하는 관리자(admin) 목록입니다.</p>
      ${admins.length ? `<div class="table-wrap"><table><tbody>
        ${admins.map(a => `<tr>
          <td><strong>${esc(a.username)}</strong> <span class="muted">${esc(a.displayName || '')}</span></td>
          <td style="text-align:right"><button class="btn btn-sm btn-danger" data-unassign="${a.id}">해제</button></td>
        </tr>`).join('')}
      </tbody></table></div>` : '<div class="empty" style="padding:18px">배정된 관리자가 없습니다.</div>'}
      <div class="field" style="margin-top:14px">
        <label>관리자 추가 (admin 역할 사용자)</label>
        <div style="display:flex;gap:8px">
          <select id="add-admin-sel" style="flex:1">
            ${candidates.length ? candidates.map(u => `<option value="${u.id}">${esc(u.username)} ${esc(u.displayName || '')}</option>`).join('')
              : '<option value="">(추가할 admin 사용자가 없음)</option>'}
          </select>
          <button class="btn btn-primary" id="add-admin-btn" ${candidates.length ? '' : 'disabled'}>추가</button>
        </div>
        <div class="hint">admin 역할 사용자만 배정 가능. (사용자 탭에서 역할을 admin으로 바꿀 수 있음)</div>
      </div>`,
    footer: `<button class="btn btn-ghost" data-close>닫기</button>`,
  });

  $$('[data-unassign]').forEach(b => b.addEventListener('click', async () => {
    try { await API.unassignTenantAdmin(tenant.id, b.dataset.unassign); ok('배정 해제됨'); openTenantAdminsModal(tenant); }
    catch (e) { fail(e.message); }
  }));
  const addBtn = $('#add-admin-btn');
  if (addBtn) addBtn.addEventListener('click', async () => {
    const uid = $('#add-admin-sel').value;
    if (!uid) return;
    try { await API.assignTenantAdmin(tenant.id, uid); ok('관리자 배정됨'); openTenantAdminsModal(tenant); }
    catch (e) { fail(e.message); }
  });
}

// ============================================================
//  사용자 (super_admin)
// ============================================================
async function viewUsers() {
  shell('users', loadingHtml());
  try {
    const [users, tenants] = await Promise.all([
      API.listUsers().then(r => r.data),
      API.listTenantsAll().then(r => r.data).catch(() => []),
    ]);
    const tName = (id) => tenants.find(t => t.id === id)?.name || (id ? shortId(id) : '-');
    content().innerHTML = `
      <div class="page-head"><h2>사용자</h2><span class="badge gray">${users.length}명</span>
        <div class="spacer"></div>
        <button class="btn btn-primary" id="new-user">+ 새 사용자</button>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>아이디</th><th>이름</th><th>역할</th><th>소속 테넌트</th><th>상태</th><th></th></tr></thead>
        <tbody>${users.map(u => `<tr>
          <td><strong>${esc(u.username)}</strong></td>
          <td>${esc(u.displayName || '-')}</td>
          <td>${roleBadge(u.role)}</td>
          <td>${u.role === 'super_admin' ? '<span class="muted">전역</span>' : esc(tName(u.tenantId))}</td>
          <td>${activeBadge(u.active)}</td>
          <td><div class="actions-cell">
            ${u.id === session().userId ? '<span class="badge gray">나</span>' : `
              <button class="btn btn-sm" data-role="${u.id}">역할</button>
              ${u.role === 'super_admin' ? '' : `<button class="btn btn-sm btn-danger" data-del="${u.id}">삭제</button>`}`}
          </div></td>
        </tr>`).join('')}</tbody></table></div>`;

    $('#new-user').addEventListener('click', () => openFormModal({
      title: '새 사용자 만들기',
      fields: [
        { name: 'username', label: '아이디', required: true },
        { name: 'password', label: '비밀번호', type: 'password', required: true },
        { name: 'displayName', label: '표시 이름' },
        { name: 'role', label: '역할', type: 'select', value: 'customer', options: [
          { value: 'customer', label: 'customer (고객)' },
          { value: 'admin', label: 'admin (테넌트 관리자)' },
          { value: 'super_admin', label: 'super_admin (전역 관리자)' },
        ] },
        { name: 'tenantId', label: '소속 테넌트', type: 'select', value: '',
          options: [{ value: '', label: '(없음 / super_admin)' }, ...tenants.map(t => ({ value: t.id, label: t.name }))],
          hint: 'admin/customer 는 테넌트 필수. super_admin 은 전역이라 무시됩니다.' },
      ],
      submitLabel: '생성',
      onSubmit: async (d) => {
        if (d.role === 'super_admin' || !d.tenantId) delete d.tenantId;
        await API.createUser(d); ok('사용자가 생성되었습니다.'); viewUsers();
      },
    }));

    $$('[data-role]').forEach(b => b.addEventListener('click', () => {
      const u = users.find(x => x.id === b.dataset.role);
      openFormModal({
        title: `역할 변경 — ${u.username}`,
        fields: [
          { name: 'role', label: '역할', type: 'select', value: u.role, options: [
            { value: 'super_admin', label: 'super_admin (전역 관리자)' },
            { value: 'admin', label: 'admin (테넌트 관리자)' },
            { value: 'customer', label: 'customer (고객)' },
          ] },
          { name: 'tenantId', label: '소속 테넌트', type: 'select', value: u.tenantId || '',
            options: [{ value: '', label: '(변경 안 함 / super_admin은 무시)' },
                      ...tenants.map(t => ({ value: t.id, label: t.name }))],
            hint: 'admin/customer 로 바꿀 땐 테넌트를 지정하세요. super_admin 은 자동으로 전역 처리됩니다.' },
        ],
        submitLabel: '변경',
        onSubmit: async (d) => {
          const body = { role: d.role };
          if (d.tenantId) body.tenantId = d.tenantId;
          await API.updateUser(u.id, body);
          ok('역할이 변경되었습니다.'); viewUsers();
        },
      });
    }));

    $$('[data-del]').forEach(b => b.addEventListener('click', async () => {
      const u = users.find(x => x.id === b.dataset.del);
      if (await confirmModal(`'${u.username}' 사용자를 삭제할까요?`)) {
        try { await API.deleteUser(u.id); ok('삭제되었습니다.'); viewUsers(); }
        catch (e) { fail(e.message); }
      }
    }));
  } catch (e) { content().innerHTML = errPage(e); }
}

// ============================================================
//  감사 로그 (super_admin)
// ============================================================
async function viewAudit() {
  shell('audit', loadingHtml());
  try {
    const rows = (await API.auditRecent(100)).data;
    content().innerHTML = `
      <div class="page-head"><h2>감사 로그</h2><span class="badge gray">최근 ${rows.length}건</span>
        <div class="spacer"></div><button class="btn btn-ghost" id="reload">새로고침</button></div>
      ${rows.length ? auditTable(rows) : emptyHtml('🗒️', '기록이 없습니다.')}`;
    $('#reload').addEventListener('click', viewAudit);
  } catch (e) { content().innerHTML = errPage(e); }
}

// ============================================================
//  테넌트 워크스페이스 (상품 / 주문)  — super_admin & admin
// ============================================================
function workspaceHead(tenantId, tenantName, tab) {
  const back = isSuper() ? `<div class="breadcrumb"><a href="#/tenants">← 테넌트 목록</a></div>` : '';
  const sc = signupCountFor(tenantId);
  const cc = chargeCountFor(tenantId);
  const oc = orderCountFor(tenantId);
  const tabs = [['products', `#/tenant/${tenantId}/products`, '상품'],
                ['orders',   `#/tenant/${tenantId}/orders`,   `주문${oc ? ` <span class="nav-count">${oc}</span>` : ''}`],
                ['signups',  `#/tenant/${tenantId}/signups`,  `가입요청${sc ? ` <span class="nav-count">${sc}</span>` : ''}`],
                ['charges',  `#/tenant/${tenantId}/charges`,   `충전요청${cc ? ` <span class="nav-count">${cc}</span>` : ''}`],
                ['settings', `#/tenant/${tenantId}/settings`, '설정']];
  return `${back}
    <div class="page-head">
      <h2>${esc(tenantName || '테넌트')}</h2>
      <div class="spacer"></div>
      <div style="display:flex;gap:6px">
        ${tabs.map(([k, h, l]) => `<a class="btn btn-sm ${k === tab ? 'btn-primary' : 'btn-ghost'}" href="${h}">${l}</a>`).join('')}
      </div>
    </div>`;
}

async function resolveTenantName(tenantId) {
  try {
    const list = isSuper() ? (await API.listTenantsAll()).data : (await API.listManagedTenants()).data;
    return list.find(t => t.id === tenantId)?.name || '상점';
  } catch { return '상점'; }
}

async function viewProducts(tenantId) {
  const navKey = isSuper() ? 'tenants' : 'mytenants';
  shell(navKey, loadingHtml());
  try {
    const [products, tName] = await Promise.all([
      API.listProducts(tenantId, true).then(r => r.data),
      resolveTenantName(tenantId),
    ]);
    content().innerHTML = `
      ${workspaceHead(tenantId, tName, 'products')}
      <div class="page-head" style="margin-top:-4px">
        <span class="badge gray">${products.length}개 상품</span>
        <div class="spacer"></div>
        <button class="btn btn-primary" id="new-product">+ 새 상품</button>
      </div>
      ${products.length ? `<div class="table-wrap"><table>
        <thead><tr><th>상품명</th><th>카테고리</th><th>가격</th><th>재고</th><th>상태</th><th></th></tr></thead>
        <tbody>${products.map(p => `<tr>
          <td><strong>${esc(p.name)}</strong>${p.description ? `<div class="muted" style="font-size:12px">${esc(p.description)}</div>` : ''}</td>
          <td>${p.category ? `<span class="badge gray">${esc(p.category)}</span>` : '<span class="muted">-</span>'}</td>
          <td class="nowrap">${money(p.price)}</td>
          <td>${p.stock > 0 ? p.stock : '<span class="badge red">품절</span>'}</td>
          <td>${activeBadge(p.active)}</td>
          <td><div class="actions-cell">
            <button class="btn btn-sm" data-edit="${p.id}">수정</button>
            <button class="btn btn-sm btn-danger" data-del="${p.id}">삭제</button>
          </div></td>
        </tr>`).join('')}</tbody></table></div>`
        : emptyHtml('📦', '상품이 없습니다.')}`;

    const productFields = (p = {}) => ([
      { name: 'name', label: '상품명', value: p.name, required: true },
      { name: 'description', label: '설명', type: 'textarea', value: p.description },
      { name: 'price', label: '가격(원)', type: 'number', value: p.price, min: 0, required: true },
      { name: 'stock', label: '재고', type: 'number', value: p.stock, min: 0, required: true },
      { name: 'category', label: '카테고리', value: p.category },
    ]);

    $('#new-product').addEventListener('click', () => openFormModal({
      title: '새 상품 등록', fields: productFields(), submitLabel: '등록',
      onSubmit: async (d) => { await API.createProduct(tenantId, d); ok('상품이 등록되었습니다.'); viewProducts(tenantId); },
    }));

    $$('[data-edit]').forEach(b => b.addEventListener('click', () => {
      const p = products.find(x => x.id === b.dataset.edit);
      openFormModal({
        title: '상품 수정',
        fields: [...productFields(p), { name: 'isActive', label: '활성 상태', type: 'checkbox', value: p.active }],
        onSubmit: async (d) => { await API.updateProduct(tenantId, p.id, d); ok('수정되었습니다.'); viewProducts(tenantId); },
      });
    }));

    $$('[data-del]').forEach(b => b.addEventListener('click', async () => {
      const p = products.find(x => x.id === b.dataset.del);
      if (await confirmModal(`'${p.name}' 상품을 삭제할까요?`)) {
        try { await API.deleteProduct(tenantId, p.id); ok('삭제되었습니다.'); viewProducts(tenantId); }
        catch (e) { fail(e.message); }
      }
    }));
  } catch (e) { content().innerHTML = errPage(e); }
}

async function viewOrders(tenantId) {
  const navKey = isSuper() ? 'tenants' : 'mytenants';
  shell(navKey, loadingHtml());
  try {
    const [orders, tName] = await Promise.all([
      API.listOrders(tenantId).then(r => r.data),
      resolveTenantName(tenantId),
    ]);
    content().innerHTML = `
      ${workspaceHead(tenantId, tName, 'orders')}
      <div class="page-head" style="margin-top:-4px"><span class="badge gray">${orders.length}건 주문</span></div>
      ${orders.length ? `<div class="table-wrap"><table>
        <thead><tr><th>주문ID</th><th>고객</th><th>금액</th><th>상태</th><th>일시</th><th>상태변경</th></tr></thead>
        <tbody>${orders.map(o => `<tr>
          <td class="mono">${shortId(o.id)}</td>
          <td class="mono muted">${shortId(o.customerId)}</td>
          <td class="nowrap"><strong>${money(o.totalAmount)}</strong></td>
          <td>${statusBadge(o.status)}</td>
          <td class="nowrap mono muted">${fmtDate(o.createdAt)}</td>
          <td>
            <select class="qty" data-status="${o.id}" style="width:130px">
              ${ORDER_STATUS.map(s =>
                `<option value="${s.value}" ${s.value === o.status ? 'selected' : ''}>${s.ko}</option>`).join('')}
            </select>
          </td>
        </tr>`).join('')}</tbody></table></div>`
        : emptyHtml('🧾', '주문이 없습니다.')}`;

    $$('[data-status]').forEach(sel => sel.addEventListener('change', async () => {
      try {
        await API.updateOrderStatus(tenantId, sel.dataset.status, sel.value);
        ok(`주문 상태가 '${statusKo(sel.value)}'(으)로 변경되었습니다.`);
        viewOrders(tenantId);     // 변경 즉시 갱신
        refreshNotif(false);
      } catch (e) { fail(e.message); viewOrders(tenantId); }
    }));
  } catch (e) { content().innerHTML = errPage(e); }
}

// ============================================================
//  가입요청 심사 (admin / super_admin)
// ============================================================
function signupStatusBadge(s) {
  const map = { pending: 'amber', approved: 'green', rejected: 'red' };
  const ko  = { pending: '대기', approved: '승인', rejected: '반려' };
  return `<span class="badge ${map[s] || 'gray'}">${esc(ko[s] || s)}</span>`;
}

async function viewSignupRequests(tenantId) {
  const navKey = isSuper() ? 'tenants' : 'mytenants';
  shell(navKey, loadingHtml());
  try {
    const [reqs, tName] = await Promise.all([
      API.listSignups(tenantId).then(r => r.data),
      resolveTenantName(tenantId),
    ]);
    const pending = reqs.filter(r => r.status === 'pending').length;
    content().innerHTML = `
      ${workspaceHead(tenantId, tName, 'signups')}
      <div class="page-head" style="margin-top:-4px">
        <span class="badge amber">대기 ${pending}</span>
        <span class="badge gray">전체 ${reqs.length}</span>
        <div class="spacer"></div>
        <button class="btn btn-ghost" id="reload">새로고침</button>
      </div>
      ${reqs.length ? `<div class="table-wrap"><table>
        <thead><tr><th>아이디</th><th>이름</th><th>상태</th><th>요청일</th><th>처리</th></tr></thead>
        <tbody>${reqs.map(r => `<tr>
          <td><strong>${esc(r.username)}</strong></td>
          <td>${esc(r.displayName || '-')}</td>
          <td>${signupStatusBadge(r.status)}${r.rejectReason ? `<div class="muted" style="font-size:12px">사유: ${esc(r.rejectReason)}</div>` : ''}</td>
          <td class="nowrap mono muted">${fmtDate(r.createdAt)}</td>
          <td><div class="actions-cell">
            ${r.status === 'pending' ? `
              <button class="btn btn-sm btn-primary" data-approve="${r.id}">승인</button>
              <button class="btn btn-sm btn-danger" data-reject="${r.id}">반려</button>`
              : '<span class="muted" style="font-size:12px">처리완료</span>'}
          </div></td>
        </tr>`).join('')}</tbody></table></div>`
        : emptyHtml('📝', '접수된 가입 요청이 없습니다.')}`;

    $('#reload').addEventListener('click', () => viewSignupRequests(tenantId));

    $$('[data-approve]').forEach(b => b.addEventListener('click', async () => {
      const r = reqs.find(x => x.id === b.dataset.approve);
      if (await confirmModal(`'${r.username}' 가입을 승인할까요? customer 계정이 생성됩니다.`, { danger: false, confirmLabel: '승인' })) {
        try { await API.approveSignup(tenantId, r.id); ok('승인되어 계정이 생성되었습니다.'); viewSignupRequests(tenantId); refreshNotif(false); }
        catch (e) { fail(e.message); }
      }
    }));

    $$('[data-reject]').forEach(b => b.addEventListener('click', () => {
      const r = reqs.find(x => x.id === b.dataset.reject);
      openFormModal({
        title: `가입 반려 — ${r.username}`,
        fields: [{ name: 'reason', label: '반려 사유 (선택)', type: 'textarea' }],
        submitLabel: '반려',
        onSubmit: async (d) => { await API.rejectSignup(tenantId, r.id, d.reason || ''); ok('반려 처리되었습니다.'); viewSignupRequests(tenantId); refreshNotif(false); },
      });
    }));
  } catch (e) { content().innerHTML = errPage(e); }
}

// ============================================================
//  충전요청 심사 (admin / super_admin)
// ============================================================
async function viewChargeRequests(tenantId) {
  const navKey = isSuper() ? 'tenants' : 'mytenants';
  shell(navKey, loadingHtml());
  try {
    const [reqs, tName] = await Promise.all([
      API.listCharges(tenantId).then(r => r.data),
      resolveTenantName(tenantId),
    ]);
    const pending = reqs.filter(r => r.status === 'pending').length;
    content().innerHTML = `
      ${workspaceHead(tenantId, tName, 'charges')}
      <div class="page-head" style="margin-top:-4px">
        <span class="badge amber">대기 ${pending}</span>
        <span class="badge gray">전체 ${reqs.length}</span>
        <div class="spacer"></div>
        <button class="btn btn-ghost" id="reload">새로고침</button>
      </div>
      ${reqs.length ? `<div class="table-wrap"><table>
        <thead><tr><th>고객</th><th>금액</th><th>상태</th><th>요청일</th><th>처리</th></tr></thead>
        <tbody>${reqs.map(r => `<tr>
          <td><strong>${esc(r.username || shortId(r.userId))}</strong></td>
          <td><strong>${money(r.amount)}</strong></td>
          <td>${signupStatusBadge(r.status)}${r.rejectReason ? `<div class="muted" style="font-size:12px">사유: ${esc(r.rejectReason)}</div>` : ''}</td>
          <td class="nowrap mono muted">${fmtDate(r.createdAt)}</td>
          <td><div class="actions-cell">
            ${r.status === 'pending' ? `
              <button class="btn btn-sm btn-primary" data-approve="${r.id}">승인</button>
              <button class="btn btn-sm btn-danger" data-reject="${r.id}">반려</button>`
              : '<span class="muted" style="font-size:12px">처리완료</span>'}
          </div></td>
        </tr>`).join('')}</tbody></table></div>`
        : emptyHtml('💳', '접수된 충전 요청이 없습니다.')}`;

    $('#reload').addEventListener('click', () => viewChargeRequests(tenantId));

    $$('[data-approve]').forEach(b => b.addEventListener('click', async () => {
      const r = reqs.find(x => x.id === b.dataset.approve);
      if (await confirmModal(`'${r.username}'의 ${money(r.amount)} 충전을 승인할까요? 고객 잔액에 반영됩니다.`, { danger: false, confirmLabel: '승인' })) {
        try { await API.approveCharge(tenantId, r.id); ok('승인되어 잔액에 반영되었습니다.'); viewChargeRequests(tenantId); refreshNotif(false); }
        catch (e) { fail(e.message); }
      }
    }));

    $$('[data-reject]').forEach(b => b.addEventListener('click', () => {
      const r = reqs.find(x => x.id === b.dataset.reject);
      openFormModal({
        title: `충전 반려 — ${r.username}`,
        fields: [{ name: 'reason', label: '반려 사유 (선택)', type: 'textarea' }],
        submitLabel: '반려',
        onSubmit: async (d) => { await API.rejectCharge(tenantId, r.id, d.reason || ''); ok('반려 처리되었습니다.'); viewChargeRequests(tenantId); refreshNotif(false); },
      });
    }));
  } catch (e) { content().innerHTML = errPage(e); }
}

// ============================================================
//  내 상점 (admin: 관리하는 테넌트 목록 / 생성)
// ============================================================
async function viewMyTenants() {
  shell('mytenants', loadingHtml());
  try {
    const tenants = (await API.listManagedTenants()).data;
    content().innerHTML = `
      <div class="page-head"><h2>내 상점</h2><span class="badge gray">${tenants.length}개</span>
        <div class="spacer"></div>
        <button class="btn btn-primary" id="new-tenant">+ 새 상점</button>
      </div>
      ${tenants.length ? `<div class="grid cols-2">${tenants.map(t => `
        <div class="card" style="margin:0">
          <h3 style="margin-bottom:6px">${esc(t.name)} ${activeBadge(t.active)}</h3>
          <div class="muted mono" style="font-size:12px">/${esc(t.slug)}${t.domain ? ` · ${esc(t.domain)}` : ''}</div>
          ${t.description ? `<div class="muted" style="font-size:13px;margin-top:6px">${esc(t.description)}</div>` : ''}
          <div style="display:flex;gap:6px;margin-top:12px;flex-wrap:wrap">
            <a class="btn btn-sm btn-primary" href="#/tenant/${t.id}/products">상품</a>
            <a class="btn btn-sm btn-ghost" href="#/tenant/${t.id}/orders">주문${orderCountFor(t.id) ? ` <span class="nav-count">${orderCountFor(t.id)}</span>` : ''}</a>
            <a class="btn btn-sm btn-ghost" href="#/tenant/${t.id}/signups">가입요청${signupCountFor(t.id) ? ` <span class="nav-count">${signupCountFor(t.id)}</span>` : ''}</a>
            <a class="btn btn-sm btn-ghost" href="#/tenant/${t.id}/charges">충전요청${chargeCountFor(t.id) ? ` <span class="nav-count">${chargeCountFor(t.id)}</span>` : ''}</a>
            <a class="btn btn-sm btn-ghost" href="#/tenant/${t.id}/settings">설정</a>
          </div>
        </div>`).join('')}</div>`
        : emptyHtml('🏪', '관리하는 상점이 없습니다. 새 상점을 만들어 보세요.')}`;

    $('#new-tenant').addEventListener('click', () => openFormModal({
      title: '새 상점 만들기',
      fields: [
        { name: 'name', label: '이름', required: true },
        { name: 'slug', label: '슬러그 (접속 주소)', required: true, hint: '소문자/숫자/하이픈만 (예: my-shop)' },
        { name: 'domain', label: '커스텀 도메인 (선택)', hint: '예: myshop.example.com' },
        { name: 'description', label: '설명', type: 'textarea' },
      ],
      submitLabel: '생성',
      onSubmit: async (d) => { if (!d.domain) delete d.domain; await API.createTenant(d); ok('상점이 생성되었습니다.'); viewMyTenants(); },
    }));
  } catch (e) { content().innerHTML = errPage(e); }
}

// ── 테넌트 설정 (접속 주소/도메인 변경) — canManage ────────
async function viewTenantSettings(tenantId) {
  const navKey = isSuper() ? 'tenants' : 'mytenants';
  shell(navKey, loadingHtml());
  try {
    const list = isSuper() ? (await API.listTenantsAll()).data : (await API.listManagedTenants()).data;
    const t = list.find(x => x.id === tenantId);
    if (!t) { content().innerHTML = errPage({ message: '상점을 찾을 수 없거나 권한이 없습니다.' }); return; }
    content().innerHTML = `
      ${workspaceHead(tenantId, t.name, 'settings')}
      <div class="card" style="max-width:560px">
        <h3>접속 주소 / 기본 정보</h3>
        <div class="err-box" id="set-err"></div>
        <form id="set-form">
          <div class="field"><label>이름</label><input name="name" value="${esc(t.name)}" required /></div>
          <div class="field"><label>슬러그 (접속 주소)</label><input name="slug" value="${esc(t.slug)}" />
            <div class="hint">소문자/숫자/하이픈만. 현재 접속경로: <span class="mono">/${esc(t.slug)}</span></div></div>
          <div class="field"><label>커스텀 도메인</label><input name="domain" value="${esc(t.domain || '')}" placeholder="myshop.example.com" />
            <div class="hint">비우면 도메인 제거</div></div>
          <div class="field"><label>설명</label><textarea name="description" rows="3">${esc(t.description || '')}</textarea></div>
          <button class="btn btn-primary" type="submit">저장</button>
        </form>
      </div>`;
    $('#set-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      const body = { name: f.name.value.trim(), slug: f.slug.value.trim(),
                     domain: f.domain.value.trim(), description: f.description.value };
      try { await API.updateTenant(tenantId, body); ok('저장되었습니다.'); viewTenantSettings(tenantId); }
      catch (err) { const eb = $('#set-err'); eb.textContent = err.message; eb.classList.add('show'); }
    });
  } catch (e) { content().innerHTML = errPage(e); }
}

// ============================================================
//  쇼핑 (customer)
// ============================================================
const cart = {}; // productId -> qty

async function viewShop() {
  shell('shop', loadingHtml());
  const tid = session().tenantId;
  if (!tid) { content().innerHTML = emptyHtml('🛒', '소속 테넌트가 없는 계정입니다.'); return; }
  try {
    const [products, me] = await Promise.all([
      API.listProducts(tid, false).then(r => r.data),
      API.me().then(r => r.data).catch(() => ({ balance: 0 })),
    ]);
    content().innerHTML = `
      <div class="page-head"><h2>🛍️ 쇼핑</h2>
        <span class="badge green">잔액 ${money(me.balance)}</span>
        <div class="spacer"></div>
        <a class="btn btn-ghost" href="#/wallet">충전</a>
        <button class="btn btn-primary" id="checkout">주문하기</button></div>
      ${products.length ? `<div class="grid cols-3">${products.map(p => `
        <div class="product-card">
          <div class="thumb">📦</div>
          <div class="body">
            <div class="pname">${esc(p.name)}</div>
            <div class="muted" style="font-size:12px">${esc(p.category || '')}</div>
            <div class="price">${money(p.price)}</div>
            <div class="muted" style="font-size:12px">재고 ${p.stock}</div>
          </div>
          <div class="foot">
            <input class="field qty" type="number" min="0" value="0" data-qty="${p.id}" style="margin:0" ${p.stock <= 0 ? 'disabled' : ''}/>
            <span class="muted" style="font-size:12px">개</span>
          </div>
        </div>`).join('')}</div>`
        : emptyHtml('📦', '판매 중인 상품이 없습니다.')}`;

    $('#checkout').addEventListener('click', async () => {
      const items = $$('[data-qty]').map(i => ({ productId: i.dataset.qty, quantity: Number(i.value) }))
        .filter(x => x.quantity > 0);
      if (!items.length) { fail('수량을 1개 이상 선택하세요.'); return; }
      try {
        const r = await API.placeOrder(tid, { items });
        ok(`주문 완료! 금액 ${money(r.data.totalAmount)}`, '주문 성공');
        location.hash = '#/my-orders';
      } catch (e) { fail(e.message); }
    });
  } catch (e) { content().innerHTML = errPage(e); }
}

async function viewMyOrders() {
  shell('myorders', loadingHtml());
  const tid = session().tenantId;
  try {
    const orders = (await API.myOrders(tid)).data;
    content().innerHTML = `
      <div class="page-head"><h2>내 주문</h2><span class="badge gray">${orders.length}건</span></div>
      ${orders.length ? `<div class="table-wrap"><table>
        <thead><tr><th>주문ID</th><th>금액</th><th>상태</th><th>일시</th></tr></thead>
        <tbody>${orders.map(o => `<tr>
          <td class="mono">${shortId(o.id)}</td>
          <td><strong>${money(o.totalAmount)}</strong></td>
          <td>${statusBadge(o.status)}</td>
          <td class="nowrap mono muted">${fmtDate(o.createdAt)}</td>
        </tr>`).join('')}</tbody></table></div>`
        : emptyHtml('🧾', '주문 내역이 없습니다. 쇼핑하러 가볼까요?')}`;
  } catch (e) { content().innerHTML = errPage(e); }
}

// ── 충전/잔액 (customer) ──────────────────────────────────
async function viewWallet() {
  shell('wallet', loadingHtml());
  const tid = session().tenantId;
  if (!tid) { content().innerHTML = emptyHtml('💳', '소속 상점이 없는 계정입니다.'); return; }
  try {
    const [me, charges] = await Promise.all([
      API.me().then(r => r.data),
      API.listMyCharges(tid).then(r => r.data).catch(() => []),
    ]);
    content().innerHTML = `
      <div class="page-head"><h2>충전 / 잔액</h2></div>
      <div class="stat-cards">
        <div class="stat"><div class="k">현재 잔액</div><div class="v">${money(me.balance)}</div></div>
      </div>
      <div class="card" style="max-width:420px">
        <h3>충전 요청</h3>
        <div class="err-box" id="ch-err"></div>
        <form id="ch-form">
          <div class="field"><label>충전 금액 (원)</label>
            <input name="amount" type="number" min="1" placeholder="10000" required /></div>
          <button class="btn btn-primary" type="submit">충전 요청</button>
          <div class="hint" style="margin-top:6px">관리자 승인 후 잔액에 반영됩니다.</div>
        </form>
      </div>
      <div class="card">
        <h3>내 충전 요청 내역</h3>
        ${charges.length ? `<div class="table-wrap"><table>
          <thead><tr><th>금액</th><th>상태</th><th>요청일</th></tr></thead>
          <tbody>${charges.map(c => `<tr>
            <td><strong>${money(c.amount)}</strong></td>
            <td>${signupStatusBadge(c.status)}${c.rejectReason ? `<div class="muted" style="font-size:12px">사유: ${esc(c.rejectReason)}</div>` : ''}</td>
            <td class="nowrap mono muted">${fmtDate(c.createdAt)}</td>
          </tr>`).join('')}</tbody></table></div>`
          : emptyHtml('💳', '충전 요청 내역이 없습니다.')}
      </div>`;

    $('#ch-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const amount = Number(e.target.amount.value);
      try { await API.submitCharge(tid, amount); ok('충전 요청이 접수되었습니다. 관리자 승인을 기다려주세요.', '요청 완료'); viewWallet(); }
      catch (err) { const eb = $('#ch-err'); eb.textContent = err.message; eb.classList.add('show'); }
    });
  } catch (e) { content().innerHTML = errPage(e); }
}

// ── 에러 페이지 ───────────────────────────────────────────
function errPage(e) {
  const expired = (e.status === 401 || e.status === 403) && !/권한/.test(e.message || '');
  return `<div class="card"><div class="err-box show" style="margin:0">
    <strong>요청 실패:</strong> ${esc(e.message)}
    ${expired ? '<div style="margin-top:6px"><a href="#/login" data-clear-auth>다시 로그인하기</a></div>' : ''}
  </div></div>`;
}

// ============================================================
//  라우터
// ============================================================
function router() {
  const hash = location.hash || '';

  if (hash === '#/login' || (!session() && hash !== '#/login')) {
    if (!session()) { viewLogin(); return; }
  }
  if (hash === '#/login' && session()) { location.hash = defaultRoute(); return; }
  if (!session()) { viewLogin(); return; }

  // 패턴 매칭
  let m;
  if (hash === '' || hash === '#/' || hash === '#/dashboard') {
    if (isCust()) { location.hash = '#/shop'; return; }
    if (isAdmin()) { location.hash = '#/my-tenants'; return; }
    viewDashboard();
  } else if (hash === '#/tenants' && isSuper()) viewTenants();
  else if (hash === '#/my-tenants' && (isAdmin() || isSuper())) viewMyTenants();
  else if (hash === '#/users' && isSuper()) viewUsers();
  else if (hash === '#/audit' && isSuper()) viewAudit();
  else if ((m = hash.match(/^#\/tenant\/([^/]+)\/products$/))) viewProducts(m[1]);
  else if ((m = hash.match(/^#\/tenant\/([^/]+)\/orders$/))) viewOrders(m[1]);
  else if ((m = hash.match(/^#\/tenant\/([^/]+)\/signups$/))) viewSignupRequests(m[1]);
  else if ((m = hash.match(/^#\/tenant\/([^/]+)\/charges$/))) viewChargeRequests(m[1]);
  else if ((m = hash.match(/^#\/tenant\/([^/]+)\/settings$/))) viewTenantSettings(m[1]);
  else if (hash === '#/shop' && isCust()) viewShop();
  else if (hash === '#/my-orders' && isCust()) viewMyOrders();
  else if (hash === '#/wallet' && isCust()) viewWallet();
  else {
    // 권한 없는 경로 → 기본 화면
    location.hash = defaultRoute();
  }
}

// 인라인 onclick 대체(엄격 CSP 호환): 세션 만료 '다시 로그인하기' 처리
document.addEventListener('click', (e) => {
  const t = e.target.closest && e.target.closest('[data-clear-auth]');
  if (t) API.clearAuth();
});

window.addEventListener('hashchange', router);
window.addEventListener('DOMContentLoaded', () => {
  if (session()) startNotifPolling();   // 역할에 따라 admin/super 또는 customer 폴링
  if (!location.hash) location.hash = session() ? defaultRoute() : '#/login';
  else router();
});
