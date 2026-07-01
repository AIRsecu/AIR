/* ============================================================
 *  api.js  - 백엔드(API) 통신 클라이언트
 *   - 서버 주소(baseUrl)는 localStorage 에 저장 → UI 에서 변경 가능
 *   - accessToken 만료 시 refreshToken 으로 1회 자동 갱신 후 재시도
 * ============================================================ */
const API = (() => {
  const LS = {
    base:    'shop_api_base',
    access:  'shop_access',
    refresh: 'shop_refresh',
    session: 'shop_session',
  };

  // ── 서버 주소 ───────────────────────────────────────────
  // localhost(개발)에서 띄우면 입력한 EC2 주소로 직접 호출,
  // 실제 호스트(EC2 nginx)에서 서빙되면 동일 출처(상대경로)로 호출 → 프록시 경유.
  function isLocalHost() {
    const h = location.hostname;
    return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '';
  }
  function getBase() {
    if (!isLocalHost()) return '';                       // EC2 통합 서빙 → 동일 출처
    return localStorage.getItem(LS.base) || '';          // 로컬 개발 → 입력값
  }
  function setBase(url) {
    localStorage.setItem(LS.base, url.trim().replace(/\/+$/, ''));
  }
  function apiUrl(path) {
    return getBase().replace(/\/+$/, '') + '/api/v1' + path; // base='' 이면 상대경로
  }

  // ── 토큰 / 세션 저장 ────────────────────────────────────
  const getAccess  = () => localStorage.getItem(LS.access);
  const getRefresh = () => localStorage.getItem(LS.refresh);
  function getSession() {
    try { return JSON.parse(localStorage.getItem(LS.session)); }
    catch { return null; }
  }
  function saveTokens(access, refresh) {
    if (access)  localStorage.setItem(LS.access, access);
    if (refresh) localStorage.setItem(LS.refresh, refresh);
  }
  function saveSession(s) { localStorage.setItem(LS.session, JSON.stringify(s)); }
  function clearAuth() {
    localStorage.removeItem(LS.access);
    localStorage.removeItem(LS.refresh);
    localStorage.removeItem(LS.session);
  }

  // ── 에러 타입 ───────────────────────────────────────────
  class ApiError extends Error {
    constructor(status, code, message) {
      super(message || code || ('HTTP ' + status));
      this.status = status; this.code = code;
    }
  }

  // ── 저수준 요청 ─────────────────────────────────────────
  async function raw(method, path, body, withAuth) {
    const headers = { 'Content-Type': 'application/json' };
    if (withAuth && getAccess()) headers['Authorization'] = 'Bearer ' + getAccess();

    let res;
    try {
      res = await fetch(apiUrl(path), {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (e) {
      throw new ApiError(0, 'NETWORK',
        '서버에 연결할 수 없습니다. 서버 주소/보안그룹(8080)/백엔드 상태를 확인하세요.');
    }

    // 본문이 비어있을 수 있음(403 등)
    const text = await res.text();
    let json = null;
    if (text) { try { json = JSON.parse(text); } catch { /* ignore */ } }

    if (!res.ok) {
      const code = json?.code || ('HTTP_' + res.status);
      // 토큰 만료 시 인증 필터가 통과 못 해 본문 없는 401/403 이 옴 → 재로그인 안내
      const sessionExpired = '캐시가 만료되었습니다. 다시 로그인 하시면 됩니다.';
      const msg  = json?.message
        || (res.status === 403 ? sessionExpired : null)
        || (res.status === 401 ? sessionExpired : null)
        || ('요청 실패 (HTTP ' + res.status + ')');
      throw new ApiError(res.status, code, msg);
    }
    return json; // { success, data, ... }
  }

  // ── 토큰 자동 갱신 래퍼 ─────────────────────────────────
  let refreshing = null;
  async function doRefresh() {
    const rt = getRefresh();
    if (!rt) throw new ApiError(401, 'NO_REFRESH', '재로그인이 필요합니다.');
    if (!refreshing) {
      refreshing = raw('POST', '/auth/refresh', { refreshToken: rt }, false)
        .then(j => { saveTokens(j.data.accessToken, j.data.refreshToken); return j; })
        .finally(() => { refreshing = null; });
    }
    return refreshing;
  }

  async function request(method, path, body, withAuth = true) {
    try {
      return await raw(method, path, body, withAuth);
    } catch (e) {
      const expired = withAuth && e.status === 401 &&
        (e.code === 'TOKEN_EXPIRED' || e.code === 'TOKEN_INVALID');
      if (expired && getRefresh()) {
        await doRefresh();                       // 실패 시 throw → 로그인 화면으로
        return await raw(method, path, body, withAuth);
      }
      throw e;
    }
  }

  // ── 인증 ────────────────────────────────────────────────
  async function login(username, password) {
    const j = await raw('POST', '/auth/login', { username, password }, false);
    saveTokens(j.data.accessToken, j.data.refreshToken);
    saveSession({
      userId:   j.data.userId,
      username: j.data.username,
      role:     j.data.role,
      tenantId: j.data.tenantId,
    });
    return j.data;
  }
  async function logout() {
    const rt = getRefresh();
    try { await request('POST', '/auth/logout', { refreshToken: rt }); }
    catch { /* 무시 */ }
    clearAuth();
  }

  return {
    getBase, setBase, isLocalHost,
    getSession, getAccess, clearAuth,
    login, logout, request,
    ApiError,

    // 도메인 헬퍼 -----------------------------------------
    health:        ()              => raw('GET', '/health', undefined, false),

    // tenants
    listTenantsAll:()              => request('GET', '/tenants/all'),
    listTenants:   ()              => request('GET', '/tenants', undefined, false),
    listManagedTenants: ()         => request('GET', '/tenants/managed'),
    createTenant:  (b)             => request('POST', '/tenants', b),
    updateTenant:  (id, b)         => request('PATCH', `/tenants/${id}`, b),
    deleteTenant:  (id)            => request('DELETE', `/tenants/${id}`),
    listTenantAdmins:   (id)       => request('GET', `/tenants/${id}/admins`),
    assignTenantAdmin:  (id, userId) => request('POST', `/tenants/${id}/admins`, { userId }),
    unassignTenantAdmin:(id, userId) => request('DELETE', `/tenants/${id}/admins/${userId}`),

    // users
    listUsers:     ()              => request('GET', '/users'),
    me:            ()              => request('GET', '/users/me'),
    createUser:    (b)             => request('POST', '/users', b),
    updateUser:    (id, b)         => request('PATCH', `/users/${id}`, b),
    deleteUser:    (id)            => request('DELETE', `/users/${id}`),

    // products
    listProducts:  (tid, all)      => request('GET', `/tenants/${tid}/products${all ? '?activeOnly=false' : ''}`),
    createProduct: (tid, b)        => request('POST', `/tenants/${tid}/products`, b),
    updateProduct: (tid, id, b)    => request('PATCH', `/tenants/${tid}/products/${id}`, b),
    deleteProduct: (tid, id)       => request('DELETE', `/tenants/${tid}/products/${id}`),

    // uploads (파일 업로드 — multipart/form-data; [취약] 서버측 확장자/경로 검증 없음)
    uploadFile:    (tid, file) => {
      const fd = new FormData();
      fd.append('file', file);
      const headers = {};
      if (getAccess()) headers['Authorization'] = 'Bearer ' + getAccess();
      return fetch(apiUrl(`/tenants/${tid}/uploads`), { method: 'POST', headers, body: fd })
        .then(async res => {
          const t = await res.text(); let j = null; if (t) { try { j = JSON.parse(t); } catch {} }
          if (!res.ok) throw new ApiError(res.status, j?.code || ('HTTP_' + res.status),
            j?.message || ('업로드 실패 (HTTP ' + res.status + ')'));
          return j;
        });
    },
    downloadUrl:   (tid, name)     => apiUrl(`/tenants/${tid}/uploads/download?name=`) + encodeURIComponent(name),

    // orders
    listOrders:    (tid)           => request('GET', `/tenants/${tid}/orders`),
    myOrders:      (tid)           => request('GET', `/tenants/${tid}/orders/my`),
    placeOrder:    (tid, b)        => request('POST', `/tenants/${tid}/orders`, b),
    updateOrderStatus:(tid, id, s) => request('PATCH', `/tenants/${tid}/orders/${id}/status`, { status: s }),

    // audit
    auditRecent:   (limit = 100)   => request('GET', `/audit/recent?limit=${limit}`),
    auditMine:     ()              => request('GET', '/audit/me'),

    // signup requests (회원가입 요청)
    submitSignup:  (tid, b)        => request('POST', `/tenants/${tid}/signup-requests`, b, false),
    listSignups:   (tid, status)   => request('GET', `/tenants/${tid}/signup-requests${status ? '?status=' + status : ''}`),
    approveSignup: (tid, id)       => request('POST', `/tenants/${tid}/signup-requests/${id}/approve`, {}),
    rejectSignup:  (tid, id, reason) => request('POST', `/tenants/${tid}/signup-requests/${id}/reject`, { reason }),

    // charge requests (잔액 충전)
    submitCharge:  (tid, amount)   => request('POST', `/tenants/${tid}/charge-requests`, { amount }),
    listMyCharges: (tid)           => request('GET', `/tenants/${tid}/charge-requests/mine`),
    listCharges:   (tid, status)   => request('GET', `/tenants/${tid}/charge-requests${status ? '?status=' + status : ''}`),
    approveCharge: (tid, id)       => request('POST', `/tenants/${tid}/charge-requests/${id}/approve`, {}),
    rejectCharge:  (tid, id, reason) => request('POST', `/tenants/${tid}/charge-requests/${id}/reject`, { reason }),

    // notifications (가입+충전 대기 집계)
    pendingNotifications: ()       => request('GET', '/notifications/pending-signups'),

    // 실시간 알림 스트림(SSE) URL. EventSource 는 헤더를 못 보내므로 토큰을 쿼리로 전달.
    streamUrl: ()                  => apiUrl('/notifications/stream') + '?token=' + encodeURIComponent(getAccess() || ''),
  };
})();
