// =======================
// Helpers.js (ajustado)
// =======================

// ----------------- Carrinho -----------------
(() => {
  // Namespacing por host p/ evitar conflito entre ambientes (localhost, prod, etc.)
  const NS = location.hostname.replace(/\W+/g, '_');
  const KEY_CART = `cart_${NS}`;
  const KEY_ZONE = `zone_${NS}`;      // zona de entrega selecionada (opcional)
  const KEY_FEE  = `fee_${NS}`;       // taxa de entrega aplicada (opcional)

  const safeRead = (k, fallback) => {
    try {
      const raw = localStorage.getItem(k);
      return raw ? JSON.parse(raw) : fallback;
    } catch { return fallback; }
  };
  const safeWrite = (k, v) => {
    try { localStorage.setItem(k, JSON.stringify(v)); }
    catch { /* quota cheia: silencioso */ }
  };

  // Identificador do item: preferir id; senão (name+price)
  const itemKey = (it) => it?.id != null
    ? `id:${String(it.id)}`
    : `np:${String(it.name)}|${Number(it.price)}`;

  window.Cart = {
    // Itens
    load() { return safeRead(KEY_CART, []); },
    save(items) { safeWrite(KEY_CART, items || []); },
    clear() { this.save([]); },

    add(item) { // {id?, name, price, qty}
      const items = this.load();
      const key = itemKey(item);
      const idx = items.findIndex(i => itemKey(i) === key);
      const qty = Math.max(1, Number(item.qty || 1));
      if (idx >= 0) {
        items[idx].qty = Number(items[idx].qty || 0) + qty;
      } else {
        items.push({
          id: item.id ?? null,
          name: String(item.name),
          price: Number(item.price),
          qty
        });
      }
      this.save(items);
    },

    setQty(ref, qty) {
      const items = this.load();
      const key = itemKey(ref);
      const i = items.findIndex(x => itemKey(x) === key);
      if (i >= 0) {
        const v = Math.max(0, Number(qty || 0));
        if (v === 0) items.splice(i, 1);
        else items[i].qty = v;
        this.save(items);
      }
    },

    inc(ref, step = 1) {
      const items = this.load();
      const key = itemKey(ref);
      const i = items.findIndex(x => itemKey(x) === key);
      if (i >= 0) {
        items[i].qty = Math.max(1, Number(items[i].qty || 1) + Number(step || 1));
        this.save(items);
      }
    },

    dec(ref, step = 1) {
      this.inc(ref, -Math.abs(step || 1));
      // remove se zerar
      const items = this.load().filter(it => Number(it.qty) > 0);
      this.save(items);
    },

    remove(ref) {
      const key = itemKey(ref);
      this.save(this.load().filter(i => itemKey(i) !== key));
    },

    subtotal() {
      return this.load().reduce((a, b) => a + Number(b.price) * Number(b.qty), 0);
    },

    // -------- entrega/fee/zone (opcional) --------
    setZone(z) { safeWrite(KEY_ZONE, z); },
    getZone() { return safeRead(KEY_ZONE, null); },

    setFee(v) { safeWrite(KEY_FEE, Number(v || 0)); },
    getFee() { return Number(safeRead(KEY_FEE, 0)); },

    total() { return this.subtotal() + this.getFee(); }
  };
})();

// ----------------- API base / Fetch wrappers -----------------
(() => {
  const isLocal =
    location.hostname === 'localhost' ||
    location.hostname === '127.0.0.1';

  // DEV: mesma origem (servidor Node servindo /api e estáticos)
  // PROD: por padrão usa a origem da página; se sua API estiver em outro domínio,
  // defina window.API_BASE *antes* de carregar este arquivo (ex: https://api.seudominio.com/)
  const DEFAULT_API_BASE = isLocal ? '/' : (window.location.origin + '/');

  // permite override prévio
  const base = (window.API_BASE || DEFAULT_API_BASE).replace(/\/?$/, '/');
  window.API_BASE = base;

  const join = (a, b) => (a.replace(/\/+$/, '') + '/' + String(b).replace(/^\/+/, ''));

  function buildApiUrl(path) {
    if (/^https?:\/\//i.test(path)) return path;
    return join(window.API_BASE, path);
  }

  // Normaliza init + JSON automático (se body for objeto)
  function normalizeInit(init = {}) {
    const out = { ...init };
    out.headers = new Headers(init.headers || {});
    // Accept JSON por padrão
    if (!out.headers.has('Accept')) out.headers.set('Accept', 'application/json');

    // Se body for objeto e não tiver Content-Type, envia JSON
    if (out.body && typeof out.body === 'object' && !(out.body instanceof FormData)) {
      if (!out.headers.has('Content-Type')) out.headers.set('Content-Type', 'application/json; charset=utf-8');
      out.body = JSON.stringify(init.body);
    }
    return out;
  }

  // Fetch simples
  window.apiFetch = (path, init = {}) =>
    fetch(buildApiUrl(path), normalizeInit(init));

  // JSON com checagem + timeout
  window.apiFetchJSON = async (path, init = {}, { timeoutMs = 15000 } = {}) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort('timeout'), timeoutMs);
    try {
      const res = await window.apiFetch(path, { ...init, signal: controller.signal });
      const ct = res.headers.get('content-type') || '';
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`HTTP ${res.status} – ${text.slice(0, 300)}`);
      }
      if (!ct.includes('application/json')) {
        const text = await res.text().catch(() => '');
        throw new Error(`Resposta não-JSON: ${text.slice(0, 200)}`);
      }
      return res.json();
    } finally {
      clearTimeout(timer);
    }
  };

  // Atalhos REST (mesma origem por padrão)
  window.api = {
    get: (p, opt) => window.apiFetchJSON(p, { method: 'GET', ...(opt || {}) }),
    post: (p, body, opt) => window.apiFetchJSON(p, { method: 'POST', body, ...(opt || {}) }),
    put: (p, body, opt) => window.apiFetchJSON(p, { method: 'PUT', body, ...(opt || {}) }),
    patch: (p, body, opt) => window.apiFetchJSON(p, { method: 'PATCH', body, ...(opt || {}) }),
    del: (p, opt) => window.apiFetchJSON(p, { method: 'DELETE', ...(opt || {}) }),
  };

  // Para rotas com cookie (admin/login) — same-origin + credentials
  window.apiFetchAuth = (path, init = {}) =>
    window.apiFetch(path, { credentials: 'include', ...init });

  window.apiAuth = {
    get: (p, opt) => window.apiFetchJSON(p, { method: 'GET', credentials: 'include', ...(opt || {}) }),
    post: (p, body, opt) => window.apiFetchJSON(p, { method: 'POST', credentials: 'include', body, ...(opt || {}) }),
    put: (p, body, opt) => window.apiFetchJSON(p, { method: 'PUT', credentials: 'include', body, ...(opt || {}) }),
    patch: (p, body, opt) => window.apiFetchJSON(p, { method: 'PATCH', credentials: 'include', body, ...(opt || {}) }),
    del: (p, opt) => window.apiFetchJSON(p, { method: 'DELETE', credentials: 'include', ...(opt || {}) }),
  };

  // ----------------- Socket.io (se usar no admin) -----------------
  // Default = same-origin. Para API em domínio separado, defina window.WS_URL antes deste script.
  window.WS_URL = window.WS_URL || window.location.origin;
})();

// ----------------- Navegação simples -----------------
window.Nav = {
  go(p) { window.location.href = p; }
};
