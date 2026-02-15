const UI = (() => {
  function qs(sel, el = document) { return el.querySelector(sel); }
  function qsa(sel, el = document) { return [...el.querySelectorAll(sel)]; }

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json" , ...(opts.headers||{}) },
      ...opts
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.error || "Request failed");
    return json;
  }

  async function apiRaw(path, opts = {}) {
    const res = await fetch(path, opts);
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.error || "Request failed");
    return json;
  }

  function icon(name) {
    // minimal SVG icon set (no emojis)
    const icons = {
      home: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M3 10.5 12 3l9 7.5V21a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1v-10.5z"/></svg>`,
      building:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M4 21V3h12v18"/><path d="M16 9h4v12"/><path d="M8 7h4"/><path d="M8 11h4"/><path d="M8 15h4"/></svg>`,
      users:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
      bell:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M18 8a6 6 0 1 0-12 0c0 7-3 7-3 7h18s-3 0-3-7"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>`,
      calendar:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4"/><path d="M8 2v4"/><path d="M3 10h18"/></svg>`,
      upload:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 3v12"/><path d="M7 8l5-5 5 5"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/></svg>`,
      plus:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 5v14"/><path d="M5 12h14"/></svg>`,
      link:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M10 13a5 5 0 0 1 0-7l1-1a5 5 0 0 1 7 7l-1 1"/><path d="M14 11a5 5 0 0 1 0 7l-1 1a5 5 0 0 1-7-7l1-1"/></svg>`,
      edit:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>`,
      logout:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/></svg>`
    };
    return icons[name] || icons.home;
  }

  async function me() {
    const r = await api("/api/me", { method: "GET" });
    return r.user;
  }

  function sidebar(active) {
    const nav = [
      { href:"/dashboard.html", key:"dashboard", label:"Dashboard", ic:"home" },
      { href:"/properties.html", key:"properties", label:"Properties", ic:"building" },
      { href:"/owners.html", key:"owners", label:"Owners", ic:"users" },
      { href:"/leads.html", key:"leads", label:"Leads", ic:"users" },
      { href:"/showings.html", key:"showings", label:"Showings", ic:"calendar" },
      { href:"/notifications.html", key:"notifications", label:"Notifications", ic:"bell" },
      { href:"/import-leads.html", key:"import", label:"Import Leads", ic:"upload" },
      { href:"/users.html", key:"users", label:"Users", ic:"users" },
    ];
    const items = nav.map(n => `
      <a class="nav-item ${n.key===active?"active":""}" href="${n.href}">
        <span class="ic">${icon(n.ic)}</span>
        <span>${n.label}</span>
      </a>`).join("");
    return `
      <aside class="sidebar">
        <div class="brand">
          <div class="brand-ic">${icon("building")}</div>
          <div class="brand-txt">
            <div class="brand-name">Real Estate CRM</div>
            <div class="brand-sub">JSON Edition</div>
          </div>
        </div>
        <nav class="nav">${items}</nav>
        <div class="side-footer">
          <button id="btnLogout" class="btn ghost full">
            <span class="ic">${icon("logout")}</span>
            <span>Logout</span>
          </button>
        </div>
      </aside>
    `;
  }

  async function mountLayout(activeKey) {
    const user = await me();
    if (!user && location.pathname !== "/login.html") location.href = "/login.html";
    const root = document.body;
    root.classList.add("app");
    const layout = `
      ${sidebar(activeKey)}
      <main class="main">
        <header class="topbar">
          <div class="top-left">
            <div class="page-title" id="pageTitle"></div>
            <div class="page-sub" id="pageSub"></div>
          </div>
          <div class="top-right">
            <div class="user-pill">
              <span class="dot"></span>
              <span>${user?.name || ""}</span>
              <span class="muted">(${user?.role || ""})</span>
            </div>
          </div>
        </header>
        <section class="content" id="content"></section>
      </main>
    `;
    root.innerHTML = layout;

    const btn = qs("#btnLogout");
    if (btn) {
      btn.addEventListener("click", async () => {
        try { await api("/api/auth/logout", { method:"POST", body: "{}" }); }
        catch {}
        location.href = "/login.html";
      });
    }
    return user;
  }

  function setTitle(t, s="") {
    qs("#pageTitle").textContent = t;
    qs("#pageSub").textContent = s;
  }

  function toast(msg) {
    let el = document.querySelector(".toast");
    if (!el) {
      el = document.createElement("div");
      el.className = "toast";
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.classList.add("show");
    setTimeout(() => el.classList.remove("show"), 2200);
  }

  function fmtMoney(n) {
    const x = Number(n || 0);
    return x.toLocaleString(undefined, { maximumFractionDigits: 0 });
  }

  return { qs, qsa, api, apiRaw, mountLayout, setTitle, toast, fmtMoney, icon };
})();
