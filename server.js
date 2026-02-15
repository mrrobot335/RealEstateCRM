/* Real Estate CRM (JSON storage, Node http only)
   - Auth (cookie sessions)
   - RBAC (manager/agent)
   - Properties with images, owner, sources/urls
   - Leads with scheduling showings
   - Notifications (showing close)
   - Import leads CSV + XLSX
*/
const http = require("http");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const Busboy = require("busboy");
const { nanoid } = require("nanoid");
const XLSX = require("xlsx");

const PORT = 3000;
const ROOT = __dirname;

const DIR_DATA = path.join(ROOT, "data");
const DIR_PUBLIC = path.join(ROOT, "public");
const DIR_UPLOADS = path.join(ROOT, "uploads");
const DIR_PROP_UPLOADS = path.join(DIR_UPLOADS, "properties");

const FILES = {
    users: path.join(DIR_DATA, "users.json"),
    sessions: path.join(DIR_DATA, "sessions.json"),
    properties: path.join(DIR_DATA, "properties.json"),
    owners: path.join(DIR_DATA, "owners.json"),
    leads: path.join(DIR_DATA, "leads.json"),
    showings: path.join(DIR_DATA, "showings.json"),
    notifications: path.join(DIR_DATA, "notifications.json"),
    audit: path.join(DIR_DATA, "audit.json"),
};

const PERMS = {
    manager: {
        properties: ["create", "read", "update", "delete"],
        owners: ["create", "read", "update", "delete"],
        leads: ["create", "read", "update", "delete", "import"],
        showings: ["create", "read", "update", "delete"],
        users: ["create", "read", "update", "delete"],
        notifications: ["read", "update"],
        audit: ["read"],
    },
    agent: {
        properties: ["create", "read", "update"],
        owners: ["create", "read", "update"],
        leads: ["create", "read", "update", "import"],
        showings: ["create", "read", "update"],
        users: ["read"],
        notifications: ["read", "update"],
        audit: [],
    },
};


console.log("SERVER STARTING");


function nowISO() {
    return new Date().toISOString();
}

function safeJSONParse(s, fallback) {
    try { return JSON.parse(s); } catch { return fallback; }
}

async function ensureDirs() {
    for (const d of [DIR_DATA, DIR_UPLOADS, DIR_PROP_UPLOADS]) {
        await fsp.mkdir(d, { recursive: true });
    }
}

async function atomicWriteJSON(file, data) {
    const tmp = file + ".tmp";
    await fsp.writeFile(tmp, JSON.stringify(data, null, 2), "utf8");
    await fsp.rename(tmp, file);
}

async function readJSON(file, fallback) {
    try {
        const txt = await fsp.readFile(file, "utf8");
        return safeJSONParse(txt, fallback);
    } catch {
        return fallback;
    }
}

function contentTypeByExt(ext) {
    const map = {
        ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".svg": "image/svg+xml",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
        ".json": "application/json; charset=utf-8",
    };
    return map[ext.toLowerCase()] || "application/octet-stream";
}

function send(res, code, body, headers = {}) {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
    res.writeHead(code, { "Content-Length": buf.length, ...headers });
    res.end(buf);
}

function sendJSON(res, code, obj) {
    send(res, code, JSON.stringify(obj), { "Content-Type": "application/json; charset=utf-8" });
}

function redirect(res, location) {
    res.writeHead(302, { Location: location });
    res.end();
}

function parseCookies(req) {
    const h = req.headers.cookie || "";
    const out = {};
    h.split(";").map(s => s.trim()).filter(Boolean).forEach(pair => {
        const i = pair.indexOf("=");
        if (i >= 0) out[pair.slice(0, i)] = decodeURIComponent(pair.slice(i + 1));
    });
    return out;
}

function readBody(req, maxBytes = 2_000_000) {
    return new Promise((resolve, reject) => {
        let chunks = [];
        let total = 0;
        req.on("data", (c) => {
            total += c.length;
            if (total > maxBytes) {
                reject(new Error("Payload too large"));
                req.destroy();
                return;
            }
            chunks.push(c);
        });
        req.on("end", () => resolve(Buffer.concat(chunks)));
        req.on("error", reject);
    });
}

function urlParts(req) {
    const u = new URL(req.url, `http://${req.headers.host}`);
    return u;
}

function hasPerm(user, area, action) {
    if (!user) return false;
    const role = user.role;
    const rolePerms = PERMS[role] || {};
    const allowed = rolePerms[area] || [];
    return allowed.includes(action);
}

async function auditLog(user, action, meta = {}) {
    const audit = await readJSON(FILES.audit, []);
    audit.unshift({
        id: "aud_" + nanoid(10),
        at: nowISO(),
        userId: user?.id || null,
        userEmail: user?.email || null,
        action,
        meta,
    });
    await atomicWriteJSON(FILES.audit, audit.slice(0, 2000));
}

async function seedIfEmpty() {
    const users = await readJSON(FILES.users, null);
    if (!users || users.length === 0) {
        const managerPass = await bcrypt.hash("Manager123!", 10);
        const agentPass = await bcrypt.hash("Agent123!", 10);

        const seedUsers = [
            {
                id: "u_mgr_" + nanoid(6),
                name: "Manager",
                email: "manager@crm.local",
                role: "manager",
                passwordHash: managerPass,
                createdAt: nowISO(),
                isActive: true,
            },
            {
                id: "u_agt_" + nanoid(6),
                name: "Agent",
                email: "agent@crm.local",
                role: "agent",
                passwordHash: agentPass,
                createdAt: nowISO(),
                isActive: true,
            },
        ];
        await atomicWriteJSON(FILES.users, seedUsers);
    }

    for (const [k, file] of Object.entries(FILES)) {
        const exists = fs.existsSync(file);
        if (!exists) {
            const empty = (k === "sessions") ? {} : [];
            await atomicWriteJSON(file, empty);
        }
    }
}

async function getUserFromSession(req) {
    const cookies = parseCookies(req);
    const sid = cookies.sid;
    if (!sid) return null;

    const sessions = await readJSON(FILES.sessions, {});
    const sess = sessions[sid];
    if (!sess) return null;

    if (Date.now() > sess.expiresAt) {
        delete sessions[sid];
        await atomicWriteJSON(FILES.sessions, sessions);
        return null;
    }

    const users = await readJSON(FILES.users, []);
    return users.find(u => u.id === sess.userId) || null;
}

async function createSession(res, userId) {
    const sessions = await readJSON(FILES.sessions, {});
    const sid = crypto.randomBytes(24).toString("hex");
    sessions[sid] = {
        userId,
        createdAt: Date.now(),
        expiresAt: Date.now() + 1000 * 60 * 60 * 12 // 12 hours
    };
    await atomicWriteJSON(FILES.sessions, sessions);

    const cookie = [
        `sid=${encodeURIComponent(sid)}`,
        "HttpOnly",
        "Path=/",
        "SameSite=Lax",
    ].join("; ");
    res.setHeader("Set-Cookie", cookie);
}

async function destroySession(req, res) {
    const cookies = parseCookies(req);
    const sid = cookies.sid;
    if (sid) {
        const sessions = await readJSON(FILES.sessions, {});
        delete sessions[sid];
        await atomicWriteJSON(FILES.sessions, sessions);
    }
    res.setHeader("Set-Cookie", "sid=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax");
}

function requireAuth(user, res) {
    if (!user) {
        sendJSON(res, 401, { ok: false, error: "Not authenticated" });
        return false;
    }
    return true;
}

function requirePerm(user, res, area, action) {
    if (!requireAuth(user, res)) return false;
    if (!hasPerm(user, area, action)) {
        sendJSON(res, 403, { ok: false, error: "Forbidden" });
        return false;
    }
    return true;
}

function sanitizeText(s, max = 5000) {
    if (typeof s !== "string") return "";
    return s.trim().slice(0, max);
}

function toNumber(x, def = null) {
    const n = Number(x);
    return Number.isFinite(n) ? n : def;
}

function normalizeUrl(u) {
    const s = String(u || "").trim();
    if (!s) return "";
    try {
        const parsed = new URL(s);
        return parsed.toString();
    } catch {
        return "";
    }
}

function isImageFilename(name) {
    const ext = path.extname(name).toLowerCase();
    return [".png", ".jpg", ".jpeg", ".webp"].includes(ext);
}

async function serveStatic(req, res) {
    const urlPath = (req.url || "/").split("?")[0];

    // 🔹 SERVE UPLOADS
    if (urlPath.startsWith("/uploads/")) {
        const rel = urlPath.replace("/uploads/", "");
        const filePath = path.join(DIR_UPLOADS, rel);

        if (!filePath.startsWith(DIR_UPLOADS)) {
            return send(res, 400, "Bad path");
        }

        try {
            const st = await fsp.stat(filePath);
            if (!st.isFile()) return send(res, 404, "Not found");

            const ext = path.extname(filePath);
            const buf = await fsp.readFile(filePath);

            return send(res, 200, buf, {
                "Content-Type": contentTypeByExt(ext),
                "Cache-Control": "no-store"
            });
        } catch {
            return send(res, 404, "Not found");
        }
    }

    // 🔹 SERVE PUBLIC FILES
    let filePath = urlPath === "/" ? "/login.html" : urlPath;
    if (filePath.includes("..")) return send(res, 400, "Bad request");

    const full = path.join(DIR_PUBLIC, filePath);
    if (!full.startsWith(DIR_PUBLIC)) return send(res, 400, "Bad path");

    try {
        const st = await fsp.stat(full);
        if (!st.isFile()) return send(res, 404, "Not found");

        const ext = path.extname(full);
        const buf = await fsp.readFile(full);

        return send(res, 200, buf, {
            "Content-Type": contentTypeByExt(ext),
            "Cache-Control": "no-store"
        });
    } catch {
        return send(res, 404, "Not found");
    }
}



function computeUpcomingNotifications(showings, leads, properties) {
    const notif = [];
    const now = Date.now();
    const soonMs = 1000 * 60 * 60 * 24; // 24h
    for (const s of showings) {
        if (s.status !== "Scheduled") continue;
        const at = Date.parse(s.at);
        if (!Number.isFinite(at)) continue;
        const diff = at - now;
        if (diff > 0 && diff <= soonMs) {
            const lead = leads.find(l => l.id === s.leadId);
            const prop = properties.find(p => p.id === s.propertyId);
            notif.push({
                id: "ntf_" + nanoid(10),
                type: "showing_soon",
                severity: diff <= 1000 * 60 * 60 * 3 ? "High" : "Medium",
                title: "Upcoming showing",
                message: `${lead?.name || "Lead"} has a showing for ${prop?.title || "property"} within 24h.`,
                showingId: s.id,
                at: nowISO(),
                isRead: false,
            });
        }
    }
    return notif;
}

function parseCSV(text) {
    // simple CSV parser: comma separated, supports quoted values
    const rows = [];
    let i = 0;
    const s = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    let row = [];
    let cur = "";
    let inQ = false;

    while (i < s.length) {
        const ch = s[i];
        if (inQ) {
            if (ch === '"') {
                if (s[i + 1] === '"') { cur += '"'; i += 2; continue; }
                inQ = false; i++; continue;
            }
            cur += ch; i++; continue;
        } else {
            if (ch === '"') { inQ = true; i++; continue; }
            if (ch === ",") { row.push(cur.trim()); cur = ""; i++; continue; }
            if (ch === "\n") { row.push(cur.trim()); rows.push(row); row = []; cur = ""; i++; continue; }
            cur += ch; i++; continue;
        }
    }
    row.push(cur.trim());
    rows.push(row);
    return rows.filter(r => r.some(x => (x || "").trim() !== ""));
}

function mapLeadRow(headers, row) {
    const obj = {};
    headers.forEach((h, idx) => obj[h] = row[idx] ?? "");
    // common column mapping
    const name = obj.name || obj.fullname || obj.client || obj.lead || obj["Name"] || obj["Full Name"] || "";
    const phone = obj.phone || obj.mobile || obj.tel || obj["Phone"] || "";
    const email = obj.email || obj.mail || obj["Email"] || "";
    const source = obj.source || obj.channel || obj["Source"] || "";
    const status = obj.status || obj["Status"] || "New";
    const budget = obj.budget || obj["Budget"] || "";
    const notes = obj.notes || obj["Notes"] || "";
    return {
        name: sanitizeText(String(name), 120),
        phone: sanitizeText(String(phone), 60),
        email: sanitizeText(String(email), 120),
        source: sanitizeText(String(source), 120),
        status: sanitizeText(String(status), 40) || "New",
        budget: sanitizeText(String(budget), 60),
        notes: sanitizeText(String(notes), 2000),
    };
}

async function routeAPI(req, res, user) {
    const u = urlParts(req);

    // keep notifications up-to-date
    // (for demo: compute on each API call, dedupe by showingId)
    const properties = await readJSON(FILES.properties, []);
    const leads = await readJSON(FILES.leads, []);
    const showings = await readJSON(FILES.showings, []);
    let notifications = await readJSON(FILES.notifications, []);

    const gen = computeUpcomingNotifications(showings, leads, properties);
    const existingKey = new Set(notifications.map(n => (n.type + ":" + (n.showingId || ""))));
    for (const n of gen) {
        const key = n.type + ":" + (n.showingId || "");
        if (!existingKey.has(key)) notifications.unshift(n);
    }
    notifications = notifications.slice(0, 500);
    await atomicWriteJSON(FILES.notifications, notifications);

    // AUTH
    if (req.method === "POST" && u.pathname === "/api/auth/login") {
        const buf = await readBody(req);
        const body = safeJSONParse(buf.toString("utf8"), {});
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        const users = await readJSON(FILES.users, []);
        const found = users.find(x => x.email.toLowerCase() === email && x.isActive);
        if (!found) return sendJSON(res, 400, { ok: false, error: "Invalid credentials" });

        const ok = await bcrypt.compare(password, found.passwordHash);
        if (!ok) return sendJSON(res, 400, { ok: false, error: "Invalid credentials" });

        await createSession(res, found.id);
        return sendJSON(res, 200, { ok: true });


    }

    if (req.method === "POST" && u.pathname === "/api/auth/logout") {
        if (user) await auditLog(user, "auth.logout", {});
        await destroySession(req, res);
        return sendJSON(res, 200, { ok: true });
    }

    if (req.method === "GET" && u.pathname === "/api/me") {
        if (!user) return sendJSON(res, 200, { ok: true, user: null });
        return sendJSON(res, 200, { ok: true, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    }

    // PROPERTIES
    // LIST PROPERTIES (FIX)
    // PROPERTIES
    // LIST PROPERTIES (includes coverUrl for thumbnails)
    if (req.method === "GET" && u.pathname === "/api/properties") {
        if (!requirePerm(user, res, "properties", "read")) return;

        const users = await readJSON(FILES.users, []);
        const owners = await readJSON(FILES.owners, []);
        const props = await readJSON(FILES.properties, []);

        const items = props.map(p => {
            const agent = users.find(u => u.id === p.assignedAgentId) || null;
            const owner = owners.find(o => o.id === p.ownerId) || null;

            const imgs = Array.isArray(p.images) ? p.images : [];
            const cover = imgs.find(im => im && im.isCover) || imgs[0] || null;

            return {
                ...p,
                agentName: agent ? agent.name : "Unassigned",
                ownerName: owner ? owner.name : null,
                coverUrl: cover ? cover.url : null,
            };
        });

        return sendJSON(res, 200, { ok: true, items });
    }

    // GET PROPERTY BY ID (this is what property-view + property-edit need)
    if (req.method === "GET" && u.pathname.startsWith("/api/properties/")) {
        if (!requirePerm(user, res, "properties", "read")) return;

        const parts = u.pathname.split("/");
        const id = parts[3]; // /api/properties/:id

        // avoid treating /api/properties/:id/images as a property id route
        if (!id || id === "images") {
            return sendJSON(res, 404, { ok: false, error: "Not found" });
        }

        const props = await readJSON(FILES.properties, []);
        const owners = await readJSON(FILES.owners, []);
        const leadsAll = await readJSON(FILES.leads, []);
        const showingsAll = await readJSON(FILES.showings, []);

        const item = props.find(p => p.id === id);
        if (!item) return sendJSON(res, 404, { ok: false, error: "Not found" });

        const owner = owners.find(o => o.id === item.ownerId) || null;
        const leads = leadsAll.filter(l => l.propertyId === item.id);
        const showings = showingsAll.filter(s => s.propertyId === item.id);

        return sendJSON(res, 200, { ok: true, item, owner, leads, showings });
    }



    if (req.method === "POST" && u.pathname === "/api/properties") {
        if (!requirePerm(user, res, "properties", "create")) return;

        const bb = Busboy({ headers: req.headers, limits: { files: 15, fileSize: 8 * 1024 * 1024 } });

        const body = {};
        const uploadedImages = [];

        bb.on("field", (name, val) => {
            body[name] = val;
        });

        bb.on("file", async (name, file, info) => {
            if (!isImageFilename(info.filename)) {
                file.resume();
                return;
            }

            const ext = path.extname(info.filename).toLowerCase();
            const tempId = "tmp_" + nanoid(8);
            const outName = `${tempId}_${nanoid(8)}${ext}`;
            const outPath = path.join(DIR_PROP_UPLOADS, outName);

            const write = fs.createWriteStream(outPath);
            await new Promise((res, rej) => {
                file.pipe(write);
                write.on("finish", res);
                write.on("error", rej);
            });

            uploadedImages.push({
                id: "img_" + nanoid(10),
                url: `/uploads/properties/${outName}`,
                alt: "",
                order: uploadedImages.length,
                isCover: uploadedImages.length === 0,
                createdAt: nowISO()
            });
        });

        bb.on("finish", async () => {
            const owners = await readJSON(FILES.owners, []);
            const properties = await readJSON(FILES.properties, []);

            let ownerId = body.ownerId || null;
            if (!ownerId && body.ownerName) {
                const o = {
                    id: "own_" + nanoid(10),
                    name: sanitizeText(body.ownerName, 120),
                    phone: sanitizeText(body.ownerPhone, 60),
                    email: sanitizeText(body.ownerEmail, 120),
                    notes: sanitizeText(body.ownerNotes, 500),
                    createdAt: nowISO()
                };
                owners.unshift(o);
                ownerId = o.id;
                await atomicWriteJSON(FILES.owners, owners);
            }

            const p = {
                id: "p_" + nanoid(10),
                title: sanitizeText(body.title, 200),
                address: sanitizeText(body.address, 240),
                city: sanitizeText(body.city, 80),
                type: sanitizeText(body.type, 40) || "Apartment",
                status: sanitizeText(body.status, 40) || "Active",
                price: toNumber(body.price, 0),
                bedrooms: toNumber(body.bedrooms, null),
                bathrooms: toNumber(body.bathrooms, null),
                area: toNumber(body.area, null),
                floor: sanitizeText(body.floor, 40),
                condition: sanitizeText(body.condition, 60),
                description: sanitizeText(body.description, 5000),
                ownerId,
                assignedAgentId: user.id,
                sources: [],
                images: uploadedImages,
                createdAt: nowISO(),
                updatedAt: nowISO()
            };

            properties.unshift(p);
            await atomicWriteJSON(FILES.properties, properties);
            await auditLog(user, "properties.create_with_images", { propertyId: p.id });

            return sendJSON(res, 200, { ok: true, item: p });
        });

        req.pipe(bb);
        return;
    }



    if (req.method === "PUT" && u.pathname.startsWith("/api/properties/")) {
        if (!requirePerm(user, res, "properties", "update")) return;
        const id = u.pathname.split("/").pop();
        const idx = properties.findIndex(x => x.id === id);
        if (idx < 0) return sendJSON(res, 404, { ok: false, error: "Not found" });

        const buf = await readBody(req);
        const body = safeJSONParse(buf.toString("utf8"), {});

        const p = properties[idx];
        p.title = sanitizeText(body.title, 200) || p.title;
        p.address = sanitizeText(body.address, 240);
        p.city = sanitizeText(body.city, 80);
        p.type = sanitizeText(body.type, 40) || p.type;
        p.status = sanitizeText(body.status, 40) || p.status;
        p.price = toNumber(body.price, p.price);
        p.bedrooms = (body.bedrooms === "" || body.bedrooms === null) ? null : toNumber(body.bedrooms, p.bedrooms);
        p.bathrooms = (body.bathrooms === "" || body.bathrooms === null) ? null : toNumber(body.bathrooms, p.bathrooms);
        p.area = (body.area === "" || body.area === null) ? null : toNumber(body.area, p.area);
        p.floor = sanitizeText(body.floor, 40);
        p.condition = sanitizeText(body.condition, 60);
        p.description = sanitizeText(body.description, 5000);

        // owner selection (existing owner only here)
        if (body.ownerId !== undefined) p.ownerId = String(body.ownerId || "").trim() || null;

        // sources replace
        if (Array.isArray(body.sources)) {
            p.sources = body.sources.map(s => ({
                id: s.id || ("src_" + nanoid(8)),
                label: sanitizeText(s.label, 80),
                url: normalizeUrl(s.url),
                type: sanitizeText(s.type, 30) || "listing",
                addedAt: s.addedAt || nowISO(),
            })).filter(s => s.url);
        }

        // images ordering / cover / alt
        if (Array.isArray(body.images)) {
            // only allow referencing existing urls
            const byUrl = new Map((p.images || []).map(im => [im.url, im]));
            const next = [];
            for (const im of body.images) {
                const url = String(im.url || "");
                const cur = byUrl.get(url);
                if (!cur) continue;
                next.push({
                    ...cur,
                    alt: sanitizeText(im.alt, 120),
                    order: toNumber(im.order, cur.order || 0),
                    isCover: !!im.isCover,
                });
            }
            // ensure single cover
            let hasCover = next.some(x => x.isCover);
            if (!hasCover && next.length) next[0].isCover = true;
            if (hasCover) {
                let first = true;
                for (const x of next) {
                    if (x.isCover) {
                        if (first) first = false;
                        else x.isCover = false;
                    }
                }
            }
            // sort by order
            next.sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
            p.images = next;
        }

        p.updatedAt = nowISO();
        await atomicWriteJSON(FILES.properties, properties);
        await auditLog(user, "properties.update", { propertyId: p.id });

        return sendJSON(res, 200, { ok: true, item: p });
    }

    if (req.method === "DELETE" && u.pathname.startsWith("/api/properties/")) {
        if (!requirePerm(user, res, "properties", "delete")) return;
        const id = u.pathname.split("/").pop();
        const idx = properties.findIndex(x => x.id === id);
        if (idx < 0) return sendJSON(res, 404, { ok: false, error: "Not found" });

        const removed = properties.splice(idx, 1)[0];
        await atomicWriteJSON(FILES.properties, properties);
        await auditLog(user, "properties.delete", { propertyId: removed.id });

        return sendJSON(res, 200, { ok: true });
    }

    // PROPERTY IMAGES UPLOAD
    if (req.method === "POST" && u.pathname.startsWith("/api/properties/") && u.pathname.endsWith("/images")) {
        if (!requirePerm(user, res, "properties", "update")) return;
        const parts = u.pathname.split("/");
        const propertyId = parts[3];
        const p = properties.find(x => x.id === propertyId);
        if (!p) return sendJSON(res, 404, { ok: false, error: "Property not found" });

        const bb = Busboy({ headers: req.headers, limits: { files: 10, fileSize: 8 * 1024 * 1024 } });
        const uploaded = [];
        let hadFile = false;

        bb.on("file", async (name, file, info) => {
            hadFile = true;
            const filename = info.filename || "upload";
            if (!isImageFilename(filename)) {
                file.resume();
                return;
            }

            const ext = path.extname(filename).toLowerCase();
            const outName = `${propertyId}_${nanoid(10)}${ext}`;
            const outPath = path.join(DIR_PROP_UPLOADS, outName);
            const write = fs.createWriteStream(outPath);

            await new Promise((resolve, reject) => {
                file.pipe(write);
                write.on("finish", resolve);
                write.on("error", reject);
                file.on("error", reject);
            });

            const url = `/uploads/properties/${outName}`;
            uploaded.push({
                id: "img_" + nanoid(10),
                url,
                alt: "",
                order: (p.images?.length || 0) + uploaded.length,
                isCover: false,
                createdAt: nowISO(),
            });
        });

        bb.on("finish", async () => {
            if (!hadFile) return sendJSON(res, 400, { ok: false, error: "No files" });
            p.images = (p.images || []).concat(uploaded);
            // ensure a cover
            if (!p.images.some(im => im.isCover) && p.images.length) p.images[0].isCover = true;
            p.updatedAt = nowISO();
            await atomicWriteJSON(FILES.properties, properties);
            await auditLog(user, "properties.images_upload", { propertyId });

            return sendJSON(res, 200, { ok: true, uploaded });
        });

        req.pipe(bb);
        return;
    }

    // OWNERS
    if (req.method === "GET" && u.pathname === "/api/owners") {
        if (!requirePerm(user, res, "owners", "read")) return;
        const owners = await readJSON(FILES.owners, []);
        const q = (u.searchParams.get("q") || "").trim().toLowerCase();
        const items = q
            ? owners.filter(o => (o.name || "").toLowerCase().includes(q) || (o.phone || "").toLowerCase().includes(q))
            : owners;
        return sendJSON(res, 200, { ok: true, items: items.slice(0, 200) });
    }

    if (req.method === "POST" && u.pathname === "/api/owners") {
        if (!requirePerm(user, res, "owners", "create")) return;
        const buf = await readBody(req);
        const body = safeJSONParse(buf.toString("utf8"), {});
        const owners = await readJSON(FILES.owners, []);
        const o = {
            id: "own_" + nanoid(10),
            name: sanitizeText(body.name, 120),
            phone: sanitizeText(body.phone, 60),
            email: sanitizeText(body.email, 120),
            notes: sanitizeText(body.notes, 500),
            createdAt: nowISO(),
        };
        owners.unshift(o);
        await atomicWriteJSON(FILES.owners, owners);
        await auditLog(user, "owners.create", { ownerId: o.id });
        return sendJSON(res, 200, { ok: true, item: o });
    }

    // LEADS
    if (req.method === "GET" && u.pathname === "/api/leads") {
        if (!requirePerm(user, res, "leads", "read")) return;
        const q = (u.searchParams.get("q") || "").trim().toLowerCase();
        const status = (u.searchParams.get("status") || "").trim();
        const items = leads.filter(l => {
            const matchQ = !q || (l.name || "").toLowerCase().includes(q) || (l.phone || "").toLowerCase().includes(q) || (l.email || "").toLowerCase().includes(q);
            const matchS = !status || l.status === status;
            return matchQ && matchS;
        });
        return sendJSON(res, 200, { ok: true, items });
    }

    if (req.method === "GET" && u.pathname.startsWith("/api/leads/")) {
        if (!requirePerm(user, res, "leads", "read")) return;
        const id = u.pathname.split("/").pop();
        const lead = leads.find(l => l.id === id);
        if (!lead) return sendJSON(res, 404, { ok: false, error: "Not found" });
        const leadShowings = showings.filter(s => s.leadId === id);
        const prop = lead.propertyId ? properties.find(p => p.id === lead.propertyId) : null;
        return sendJSON(res, 200, { ok: true, item: lead, showings: leadShowings, property: prop });
    }

    if (req.method === "POST" && u.pathname === "/api/leads") {
        if (!requirePerm(user, res, "leads", "create")) return;
        const buf = await readBody(req);
        const body = safeJSONParse(buf.toString("utf8"), {});
        const l = {
            id: "l_" + nanoid(10),
            name: sanitizeText(body.name, 120),
            phone: sanitizeText(body.phone, 60),
            email: sanitizeText(body.email, 120),
            source: sanitizeText(body.source, 120),
            status: sanitizeText(body.status, 40) || "New",
            budget: sanitizeText(body.budget, 60),
            propertyId: sanitizeText(body.propertyId, 40) || null,
            notes: sanitizeText(body.notes, 2000),
            createdAt: nowISO(),
            updatedAt: nowISO(),
            ownerAgentId: user.id,
        };
        leads.unshift(l);
        await atomicWriteJSON(FILES.leads, leads);
        await auditLog(user, "leads.create", { leadId: l.id });
        return sendJSON(res, 200, { ok: true, item: l });
    }

    if (req.method === "PUT" && u.pathname.startsWith("/api/leads/")) {
        if (!requirePerm(user, res, "leads", "update")) return;
        const id = u.pathname.split("/").pop();
        const idx = leads.findIndex(l => l.id === id);
        if (idx < 0) return sendJSON(res, 404, { ok: false, error: "Not found" });
        const buf = await readBody(req);
        const body = safeJSONParse(buf.toString("utf8"), {});
        const l = leads[idx];
        l.name = sanitizeText(body.name, 120);
        l.phone = sanitizeText(body.phone, 60);
        l.email = sanitizeText(body.email, 120);
        l.source = sanitizeText(body.source, 120);
        l.status = sanitizeText(body.status, 40) || l.status;
        l.budget = sanitizeText(body.budget, 60);
        l.propertyId = sanitizeText(body.propertyId, 40) || null;
        l.notes = sanitizeText(body.notes, 2000);
        l.updatedAt = nowISO();
        await atomicWriteJSON(FILES.leads, leads);
        await auditLog(user, "leads.update", { leadId: id });
        return sendJSON(res, 200, { ok: true, item: l });
    }

    // SHOWINGS
    if (req.method === "GET" && u.pathname === "/api/showings") {
        if (!requirePerm(user, res, "showings", "read")) return;
        const items = showings.slice().sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
        return sendJSON(res, 200, { ok: true, items });
    }

    if (req.method === "POST" && u.pathname === "/api/showings") {
        if (!requirePerm(user, res, "showings", "create")) return;
        const buf = await readBody(req);
        const body = safeJSONParse(buf.toString("utf8"), {});
        const propertyId = String(body.propertyId || "").trim();
        const leadId = String(body.leadId || "").trim();
        const at = String(body.at || "").trim();
        if (!propertyId || !leadId || !at) return sendJSON(res, 400, { ok: false, error: "Missing fields" });

        const s = {
            id: "s_" + nanoid(10),
            propertyId,
            leadId,
            at,
            location: sanitizeText(body.location, 160),
            notes: sanitizeText(body.notes, 1000),
            status: sanitizeText(body.status, 30) || "Scheduled",
            createdAt: nowISO(),
            updatedAt: nowISO(),
            createdBy: user.id,
        };
        showings.unshift(s);
        await atomicWriteJSON(FILES.showings, showings);
        await auditLog(user, "showings.create", { showingId: s.id });
        return sendJSON(res, 200, { ok: true, item: s });
    }

    if (req.method === "PUT" && u.pathname.startsWith("/api/showings/")) {
        if (!requirePerm(user, res, "showings", "update")) return;
        const id = u.pathname.split("/").pop();
        const idx = showings.findIndex(s => s.id === id);
        if (idx < 0) return sendJSON(res, 404, { ok: false, error: "Not found" });

        const buf = await readBody(req);
        const body = safeJSONParse(buf.toString("utf8"), {});
        const s = showings[idx];
        s.at = String(body.at || s.at);
        s.location = sanitizeText(body.location, 160);
        s.notes = sanitizeText(body.notes, 1000);
        s.status = sanitizeText(body.status, 30) || s.status;
        s.updatedAt = nowISO();
        await atomicWriteJSON(FILES.showings, showings);
        await auditLog(user, "showings.update", { showingId: id });
        return sendJSON(res, 200, { ok: true, item: s });
    }

    // NOTIFICATIONS
    if (req.method === "GET" && u.pathname === "/api/notifications") {
        if (!requirePerm(user, res, "notifications", "read")) return;
        const items = await readJSON(FILES.notifications, []);
        return sendJSON(res, 200, { ok: true, items });
    }

    if (req.method === "PUT" && u.pathname.startsWith("/api/notifications/") && u.pathname.endsWith("/read")) {
        if (!requirePerm(user, res, "notifications", "update")) return;
        const parts = u.pathname.split("/");
        const id = parts[3];
        let items = await readJSON(FILES.notifications, []);
        const idx = items.findIndex(n => n.id === id);
        if (idx >= 0) items[idx].isRead = true;
        await atomicWriteJSON(FILES.notifications, items);
        return sendJSON(res, 200, { ok: true });
    }

    // USERS (manager full control; agent read only)
    if (req.method === "GET" && u.pathname === "/api/users") {
        if (!requirePerm(user, res, "users", "read")) return;
        const users = await readJSON(FILES.users, []);
        return sendJSON(res, 200, {
            ok: true,
            items: users.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, isActive: u.isActive, createdAt: u.createdAt }))
        });
    }

    if (req.method === "POST" && u.pathname === "/api/users") {
        if (!requirePerm(user, res, "users", "create")) return;
        const buf = await readBody(req);
        const body = safeJSONParse(buf.toString("utf8"), {});
        const users = await readJSON(FILES.users, []);
        const email = String(body.email || "").trim().toLowerCase();
        if (!email || !String(body.password || "")) return sendJSON(res, 400, { ok: false, error: "Missing fields" });
        if (users.some(u => u.email.toLowerCase() === email)) return sendJSON(res, 400, { ok: false, error: "Email exists" });

        const hash = await bcrypt.hash(String(body.password), 10);
        const nu = {
            id: "u_" + nanoid(10),
            name: sanitizeText(body.name, 120),
            email,
            role: (body.role === "manager" ? "manager" : "agent"),
            passwordHash: hash,
            isActive: true,
            createdAt: nowISO(),
        };
        users.unshift(nu);
        await atomicWriteJSON(FILES.users, users);
        await auditLog(user, "users.create", { userId: nu.id });
        return sendJSON(res, 200, { ok: true });
    }

    // IMPORT LEADS (CSV or XLSX)
    if (req.method === "POST" && u.pathname === "/api/leads/import") {
        if (!requirePerm(user, res, "leads", "import")) return;

        const bb = Busboy({ headers: req.headers, limits: { files: 1, fileSize: 8 * 1024 * 1024 } });
        let fileBuf = null;
        let fileName = "";

        bb.on("file", (name, file, info) => {
            fileName = info.filename || "import";
            const chunks = [];
            file.on("data", c => chunks.push(c));
            file.on("end", () => {
                fileBuf = Buffer.concat(chunks);
            });
        });

        bb.on("finish", async () => {
            if (!fileBuf) return sendJSON(res, 400, { ok: false, error: "No file" });
            const ext = path.extname(fileName).toLowerCase();
            let parsedLeads = [];

            if (ext === ".csv") {
                const text = fileBuf.toString("utf8");
                const rows = parseCSV(text);
                const headers = rows[0].map(h => String(h || "").trim().toLowerCase());
                for (let i = 1; i < rows.length; i++) {
                    const mapped = mapLeadRow(headers, rows[i]);
                    if (mapped.name) parsedLeads.push(mapped);
                }
            } else if (ext === ".xlsx" || ext === ".xls") {
                const wb = XLSX.read(fileBuf, { type: "buffer" });
                const sheet = wb.Sheets[wb.SheetNames[0]];
                const json = XLSX.utils.sheet_to_json(sheet, { defval: "" });
                for (const row of json) {
                    // normalize keys
                    const obj = {};
                    for (const [k, v] of Object.entries(row)) obj[String(k).trim().toLowerCase()] = v;
                    const mapped = mapLeadRow(Object.keys(obj), Object.values(obj));
                    if (mapped.name) parsedLeads.push(mapped);
                }
            } else {
                return sendJSON(res, 400, { ok: false, error: "Unsupported file type. Use CSV or XLSX." });
            }

            const leadsArr = await readJSON(FILES.leads, []);
            let added = 0;
            for (const pl of parsedLeads) {
                const l = {
                    id: "l_" + nanoid(10),
                    ...pl,
                    propertyId: null,
                    createdAt: nowISO(),
                    updatedAt: nowISO(),
                    ownerAgentId: user.id,
                };
                leadsArr.unshift(l);
                added++;
            }
            await atomicWriteJSON(FILES.leads, leadsArr);
            await auditLog(user, "leads.import", { added });

            return sendJSON(res, 200, { ok: true, added });
        });

        req.pipe(bb);
        return;
    }

    // ANALYTICS (simple "AI analytics" placeholder with smart summaries)
    if (req.method === "GET" && u.pathname === "/api/analytics") {
        if (!requirePerm(user, res, "properties", "read")) return;
        const users = await readJSON(FILES.users, []);
        const owners = await readJSON(FILES.owners, []);

        const byAgent = new Map();
        for (const p of properties) {
            byAgent.set(p.assignedAgentId, (byAgent.get(p.assignedAgentId) || 0) + 1);
        }

        const leadsByStatus = {};
        for (const l of leads) leadsByStatus[l.status] = (leadsByStatus[l.status] || 0) + 1;

        const upcoming = showings.filter(s => s.status === "Scheduled").slice(0, 50).sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
        const openNotifs = (await readJSON(FILES.notifications, [])).filter(n => !n.isRead).length;

        // "AI-style" insights: deterministic, safe for demo
        const insights = [];
        if ((leadsByStatus["New"] || 0) > 10) insights.push("Many leads are still New. Focus on first contact and schedule showings faster.");
        if (upcoming.length === 0) insights.push("No upcoming showings. Convert active leads into scheduled appointments.");
        if (openNotifs > 0) insights.push(`You have ${openNotifs} unread notifications. Review showings that are close.`);
        if (properties.length > 0 && owners.length === 0) insights.push("You have properties but no saved owners. Add owner contact info for better control.");

        return sendJSON(res, 200, {
            ok: true,
            metrics: {
                propertiesTotal: properties.length,
                leadsTotal: leads.length,
                showingsTotal: showings.length,
                unreadNotifications: openNotifs,
            },
            leadsByStatus,
            agentLeaderboard: users
                .filter(u => u.role === "agent" || u.role === "manager")
                .map(u => ({ id: u.id, name: u.name, count: byAgent.get(u.id) || 0 }))
                .sort((a, b) => b.count - a.count),
            insights,
        });
    }

    return sendJSON(res, 404, { ok: false, error: "Unknown API route" });
}

async function handler(req, res) {
    try {
        // API FIRST
        if (req.url.startsWith("/api/")) {
            const user = await getUserFromSession(req);
            return await routeAPI(req, res, user);
        }

        const user = await getUserFromSession(req);
        const pathOnly = req.url.split("?")[0];

        // 🚨 FIX: logged-in users cannot see login page
        if (user && pathOnly === "/login.html") {
            res.writeHead(302, { Location: "/dashboard.html" });
            return res.end();
        }

        const internalPages = [
            "/dashboard.html",
            "/properties.html",
            "/property-new.html",
            "/property-view.html",
            "/property-edit.html",
            "/owners.html",
            "/leads.html",
            "/lead-view.html",
            "/showings.html",
            "/notifications.html",
            "/import-leads.html",
            "/users.html",
        ];

        // 🚨 DEMO MODE BYPASS (TEMPORARY)
        if (internalPages.includes(pathOnly)) {
            return await serveStatic(req, res);
        }


        return await serveStatic(req, res);
    } catch (e) {
        console.error(e);
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "Server error" }));
    }
}



(async () => {
    await ensureDirs();
    await seedIfEmpty();
    http.createServer(handler).listen(PORT, () => {
        console.log(`CRM running: http://localhost:${PORT}`);
    });
})();