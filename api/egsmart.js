
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { z } = require("zod");
const { connect, ObjectId } = require("./_db");

function customAlphabet(chars, length) {
  return () => Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
}

const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "123";
const nano = customAlphabet("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 10);

function ok(res, payload){ res.setHeader("Content-Type","application/json"); return res.status(200).end(JSON.stringify(payload)); }
function bad(res, code, payload){ res.setHeader("Content-Type","application/json"); return res.status(code).end(JSON.stringify(payload)); }

async function ensureAdminUser(db){
  const users = db.collection("users");
  const admin = await users.findOne({ user: ADMIN_USER });
  if (!admin) {
    const hash = await bcrypt.hash(ADMIN_PASS, 10);
    await users.insertOne({ user: ADMIN_USER, pass: hash, role: "admin", createdAt: new Date() });
  }
}

function getAuth(req){
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer (.+)$/);
  if (!m) return null;
  try { return jwt.verify(m[1], JWT_SECRET); } catch(e){ return null; }
}

module.exports = async (req, res) => {
  if (req.method !== "POST") return bad(res, 405, { error: "method_not_allowed" });
  const { action, data } = req.body || {};
  const { db } = await connect();
  await ensureAdminUser(db);

  if (action === "login") {
    const { user, pass } = data || {};
    if (!user || !pass) return ok(res, { error: "invalid" });
    const u = await db.collection("users").findOne({ user });
    if (!u) return ok(res, { error: "invalid" });
    const match = await bcrypt.compare(pass, u.pass);
    if (!match) return ok(res, { error: "invalid" });
    const token = jwt.sign({ uid: u._id.toString(), user: u.user, role: u.role }, JWT_SECRET, { expiresIn: "12h" });
    return ok(res, { token });
  }

  const auth = getAuth(req);
  if (!auth) return bad(res, 401, { error: "unauthorized" });

  if (action === "me") return ok(res, { user: auth.user, role: auth.role });

  if (action === "getCafes") {
    const rows = await db.collection("cafes").find({}).sort({ createdAt: -1 }).toArray();
    return ok(res, rows);
  }
  if (action === "addCafe") {
    const Cafe = z.object({
      name: z.string().min(1),
      address: z.string().optional().nullable(),
      owner: z.string().optional().nullable(),
      phone: z.string().optional().nullable(),
      landline: z.string().optional().nullable(),
    });
    const parsed = Cafe.safeParse(data || {});
    if (!parsed.success) return ok(res, { error: "invalid" });
    const doc = { ...parsed.data, status: "active", createdAt: new Date() };
    const r = await db.collection("cafes").insertOne(doc);
    return ok(res, { insertedId: r.insertedId });
  }
  if (action === "toggleCafe") {
    const { id, status } = data || {};
    await db.collection("cafes").updateOne({ _id: new ObjectId(id) }, { $set: { status } });
    return ok(res, { ok: true });
  }
  if (action === "installCafe") {
    const { id } = data || {};
    const cafe = await db.collection("cafes").findOne({ _id: new ObjectId(id) });
    if (!cafe) return ok(res, { error: "not_found" });
    let token = cafe.installToken;
    if (!token) {
      token = nano();
      await db.collection("cafes").updateOne({ _id: cafe._id }, { $set: { installToken: token } });
    }
    const mikrotik = 
`# Configure MikroTik hotspot client pointing to your controller
/ip hotspot profile set [ find default=yes ] login-by=http-chap name=smartwifi
/tool fetch url="https://your-domain/api/login?token=${token}" keep-result=no`;
    const openwrt = 
`# OpenWrt captive portal hook (example)
uci set firewall.smartwifi=rule
uci set firewall.smartwifi.src='lan'
uci set firewall.smartwifi.dest_port='80'
uci set firewall.smartwifi.proto='tcp'
uci commit firewall
/etc/init.d/firewall restart
# Controller URL token=${token}`;
    return ok(res, { mikrotik, openwrt, token });
  }

  if (action === "getPlans") {
    const rows = await db.collection("plans").find({}).sort({ createdAt:-1 }).toArray();
    return ok(res, rows);
  }
  if (action === "addPlan") {
    const Plan = z.object({
      name: z.string().min(1),
      price: z.number().optional().default(0),
      quotaMB: z.number().optional().default(0),
      uploadMbps: z.number().optional().default(0),
      downloadMbps: z.number().optional().default(0),
      duration: z.object({ value: z.number(), unit: z.enum(["hours","days","months"]) })
    });
    const parsed = Plan.safeParse(data || {});
    if (!parsed.success) return ok(res, { error: "invalid" });
    const r = await db.collection("plans").insertOne({ ...parsed.data, createdAt: new Date() });
    return ok(res, { insertedId: r.insertedId });
  }
  if (action === "deletePlan") {
    const { id } = data || {};
    await db.collection("plans").deleteOne({ _id: new ObjectId(id) });
    return ok(res, { ok:true });
  }

  if (action === "generateCards") {
    const Schema = z.object({
      cafeId: z.string().min(1),
      count: z.number().min(1).max(5000),
      length: z.number().min(4).max(20),
      prefix: z.string().optional().default(""),
      planId: z.string().min(1)
    });
    const parsed = Schema.safeParse(data || {});
    if (!parsed.success) return ok(res, { error: "invalid" });
    const { cafeId, count, length, prefix, planId } = parsed.data;
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const gen = customAlphabet(alphabet, length);
    const now = new Date();
    const docs = [];
    for (let i=0;i<count;i++){
      const code = (prefix ? (prefix + "-") : "") + gen();
      docs.push({ code, cafeId, planId, status: "new", createdAt: now });
    }
    if (docs.length) await db.collection("cards").insertMany(docs);
    return ok(res, { inserted: docs.map(d => d.code), preview: docs.slice(0,20) });
  }
  if (action === "searchCards") {
    const { cafeId, code, limit } = data || {};
    const q = {};
    if (cafeId) q.cafeId = cafeId;
    if (code) q.code = code;
    const rows = await db.collection("cards").find(q).sort({ createdAt: -1 }).limit(Math.min(Number(limit||100), 200)).toArray();
    return ok(res, rows);
  }

  if (action === "addDesign") {
    const Schema = z.object({
      cafeId: z.string().min(1),
      name: z.string().min(1),
      template: z.string().min(1)
    });
    const parsed = Schema.safeParse(data || {});
    if (!parsed.success) return ok(res, { error: "invalid" });
    const cafe = await db.collection("cafes").findOne({ _id: new ObjectId(parsed.data.cafeId) }).catch(()=>null);
    const doc = { ...parsed.data, cafeName: cafe?.name || null, createdAt: new Date() };
    const r = await db.collection("designs").insertOne(doc);
    return ok(res, { insertedId: r.insertedId });
  }
  if (action === "getDesigns") {
    const rows = await db.collection("designs").find({}).sort({ createdAt:-1 }).toArray();
    return ok(res, rows);
  }
  if (action === "getDesign") {
    const { id } = data || {};
    const d = await db.collection("designs").findOne({ _id: new ObjectId(id) });
    return ok(res, d || null);
  }

  return ok(res, { error: "unknown_action" });
};
