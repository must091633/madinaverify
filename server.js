import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const db = new Database("madinaverify.db");
const PORT = Number(process.env.PORT || 4000);
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:5500";
const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE_ME";
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true";

app.use(helmet());
app.use(cors({origin: FRONTEND_ORIGIN, credentials:true}));
app.use(express.json({limit:"100kb"}));
app.use(cookieParser());
app.use(rateLimit({windowMs:15*60*1000,max:300,standardHeaders:true,legacyHeaders:false}));

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user',
 balance INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
 id TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 name TEXT NOT NULL,
 prefix TEXT NOT NULL,
 key_hash TEXT NOT NULL,
 created_at TEXT NOT NULL,
 revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS activity(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 type TEXT NOT NULL,
 status TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 action TEXT NOT NULL,
 actor TEXT NOT NULL,
 created_at TEXT NOT NULL
);
`);

const now = () => new Date().toISOString();
const hash = s => crypto.createHash("sha256").update(s).digest("hex");

function createSession(userId){
  const id = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessions(id,user_id,expires_at) VALUES(?,?,?)").run(id,userId,Date.now()+7*86400000);
  return id;
}
function getUser(req){
  const sid=req.cookies.mv_session;
  if(!sid) return null;
  const row=db.prepare("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?").get(sid,Date.now());
  return row || null;
}
function auth(req,res,next){
  const user=getUser(req);
  if(!user) return res.status(401).json({error:"unauthorized"});
  req.user=user; next();
}
function admin(req,res,next){
  if(req.user?.role!=="admin") return res.status(403).json({error:"forbidden"});
  next();
}
function cookie(res,sid){
  res.cookie("mv_session",sid,{httpOnly:true,secure:COOKIE_SECURE,sameSite:"lax",maxAge:7*86400000,path:"/"});
}

if(process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD){
  const existing=db.prepare("SELECT id FROM users WHERE email=?").get(process.env.ADMIN_EMAIL);
  if(!existing){
    const passwordHash=bcrypt.hashSync(process.env.ADMIN_PASSWORD,12);
    db.prepare("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)")
      .run("Madinaverify Admin",process.env.ADMIN_EMAIL,passwordHash,"admin",now());
  }
}

app.get("/api/v1/health",(req,res)=>res.json({status:"ok",service:"madinaverify-api",timestamp:now()}));
app.get("/api/health",(req,res)=>res.json({status:"ok",service:"madinaverify-api",timestamp:now()}));

app.post("/api/auth/register", async (req,res)=>{
  const {name,email,password}=req.body||{};
  if(!name||!email||!password) return res.status(400).json({error:"name, email and password are required"});
  if(password.length<10) return res.status(400).json({error:"password must be at least 10 characters"});
  const normalized=email.trim().toLowerCase();
  if(db.prepare("SELECT id FROM users WHERE email=?").get(normalized)) return res.status(409).json({error:"email already registered"});
  const passwordHash=await bcrypt.hash(password,12);
  const result=db.prepare("INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)").run(name.trim(),normalized,passwordHash,now());
  const sid=createSession(result.lastInsertRowid); cookie(res,sid);
  res.status(201).json({user:{id:result.lastInsertRowid,name:name.trim(),email:normalized,role:"user"}});
});

app.post("/api/auth/login", async (req,res)=>{
  const {email,password}=req.body||{};
  const user=db.prepare("SELECT * FROM users WHERE email=?").get((email||"").trim().toLowerCase());
  if(!user || !(await bcrypt.compare(password||"",user.password_hash))) return res.status(401).json({error:"invalid credentials"});
  const sid=createSession(user.id); cookie(res,sid);
  db.prepare("INSERT INTO audit_logs(user_id,action,actor,created_at) VALUES(?,?,?,?)").run(user.id,"login",user.email,now());
  res.json({user:{id:user.id,name:user.name,email:user.email,role:user.role}});
});

app.post("/api/auth/logout",auth,(req,res)=>{
  db.prepare("DELETE FROM sessions WHERE id=?").run(req.cookies.mv_session);
  res.clearCookie("mv_session",{httpOnly:true,secure:COOKIE_SECURE,sameSite:"lax",path:"/"});
  res.json({ok:true});
});

app.get("/api/me",auth,(req,res)=>{
  const keys=db.prepare("SELECT id,name,prefix,created_at createdAt FROM api_keys WHERE user_id=? AND revoked_at IS NULL ORDER BY id DESC").all(req.user.id);
  const activity=db.prepare("SELECT type,status,created_at createdAt FROM activity WHERE user_id=? ORDER BY id DESC LIMIT 20").all(req.user.id);
  const total=db.prepare("SELECT COUNT(*) c FROM activity WHERE user_id=?").get(req.user.id).c;
  const successful=db.prepare("SELECT COUNT(*) c FROM activity WHERE user_id=? AND status='success'").get(req.user.id).c;
  res.json({user:{id:req.user.id,name:req.user.name,email:req.user.email,role:req.user.role},stats:{requests:total,successRate:total?Math.round(successful/total*100):0,keys:keys.length,balance:req.user.balance},keys,activity});
});

app.post("/api/keys",auth,(req,res)=>{
  const name=(req.body?.name||"API key").trim().slice(0,80);
  const raw="mv_live_"+crypto.randomBytes(28).toString("base64url");
  const prefix=raw.slice(0,14);
  db.prepare("INSERT INTO api_keys(user_id,name,prefix,key_hash,created_at) VALUES(?,?,?,?,?)").run(req.user.id,name,prefix,hash(raw),now());
  db.prepare("INSERT INTO audit_logs(user_id,action,actor,created_at) VALUES(?,?,?,?)").run(req.user.id,"api_key_created",req.user.email,now());
  res.status(201).json({apiKey:raw,prefix,name});
});

function apiKeyAuth(req,res,next){
  const header=req.get("authorization")||"";
  const token=header.startsWith("Bearer ")?header.slice(7):"";
  if(!token) return res.status(401).json({error:"missing_api_key"});
  const key=db.prepare("SELECT * FROM api_keys WHERE key_hash=? AND revoked_at IS NULL").get(hash(token));
  if(!key) return res.status(401).json({error:"invalid_api_key"});
  req.apiUser=db.prepare("SELECT * FROM users WHERE id=?").get(key.user_id);
  req.apiKey=key; next();
}

app.get("/api/v1/health",apiKeyAuth,(req,res)=>res.json({status:"ok",authenticated:true,userId:req.apiUser.id}));

function verification(type){
  return (req,res)=>{
    if(type!=="cac" && req.body?.consent!==true) return res.status(400).json({error:"explicit consent is required"});
    const id=crypto.randomUUID();
    db.prepare("INSERT INTO activity(user_id,type,status,created_at) VALUES(?,?,?,?)").run(req.apiUser.id,type.toUpperCase(), "accepted", now());
    // Provider integration must be implemented here using an authorized service.
    res.status(202).json({requestId:id,status:"accepted",message:"Provider adapter not configured. Connect your authorized verification provider on the backend before production use."});
  };
}
app.post("/api/v1/verification/nin",apiKeyAuth,verification("nin"));
app.post("/api/v1/verification/bvn",apiKeyAuth,verification("bvn"));
app.post("/api/v1/verification/cac",apiKeyAuth,verification("cac"));

app.get("/api/admin/overview",auth,admin,(req,res)=>{
  const users=db.prepare("SELECT id,name,email,role,created_at createdAt FROM users ORDER BY id DESC LIMIT 100").all();
  const logs=db.prepare("SELECT action,actor,created_at createdAt FROM audit_logs ORDER BY id DESC LIMIT 100").all();
  const stats={
    users:db.prepare("SELECT COUNT(*) c FROM users").get().c,
    requests:db.prepare("SELECT COUNT(*) c FROM activity").get().c,
    verifications:db.prepare("SELECT COUNT(*) c FROM activity WHERE type IN ('NIN','BVN','CAC')").get().c
  };
  res.json({admin:{name:req.user.name,email:req.user.email},stats,users,logs});
});

app.use((req,res)=>res.status(404).json({error:"not_found"}));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:"internal_server_error"});});

app.listen(PORT,()=>console.log(`Madinaverify API listening on :${PORT}`));
