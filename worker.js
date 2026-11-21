const J=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{"content-type":"application/json"}});
const bad=(m,s=400)=>J({error:m},s);
const TY=["video","short","music","podcast","photo","text"],NAME=/^[a-z0-9.]{3,20}$/,ID=/^[a-f0-9]{16}$/,MAX=100*1048576;
const SCHEMA=[
"CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY,salt TEXT,h TEXT,ch TEXT)",
"CREATE TABLE IF NOT EXISTS sessions(t TEXT PRIMARY KEY,name TEXT)",
"CREATE TABLE IF NOT EXISTS channels(handle TEXT PRIMARY KEY,title TEXT,about TEXT,owner TEXT,created INT)",
"CREATE TABLE IF NOT EXISTS items(id TEXT PRIMARY KEY,type TEXT,title TEXT,descr TEXT,owner TEXT,ch TEXT,mime TEXT,size INT,created INT)",
"CREATE TABLE IF NOT EXISTS likes(id TEXT,name TEXT,PRIMARY KEY(id,name))",
"CREATE TABLE IF NOT EXISTS subs(name TEXT,ch TEXT,PRIMARY KEY(name,ch))"];
const IQ='SELECT i.id,i.type,i.title,i.descr AS "desc",i.owner,i.ch,i.mime,i.size,i.created,(SELECT COUNT(*) FROM likes WHERE id=i.id) AS likes FROM items i';
const CQ="SELECT c.*,(SELECT COUNT(*) FROM subs WHERE ch=c.handle) AS subs FROM channels c WHERE handle=?";
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const rnd=n=>hex(crypto.getRandomValues(new Uint8Array(n)));
async function pbk(pw,salt){const k=await crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveBits"]);return hex(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:new TextEncoder().encode(salt),iterations:100000},k,256))}
const same=(a,b)=>{if(a.length!==b.length)return false;let r=0;for(let i=0;i<a.length;i++)r|=a.charCodeAt(i)^b.charCodeAt(i);return r===0};
let ready;
export default{async fetch(req,env){
const url=new URL(req.url);if(!url.pathname.startsWith("/api/"))return env.ASSETS.fetch(req);
ready??=env.DB.batch(SCHEMA.map(s=>env.DB.prepare(s))).catch(e=>{ready=null;throw e});await ready;
const db=env.DB,[a,b]=url.pathname.slice(5).split("/"),m=req.method,sp=url.searchParams;
const body=()=>req.json().catch(()=>({})),one=(q,...p)=>db.prepare(q).bind(...p).first(),run=(q,...p)=>db.prepare(q).bind(...p).run(),all=async(q,...p)=>(await db.prepare(q).bind(...p).all()).results;
const tk=(req.headers.get("authorization")||"").slice(7);
const me=/^[a-f0-9]{48}$/.test(tk)?(await one("SELECT name FROM sessions WHERE t=?",tk))?.name:null;
const sess=async n=>{const t=rnd(24);await run("INSERT INTO sessions VALUES(?,?)",t,n);return J({token:t,name:n})};
const subbed=async h=>me?!!(await one("SELECT 1 x FROM subs WHERE name=? AND ch=?",me,h)):false;
if(a==="signup"&&m==="POST"){const d=await body(),n=String(d.name||"").toLowerCase().replace(/@fds\.com$/,""),pw=d.password;
 if(!NAME.test(n))return bad('Username: 3-20 letters, numbers or dots. No "_" allowed.');
 if(typeof pw!=="string"||pw.length<6||pw.includes("_"))return bad('Password: at least 6 characters, no "_".');
 if(await one("SELECT 1 x FROM users WHERE name=?",n))return bad("That FDS account already exists.");
 const salt=rnd(16);await run("INSERT INTO users VALUES(?,?,?,NULL)",n,salt,await pbk(pw,salt));return sess(n)}
if(a==="login"&&m==="POST"){const d=await body(),n=String(d.name||"").toLowerCase().replace(/@fds\.com$/,""),u=NAME.test(n)&&await one("SELECT * FROM users WHERE name=?",n);
 if(!u||typeof d.password!=="string"||!same(await pbk(d.password,u.salt),u.h))return bad("Wrong username or password.",401);return sess(n)}
if(a==="feed"&&m==="GET"){const w=[],p=[],ty=sp.get("type"),q=sp.get("q");
 if(ty){w.push("i.type=?");p.push(ty)}if(sp.get("ch")){w.push("i.ch=?");p.push(sp.get("ch"))}
 if(q){w.push("(i.title LIKE ? OR i.descr LIKE ? OR i.ch LIKE ?)");const x=`%${q}%`;p.push(x,x,x)}
 if(sp.get("mine")){if(!me)return J([]);w.push("i.owner=?");p.push(me)}
 if(sp.get("subs")){if(!me)return J([]);w.push("i.ch IN (SELECT ch FROM subs WHERE name=?)");p.push(me)}
 return J(await all(`${IQ}${w.length?" WHERE "+w.join(" AND "):""} ORDER BY i.created DESC LIMIT 60`,...p))}
if(a==="item"&&b&&m==="GET"){const i=ID.test(b)&&await one(IQ+" WHERE i.id=?",b);if(!i)return bad("Not found",404);
 return J({item:i,liked:!!me&&!!(await one("SELECT 1 x FROM likes WHERE id=? AND name=?",b,me)),subbed:await subbed(i.ch)})}
if(a==="media"&&b&&m==="GET"){if(!ID.test(b))return bad("Not found",404);const o=await env.MEDIA.get("m/"+b);if(!o)return bad("Not found",404);
 const h=new Headers();o.writeHttpMetadata(h);h.set("content-length",o.size);h.set("cache-control","private, max-age=3600");return new Response(o.body,{headers:h})}
if(a==="channel"&&b&&m==="GET"){const ch=NAME.test(b)&&await one(CQ,b);if(!ch)return bad("Not found",404);return J({ch,subbed:await subbed(b),items:await all(IQ+" WHERE i.ch=? ORDER BY i.created DESC",b)})}
if(!me)return bad("Sign in first",401);
const u=await one("SELECT * FROM users WHERE name=?",me);
if(a==="me"&&m==="GET")return J({name:me,channel:u.ch?await one(CQ,u.ch):null,subs:(await all("SELECT ch FROM subs WHERE name=?",me)).map(x=>x.ch)});
if(a==="logout"&&m==="POST"){await run("DELETE FROM sessions WHERE t=?",tk);return J({ok:1})}
if(a==="channel"&&m==="POST"){const d=await body(),h=String(d.handle||"").toLowerCase();
 if(u.ch)return bad("One account can only have one channel.");if(!NAME.test(h))return bad("Handle: 3-20 letters, numbers or dots.");
 if(await one("SELECT 1 x FROM channels WHERE handle=?",h))return bad("That channel handle is taken.");
 await db.batch([db.prepare("INSERT INTO channels VALUES(?,?,?,?,?)").bind(h,String(d.title||h).slice(0,40),String(d.about||"").slice(0,300),me,Date.now()),db.prepare("UPDATE users SET ch=? WHERE name=?").bind(h,me)]);return J(await one(CQ,h))}
if((a==="media"||a==="item")&&m!=="DELETE"&&!u.ch)return bad("Create your channel first (Account page).");
if(a==="media"&&m==="PUT"){if(!ID.test(b))return bad("Bad id");if(+req.headers.get("content-length")>MAX||!req.body)return bad("Max 100 MB",413);
 if(await env.MEDIA.head("m/"+b))return bad("Exists",409);
 await env.MEDIA.put("m/"+b,req.body,{httpMetadata:{contentType:req.headers.get("content-type")||"application/octet-stream"},customMetadata:{owner:me}});return J({ok:1})}
if(a==="item"&&m==="POST"){const d=await body(),t=String(d.title||"").trim().slice(0,100);if(!TY.includes(d.type)||!t)return bad("Bad post");
 let id=d.id;if(d.type==="text")id=rnd(8);else{const h=ID.test(id)&&await env.MEDIA.head("m/"+id);if(!h||h.customMetadata?.owner!==me)return bad("Upload incomplete");if(await one("SELECT 1 x FROM items WHERE id=?",id))return bad("Exists")}
 await run("INSERT INTO items VALUES(?,?,?,?,?,?,?,?,?)",id,d.type,t,String(d.desc||"").slice(0,2000),me,u.ch,String(d.mime||"").slice(0,60),+d.size||0,Date.now());return J(await one(IQ+" WHERE i.id=?",id))}
if(a==="like"&&m==="POST"){if(!ID.test(b)||!(await one("SELECT 1 x FROM items WHERE id=?",b)))return bad("Not found",404);
 const had=await one("SELECT 1 x FROM likes WHERE id=? AND name=?",b,me);await run(had?"DELETE FROM likes WHERE id=? AND name=?":"INSERT INTO likes VALUES(?,?)",b,me);
 return J({liked:!had,likes:(await one("SELECT COUNT(*) n FROM likes WHERE id=?",b)).n})}
if(a==="sub"&&m==="POST"){const ch=NAME.test(b)&&await one(CQ,b);if(!ch)return bad("Not found",404);if(ch.owner===me)return bad("You can't subscribe to your own channel.");
 const had=await subbed(b);await run(had?"DELETE FROM subs WHERE name=? AND ch=?":"INSERT INTO subs VALUES(?,?)",me,b);return J({subbed:!had})}
if(a==="item"&&m==="DELETE"){const i=ID.test(b)&&await one("SELECT * FROM items WHERE id=?",b);if(!i||i.owner!==me)return bad("Forbidden",403);
 if(i.type!=="text")await env.MEDIA.delete("m/"+b);await db.batch([db.prepare("DELETE FROM likes WHERE id=?").bind(b),db.prepare("DELETE FROM items WHERE id=?").bind(b)]);return J({ok:1})}
return bad("Not found",404)}};
