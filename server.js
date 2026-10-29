// Oakheart game server
// - serves the game (index.html)
// - accounts: sign up / log in, passwords stored as salted scrypt hashes
// - saves: each account's progress kept in a Postgres database (DATABASE_URL), or a local file when testing
// - admin page (/admin): look up players and reset forgotten passwords, using the ADMIN_KEY you set on Render
// - online play: everyone's "presence" (where they are, what they wear, trades, duels, monsters...) is shared
//   between players over a WebSocket, the same way the game shares it when it runs inside Claude
'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const {WebSocketServer}=require('ws');

const PORT=process.env.PORT||3000;
// The key that signs log-ins: SESSION_SECRET if you set one, otherwise one made from the (already private)
// database address, so players stay logged in across restarts without any extra setting.
const SECRET=process.env.SESSION_SECRET||(process.env.DATABASE_URL?crypto.createHash('sha256').update('oakheart|'+process.env.DATABASE_URL).digest('hex'):'');
if(!SECRET)console.warn('Note: no database is set, so log-ins reset whenever the server restarts.');
const KEY=SECRET||crypto.randomBytes(32).toString('hex');
const GAME=path.join(__dirname,'index.html');
// The admin page's password: set ADMIN_KEY in Render > Environment. Without it the admin page is switched off.
const ADMIN_KEY=String(process.env.ADMIN_KEY||'');
if(ADMIN_KEY&&ADMIN_KEY.length<12)console.warn('Note: ADMIN_KEY is short. Use at least 12 characters so nobody can guess it.');

// ---------- storage: Postgres when DATABASE_URL is set, otherwise a JSON file (for testing on your computer)
let db;
async function openStore(){
  if(process.env.DATABASE_URL){
    const {Pool}=require('pg');
    const url=process.env.DATABASE_URL,local=/localhost|127\.0\.0\.1/.test(url);
    const pool=new Pool({connectionString:url,ssl:local||process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:5});
    await pool.query(`CREATE TABLE IF NOT EXISTS accounts(username TEXT PRIMARY KEY, display TEXT NOT NULL, hash TEXT NOT NULL, salt TEXT NOT NULL, created TIMESTAMPTZ DEFAULT now());
      CREATE TABLE IF NOT EXISTS saves(username TEXT PRIMARY KEY REFERENCES accounts(username) ON DELETE CASCADE, data JSONB, updated TIMESTAMPTZ DEFAULT now());
      ALTER TABLE accounts ADD COLUMN IF NOT EXISTS reset_at BIGINT DEFAULT 0;`);
    console.log('Using the Postgres database for accounts and saves.');
    return {
      async getAccount(u){const r=await pool.query('SELECT username,display,hash,salt,reset_at,created FROM accounts WHERE username=$1',[u]);const a=r.rows[0];if(a)a.reset_at=+a.reset_at||0;return a||null;},
      async setPassword(u,hash,salt){await pool.query('UPDATE accounts SET hash=$2,salt=$3,reset_at=$4 WHERE username=$1',[u,hash,salt,Date.now()]);},
      async listAccounts(q){const r=await pool.query("SELECT a.username,a.display,a.created,s.updated FROM accounts a LEFT JOIN saves s ON s.username=a.username WHERE a.username LIKE $1 ORDER BY COALESCE(s.updated,a.created) DESC LIMIT 200",['%'+q.replace(/[%_\\]/g,'\\$&')+'%']);const n=await pool.query('SELECT count(*)::int AS n FROM accounts');return {total:n.rows[0].n,rows:r.rows};},
      async addAccount(a){await pool.query('INSERT INTO accounts(username,display,hash,salt) VALUES($1,$2,$3,$4)',[a.username,a.display,a.hash,a.salt]);},
      async getSave(u){const r=await pool.query('SELECT data FROM saves WHERE username=$1',[u]);return r.rows[0]?r.rows[0].data:null;},
      async putSave(u,d){await pool.query('INSERT INTO saves(username,data,updated) VALUES($1,$2,now()) ON CONFLICT(username) DO UPDATE SET data=EXCLUDED.data, updated=now()',[u,d]);}
    };
  }
  if(process.env.RENDER||process.env.NODE_ENV==='production'){   // online, a temporary file would lose every account: stop with a clear message instead
    throw new Error('DATABASE_URL is not set. Add your Neon connection string in Render > Environment (Key: DATABASE_URL), then deploy again.');
  }
  const file=path.join(__dirname,'data.json');
  let mem={accounts:{},saves:{}};
  try{mem=JSON.parse(fs.readFileSync(file,'utf8'));}catch(e){}
  let t=null;const flush=()=>{clearTimeout(t);t=setTimeout(()=>fs.writeFile(file,JSON.stringify(mem),()=>{}),500);};
  console.warn('No DATABASE_URL: saving to data.json (fine for testing; on Render this file is wiped on every restart).');
  return {
    async getAccount(u){return mem.accounts[u]||null;},
    async addAccount(a){mem.accounts[a.username]=Object.assign({created:new Date().toISOString()},a);flush();},
    async setPassword(u,hash,salt){const a=mem.accounts[u];if(a){a.hash=hash;a.salt=salt;a.reset_at=Date.now();flush();}},
    async listAccounts(q){const rows=Object.values(mem.accounts).filter(a=>a.username.includes(q)).map(a=>({username:a.username,display:a.display,created:a.created||null,updated:mem.savedAt&&mem.savedAt[a.username]||null}));return {total:Object.keys(mem.accounts).length,rows:rows.slice(0,200)};},
    async getSave(u){return mem.saves[u]||null;},
    async putSave(u,d){mem.saves[u]=d;(mem.savedAt=mem.savedAt||{})[u]=new Date().toISOString();flush();}
  };
}

// ---------- passwords and log-in tokens
const scrypt=(pw,salt)=>new Promise((res,rej)=>crypto.scrypt(pw,salt,64,(e,k)=>e?rej(e):res(k.toString('hex'))));
const sign=s=>crypto.createHmac('sha256',KEY).update(s).digest('base64url');
const DAYS30=30*24*3600*1000;
function makeToken(u){const body=Buffer.from(u+'|'+(Date.now()+DAYS30)).toString('base64url');return body+'.'+sign(body);}
function readToken(t){
  if(typeof t!=='string'||t.length>400)return null;
  const [body,sig]=t.split('.');if(!body||!sig)return null;
  const good=sign(body);if(good.length!==sig.length||!crypto.timingSafeEqual(Buffer.from(good),Buffer.from(sig)))return null;
  const [u,exp]=Buffer.from(body,'base64url').toString().split('|');
  return +exp>Date.now()?u:null;
}
const tokenMade=t=>{try{return +Buffer.from(String(t).split('.')[0],'base64url').toString().split('|')[1]-DAYS30;}catch(e){return 0;}};
// a log-in only counts if it was made after the account's last password reset
async function liveUser(t){
  const u=readToken(t);if(!u)return null;
  const a=await db.getAccount(u);if(!a)return null;
  return tokenMade(t)>(a.reset_at||0)?u:null;
}
const userKey=n=>String(n||'').trim().toLowerCase();
const goodName=n=>/^[A-Za-z0-9_ ]{3,14}$/.test(n)&&n.trim()===n&&!/  /.test(n);

// a few tries per minute per address, to slow down password guessing
const tries=new Map();
function tooMany(ip){const now=Date.now(),a=(tries.get(ip)||[]).filter(t=>now-t<60000);a.push(now);tries.set(ip,a);return a.length>10;}


// ---------- save checks (anti-cheat, level 1)
// Every save is compared with the account's last accepted save. XP and wealth (coins plus what your items sell for)
// can only grow as fast as a person could really earn them; anything faster is refused and the old save is kept.
// Trades and duel winnings seen by the server count as allowed gains.
const ITEM_RE=new RegExp("^(kn0|ub[0-4]|bs|fx|ar[0-9]|at[0-4]|bw[0-4]|cf[0-7]|sd[0-9]|vg[0-9]|rg[0-5]|cl0|cs0|spade|pk[0-2]|tr[0-4]|lt[0-4]|ud[0-4]|dh[0-4]|pf[0-5]|gm[0-4]|nk[0-4]|fth|rch|rbf|rrm|rwm|rgm|crm|cwm|cgm|hid|coin|rbo|rve|rbe|cbo|cve|cbe|hbo|hde|hbe|hwf|cch|cbf|log|lg[1-4]|fish|fs[1-7]|ore|or[1-4]|bar|bar[1-4]|axe[0-4]|net[0-4]|pik[0-4]|hd([0-9]|1[0-9]|2[0-8])|bd([0-7]|1[0-9]|2[0-8])|hn[0-3]|ft[0-3]|wp[0-5]|sp[0-5]|fl[0-4]|tw[0-4]|wd[0-4]|st[0-5]|bk[0-4]|pt([0-9]|1[0-9]|2[0-4])|sc[0-4]|sh[0-5]|cp[0-6]|bn[0-2]|sr[0-2]|qi0|qi1)$"),STACK_RE=new RegExp("^(fth|bn\\d|sr\\d|sd\\d|pk\\d|ar\\d)$");
const IV={"hd25":10,"hd26":10,"cp5":20,"hd24":120,"bd22":180,"kn0":8,"ub0":10,"ub1":24,"ub2":56,"ub3":112,"ub4":208,"bs":3,"fx":4,"ar0":1,"ar1":2,"ar2":5,"ar3":10,"ar4":19,"bd23":43,"bd24":170,"bd25":540,"bd26":1436,"bd27":3488,"rg0":20,"rg1":40,"rg2":76,"rg3":160,"rg4":340,"lt0":4,"lt1":24,"lt2":56,"lt3":104,"lt4":192,"sd5":4,"sd6":12,"sd7":28,"sd8":60,"sd9":128,"vg5":2,"vg6":6,"vg7":14,"vg8":30,"vg9":56,"ud0":8,"ud1":16,"ud2":28,"ud3":44,"ud4":68,"dh0":12,"dh1":24,"dh2":40,"dh3":60,"dh4":92,"ar5":1,"ar6":3,"ar7":7,"ar8":14,"ar9":26,"at0":5,"at1":11,"at2":25,"at3":47,"at4":84,"bw0":28,"bw1":68,"bw2":152,"bw3":304,"bw4":560,"cf0":5,"cf1":12,"cf2":24,"cf3":8,"cf4":16,"cf5":32,"cf6":40,"cf7":60,"sd0":2,"sd1":7,"sd2":18,"sd3":40,"sd4":88,"vg0":1,"vg1":4,"vg2":9,"vg3":20,"vg4":40,"pf0":4,"pf1":6,"pf2":3,"pf3":5,"pf4":12,"pf5":18,"gm0":16,"gm1":36,"gm2":72,"gm3":160,"gm4":360,"nk0":28,"nk1":56,"nk2":104,"nk3":224,"nk4":480,"fth":1,"rch":2,"rbf":3,"rrm":4,"rwm":9,"rgm":16,"crm":8,"cwm":15,"cgm":24,"hid":4,"rbo":4,"rve":4,"rbe":8,"cbo":8,"cve":6,"cbe":13,"hbo":6,"hde":5,"hbe":12,"hwf":8,"cch":4,"cbf":5,"log":1,"lg1":6,"lg2":14,"lg3":28,"lg4":52,"fish":3,"fs1":8,"fs2":16,"fs3":4,"fs4":11,"fs5":20,"fs6":27,"fs7":38,"ore":5,"or1":12,"or2":26,"or3":50,"or4":90,"bar":8,"bar1":18,"bar2":40,"bar3":76,"bar4":136,"axe0":2,"axe1":72,"axe2":324,"axe3":923,"axe4":2203,"net0":2,"net1":16,"net2":48,"net3":120,"net4":280,"pik0":2,"pik1":72,"pik2":324,"pik3":923,"pik4":2203,"hd0":6,"hd1":6,"hd2":12,"hd3":32,"hd4":121,"hd5":378,"hd6":1026,"hd7":2386,"hd8":320,"hd9":480,"hd10":60,"hd11":160,"hd12":360,"hd13":800,"hd14":1800,"hd15":240,"hd16":120,"hd17":32,"hd18":80,"hd19":180,"hd20":400,"hd21":880,"hd22":1,"hd23":320,"bd0":8,"bd1":8,"bd2":14,"bd3":64,"bd4":218,"bd5":702,"bd6":1846,"bd7":4406,"bd10":108,"bd11":288,"bd12":640,"bd13":1440,"bd14":3240,"bd15":480,"bd16":60,"bd17":152,"bd18":340,"bd19":760,"bd20":1680,"bd21":1,"hn0":6,"hn1":97,"hn2":820,"hn3":2019,"ft0":6,"ft1":97,"ft2":820,"ft3":2019,"wp0":20,"wp1":97,"wp2":378,"wp3":1026,"wp4":2570,"sp0":32,"sp1":121,"sp2":432,"sp3":1128,"sp4":2754,"sp5":1,"fl0":54,"fl1":194,"fl2":648,"fl3":1641,"fl4":3855,"tw0":43,"tw1":194,"tw2":756,"tw3":2052,"tw4":5140,"wd0":24,"wd1":80,"wd2":220,"wd3":600,"wd4":1600,"st0":80,"st1":240,"st2":600,"st3":1800,"st4":4800,"st5":3600,"bk0":40,"bk1":140,"bk2":360,"bk3":960,"bk4":2600,"pt0":0,"pt1":0,"pt2":0,"pt3":0,"pt4":0,"pt5":0,"pt6":0,"pt7":0,"pt8":0,"pt9":0,"pt10":0,"pt11":0,"pt12":0,"pt13":0,"pt14":0,"pt15":0,"pt16":0,"pt17":0,"pt18":0,"pt19":0,"pt20":0,"pt21":0,"tr4":1000,"wp5":2000,"pt24":0,"tr0":60,"tr1":120,"tr2":240,"tr3":400,"hd28":320,"pt23":0,"pk0":4,"pk1":12,"pk2":24,"cl0":2,"cs0":24,"spade":3,"hd27":120,"bd28":160,"cp6":200,"pt22":0,"rg5":1200,"sc0":4,"sc1":20,"sc2":56,"sc3":168,"sc4":480,"sh0":32,"sh1":121,"sh2":432,"sh3":1128,"sh4":2754,"sh5":160,"cp0":24,"cp1":56,"cp2":88,"cp3":104,"cp4":1,"bn0":3,"bn1":12,"bn2":52,"sr0":48,"sr1":160,"sr2":600,"qi0":0,"qi1":0};   // what a shop pays for each item
const BONE={bn0:20,bn1:60,bn2:250},SCR={sr0:150,sr1:500,sr2:2000},WKS=['wp','sp','fl','tw','wd','st'];
const XPK=['xp','fxp','mxp','cxp','sxp','fmxp','ckxp','dxp','hxp','akxp','fkxp','cfxp','mgxp','pxp','frxp','thxp','cnxp','slxp'];
const LIMIT={xpCap:50000,xpRate:60,wCap:100000,wRate:100};   // burst and per-second allowances
class Bad extends Error{}
const num=(v,lo,hi,what)=>{const n=v===undefined||v===null?0:+v;if(!Number.isFinite(n)||n<lo||n>hi)throw new Bad(what);return n;};
function summarize(str){
  const S={xp:{},wealth:0,cnt:{}};XPK.forEach(k=>S.xp[k]=0);
  if(!str)return S;
  let d;try{d=JSON.parse(str);}catch(e){throw new Bad('the save is not readable');}
  if(!d||typeof d!=='object')throw new Bad('the save is not readable');
  XPK.forEach(k=>{S.xp[k]=num(d[k],0,2e9,'an XP value is impossible');});
  let coins=num(d.coins,0,2e9,'coins are impossible');
  const add=(id,n)=>{if(!ITEM_RE.test(id))throw new Bad('an unknown item ('+String(id).slice(0,12)+')');S.cnt[id]=(S.cnt[id]||0)+n;};
  const inv=Array.isArray(d.inv)?d.inv:[];if(inv.length>28)throw new Bad('too many items in the bag');
  const stk=d.stk&&typeof d.stk==='object'?d.stk:{};
  const seen=new Set();
  inv.forEach(id=>{if(typeof id!=='string')throw new Bad('a broken item');
    if(STACK_RE.test(id)){if(seen.has(id))return;seen.add(id);add(id,num(stk[id],0,99999,'a stack is impossible'));}else add(id,1);});
  const bank=d.bank&&typeof d.bank==='object'?d.bank:{};
  for(const k in bank){if(k==='coin'){coins+=num(bank[k],0,2e9,'banked coins are impossible');continue;}add(k,num(bank[k],0,99999,'a banked amount is impossible'));}
  const g=d.gear&&typeof d.gear==='object'?d.gear:{};
  ['hd','bd','hn','ft','sh','bw','bk','cp','nk','pt','rg'].forEach(k=>{const t=g[k];if(Number.isInteger(t)&&t>=0&&ITEM_RE.test(k+t))add(k+t,1);});
  if(Number.isInteger(g.wp)&&g.wp>=0){const id=(WKS[g.wt]||'wp')+g.wp;if(ITEM_RE.test(id))add(id,1);}
  ['axe','net','pik'].forEach(k=>{const t=d[k];if(Number.isInteger(t)&&t>=0&&ITEM_RE.test(k+t))add(k+t,1);});
  let w=coins;for(const id in S.cnt)w+=(IV[id]||0)*S.cnt[id];
  if(d.ammo&&Number.isInteger(d.ammo.t)&&d.ammo.t>=0)w+=(IV['ar'+d.ammo.t]||0)*num(d.ammo.n,0,1e6,'arrows are impossible');   // arrows are counted one by one
  S.wealth=Math.round(w);return S;
}
const buckets=new Map();   // per account: how much XP and wealth it may still gain right now
function bucket(u){
  const now=Date.now();let b=buckets.get(u);
  if(!b){b={xp:LIMIT.xpCap,w:LIMIT.wCap,credit:0,t:now};buckets.set(u,b);}
  const dt=(now-b.t)/1000;b.t=now;
  b.xp=Math.min(LIMIT.xpCap,b.xp+dt*LIMIT.xpRate);b.w=Math.min(LIMIT.wCap,b.w+dt*LIMIT.wRate);
  return b;
}
function credit(u,v){if(v>0){bucket(u).credit+=v;}}
const offerValue=t=>{let v=Number.isInteger(t&&t.c)&&t.c>0?Math.min(t.c,2e9):0;(Array.isArray(t&&t.o)?t.o:[]).slice(0,28).forEach(e=>{if(Array.isArray(e)&&typeof e[0]==='string'&&Number.isInteger(e[1])&&e[1]>0)v+=(IV[e[0]]||0)*Math.min(e[1],99999);});return v;};
// returns null when the save is fine, or the reason it was refused
function checkSave(u,prevStr,nextStr){
  let P,N;
  try{N=summarize(nextStr);}catch(e){if(e instanceof Bad)return e.message;throw e;}
  try{P=summarize(prevStr);}catch(e){P=summarize(null);}
  const b=bucket(u);
  let xg=0;
  XPK.forEach(k=>{
    let g=N.xp[k]-P.xp[k];if(g<=0)return;
    if(k==='pxp'){let ok=0;for(const id in BONE)ok+=Math.max(0,(P.cnt[id]||0)-(N.cnt[id]||0))*BONE[id];for(const id in SCR)ok+=Math.max(0,(P.cnt[id]||0)-(N.cnt[id]||0))*SCR[id];g=Math.max(0,g-ok);}   // faith xp from bones and scriptures actually used up
    xg+=g;
  });
  if(xg>b.xp)return 'experience went up faster than anyone could earn it';
  const wg=N.wealth-P.wealth;
  if(wg>b.w+b.credit)return 'coins or items appeared faster than anyone could earn them';
  b.xp-=xg;
  if(wg>0){const fromCredit=Math.min(b.credit,wg);b.credit-=fromCredit;b.w-=wg-fromCredit;}
  return null;
}

// ---------- web server
function send(res,code,obj){res.writeHead(code,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(obj));}
function body(req,limit){return new Promise((res,rej)=>{let n=0;const parts=[];req.on('data',c=>{n+=c.length;if(n>limit){rej(new Error('too big'));req.destroy();}else parts.push(c);});req.on('end',()=>{try{res(JSON.parse(Buffer.concat(parts).toString()||'{}'));}catch(e){rej(e);}});req.on('error',rej);});}
const authUser=(req,b)=>{const h=req.headers.authorization||'';return liveUser(h.startsWith('Bearer ')?h.slice(7):(b&&b.token));};
const cleanSave=d=>{   // what a save may hold: the progress and the character, each as text
  if(!d||typeof d!=='object')return null;
  const s=typeof d.save==='string'&&d.save.length<400000?d.save:null,c=typeof d.char==='string'&&d.char.length<4000?d.char:null;
  return s||c?{save:s,char:c}:null;
};
// ---------- the admin page (open /admin and type your ADMIN_KEY)
const ADMIN_PAGE="<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex\">\n<title>Oakheart Admin</title>\n<style>\n:root{--bg:#16181d;--panel:#22252d;--line:#3a3f4b;--gold:#c9982a;--gold2:#ffe066;--text:#f1e9c8;--dim:#9a927a;--ok:#8dff7a;--bad:#ff8a7a}\n*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px ui-monospace,Menlo,Consolas,monospace}\nmain{max-width:760px;margin:0 auto;padding:20px 16px 60px}\nh1{color:var(--gold2);font-size:22px;margin:0 0 4px;letter-spacing:1px}h2{font-size:16px;color:var(--gold2);margin:0 0 12px}\n.sub{color:var(--dim);margin:0 0 20px;font-size:13px}\n.box{background:var(--panel);border:1px solid var(--gold);border-radius:8px;padding:16px;margin-bottom:16px}\nlabel{display:block;font-size:13px;color:var(--dim);margin:0 0 4px}\ninput{width:100%;font:inherit;color:var(--text);background:#14161b;border:1px solid var(--line);border-radius:6px;padding:9px 10px;margin-bottom:10px}\ninput:focus{outline:none;border-color:var(--gold2)}\nbutton{font:inherit;color:#1a1408;background:var(--gold);border:0;border-radius:6px;padding:9px 14px;cursor:pointer;font-weight:bold}\nbutton:hover{background:var(--gold2)}button.ghost{background:transparent;color:var(--text);border:1px solid var(--line);font-weight:normal}\nbutton.ghost:hover{border-color:var(--gold2);background:transparent}\n.row{display:flex;gap:8px;align-items:flex-start}.row input{flex:1}\n.msg{min-height:20px;font-size:14px;margin-top:4px}.ok{color:var(--ok)}.bad{color:var(--bad)}\ntable{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 6px;border-bottom:1px solid var(--line)}\nth{color:var(--dim);font-weight:normal}tr.p{cursor:pointer}tr.p:hover td{background:#2c3039}\n.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ok);margin-right:6px}\n.stats{color:var(--dim);font-size:13px;margin-bottom:10px}.hidden{display:none}\n.new{font-size:18px;color:var(--gold2);background:#14161b;border:1px dashed var(--gold);border-radius:6px;padding:10px;margin-top:8px;word-break:break-all}\n@media(max-width:560px){.hide-sm{display:none}}\n</style></head><body><main>\n<h1>OAKHEART ADMIN</h1><p class=\"sub\">Look up players and reset forgotten passwords. Only you should know the admin key.</p>\n<section class=\"box\" id=\"login\"><h2>Sign in</h2>\n <label for=\"key\">Admin key</label>\n <div class=\"row\"><input id=\"key\" type=\"password\" autocomplete=\"current-password\"><button id=\"go\">Open</button></div>\n <div class=\"msg\" id=\"lmsg\"></div></section>\n<div id=\"app\" class=\"hidden\">\n<section class=\"box\"><h2>Reset a password</h2>\n <label for=\"who\">Username</label><input id=\"who\" autocomplete=\"off\" spellcheck=\"false\">\n <label for=\"pw\">New password</label>\n <div class=\"row\"><input id=\"pw\" autocomplete=\"new-password\" spellcheck=\"false\"><button class=\"ghost\" id=\"gen\" type=\"button\">Make one</button></div>\n <button id=\"reset\">Reset password</button>\n <div class=\"msg\" id=\"rmsg\"></div><div class=\"new hidden\" id=\"newpw\"></div></section>\n<section class=\"box\"><h2>Players</h2>\n <div class=\"row\"><input id=\"q\" placeholder=\"Search by name\" spellcheck=\"false\"><button class=\"ghost\" id=\"lock\" type=\"button\">Lock</button></div>\n <div class=\"stats\" id=\"stats\"></div>\n <table><thead><tr><th>Name</th><th>Last played</th><th class=\"hide-sm\">Joined</th></tr></thead><tbody id=\"list\"></tbody></table></section>\n</div>\n<script>\nlet KEY='';try{KEY=sessionStorage.getItem('oakAdmin')||'';}catch(e){}\nconst $=id=>document.getElementById(id);\nasync function api(path,data){const r=await fetch('/api/admin/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.assign({key:KEY},data))});let j={};try{j=await r.json();}catch(e){}if(!r.ok)throw new Error(j.error||'Something went wrong.');return j;}\nconst when=t=>{if(!t)return 'never';const d=new Date(t),s=(Date.now()-d)/1000;if(s<90)return 'just now';if(s<3600)return Math.round(s/60)+' min ago';if(s<86400)return Math.round(s/3600)+' h ago';if(s<86400*30)return Math.round(s/86400)+' days ago';return d.toLocaleDateString();};\nfunction say(el,t,ok){el.textContent=t;el.className='msg '+(ok?'ok':'bad');}\nasync function load(){\n  const j=await api('players',{q:$('q').value});\n  $('stats').textContent=j.total+' accounts, '+j.online+' online now'+(j.players.length<j.total?' (showing '+j.players.length+')':'');\n  const tb=$('list');tb.textContent='';\n  j.players.forEach(p=>{const tr=document.createElement('tr');tr.className='p';tr.title='Tap to fill in the reset form';\n    const a=document.createElement('td');if(p.online){const d=document.createElement('span');d.className='dot';d.title='Online';a.append(d);}a.append(p.name);\n    const b=document.createElement('td');b.textContent=when(p.played);const c=document.createElement('td');c.className='hide-sm';c.textContent=when(p.created);\n    tr.append(a,b,c);tr.onclick=()=>{$('who').value=p.name;$('pw').focus();window.scrollTo({top:0,behavior:'smooth'});};tb.append(tr);});\n  if(!j.players.length){const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=3;td.textContent='No players found.';tr.append(td);tb.append(tr);}\n}\nasync function open(){try{await load();$('login').classList.add('hidden');$('app').classList.remove('hidden');try{sessionStorage.setItem('oakAdmin',KEY);}catch(e){}}catch(e){say($('lmsg'),e.message,false);KEY='';try{sessionStorage.removeItem('oakAdmin');}catch(_){}}}\n$('go').onclick=()=>{KEY=$('key').value;open();};$('key').onkeydown=e=>{if(e.key==='Enter'){KEY=$('key').value;open();}};\n$('lock').onclick=()=>{KEY='';try{sessionStorage.removeItem('oakAdmin');}catch(e){}location.reload();};\nlet qt;$('q').oninput=()=>{clearTimeout(qt);qt=setTimeout(()=>load().catch(e=>say($('rmsg'),e.message,false)),250);};\n$('gen').onclick=()=>{const w='abcdefghjkmnpqrstuvwxyz23456789',a=new Uint32Array(10);crypto.getRandomValues(a);let s='';a.forEach((v,i)=>{s+=w[v%w.length];if(i===4)s+='-';});$('pw').value=s;};\n$('reset').onclick=async()=>{\n  const u=$('who').value.trim(),pw=$('pw').value;$('newpw').classList.add('hidden');\n  if(!u)return say($('rmsg'),'Type a username.',false);if(pw.length<6)return say($('rmsg'),'The new password needs at least 6 characters.',false);\n  if(!confirm('Reset the password for '+u+'? They will be logged out everywhere.'))return;\n  try{const j=await api('reset',{username:u,password:pw});\n    say($('rmsg'),'Done. '+j.name+\"'s password is now:\"+(j.kicked?' (they were online and have been logged out)':''),true);\n    $('newpw').textContent=pw;$('newpw').classList.remove('hidden');$('pw').value='';load().catch(()=>{});\n  }catch(e){say($('rmsg'),e.message,false);}\n};\nif(KEY)open();\n</script></main></body></html>\n";
let page=null;
function gamePage(){
  if(!page){const html=fs.readFileSync(GAME,'utf8');page=html.replace('<head>','<head><script>window.OAK_SERVER=1</script>');}
  return page;
}
const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url,'http://x'),ip=(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();
  try{
    if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/index.html')){
      res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache'});return res.end(gamePage());
    }
    if(req.method==='GET'&&(url.pathname==='/admin'||url.pathname==='/admin/')){
      res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','X-Robots-Tag':'noindex','X-Frame-Options':'DENY'});return res.end(ADMIN_PAGE);
    }
    if(req.method==='POST'&&url.pathname.startsWith('/api/admin/')){
      if(!ADMIN_KEY)return send(res,503,{error:'The admin page is off. Add ADMIN_KEY in Render > Environment, then deploy again.'});
      if(tooMany('admin|'+ip))return send(res,429,{error:'Too many tries. Wait a minute and try again.'});
      const b=await body(req,10000),k=String(b.key||'');
      const ka=crypto.createHash('sha256').update(k).digest(),kb=crypto.createHash('sha256').update(ADMIN_KEY).digest();
      if(!crypto.timingSafeEqual(ka,kb)){console.log('Wrong admin key from '+ip);return send(res,401,{error:'Wrong admin key.'});}
      tries.delete('admin|'+ip);   // the right key: no waiting
      if(url.pathname==='/api/admin/players'){
        const r=await db.listAccounts(userKey(b.q).slice(0,20));
        const on=new Set([...peers.values()].map(p=>p.user));
        return send(res,200,{total:r.total,online:on.size,players:r.rows.map(a=>({username:a.username,name:a.display,created:a.created,played:a.updated,online:on.has(a.username)}))});
      }
      if(url.pathname==='/api/admin/reset'){
        const u=userKey(b.username),pw=String(b.password||'');
        const a=await db.getAccount(u);if(!a)return send(res,404,{error:'No player called "'+String(b.username||'').slice(0,20)+'".'});
        if(pw.length<6||pw.length>100)return send(res,400,{error:'The new password needs at least 6 characters.'});
        const salt=crypto.randomBytes(16).toString('hex');
        await db.setPassword(u,await scrypt(pw,salt),salt);
        let kicked=0;peers.forEach(p=>{if(p.user===u){out(p.ws,{t:'bye',why:'Your password was changed. Please log in again.'});p.ws.close();kicked++;}});
        console.log('Admin reset the password for '+u+' (from '+ip+')');
        return send(res,200,{ok:true,name:a.display,kicked});
      }
      return send(res,404,{error:'Not found'});
    }
    if(req.method==='GET'&&url.pathname==='/health')return send(res,200,{ok:true,players:peers.size});
    if(req.method==='POST'&&(url.pathname==='/api/register'||url.pathname==='/api/login')){
      if(tooMany(ip))return send(res,429,{error:'Too many tries. Wait a minute and try again.'});
      const b=await body(req,10000),name=String(b.username||'').trim(),pw=String(b.password||''),u=userKey(name);
      if(url.pathname==='/api/register'){
        if(!goodName(name))return send(res,400,{error:'Usernames are 3 to 14 letters, numbers, spaces or _.'});
        if(pw.length<6||pw.length>100)return send(res,400,{error:'Passwords need at least 6 characters.'});
        if(await db.getAccount(u))return send(res,409,{error:'That username is taken.'});
        const salt=crypto.randomBytes(16).toString('hex');
        await db.addAccount({username:u,display:name,salt,hash:await scrypt(pw,salt)});
        return send(res,200,{token:makeToken(u),username:name,save:null});
      }
      const a=await db.getAccount(u);
      const h=a?await scrypt(pw,a.salt):await scrypt(pw,'x');
      if(!a||h.length!==a.hash.length||!crypto.timingSafeEqual(Buffer.from(h),Buffer.from(a.hash)))return send(res,401,{error:'Wrong username or password.'});
      return send(res,200,{token:makeToken(u),username:a.display,save:await db.getSave(u)});
    }
    if(req.method==='GET'&&url.pathname==='/api/me'){
      const u=await authUser(req);if(!u)return send(res,401,{error:'Please log in again.'});
      const a=await db.getAccount(u);if(!a)return send(res,401,{error:'Please log in again.'});
      return send(res,200,{username:a.display});
    }
    if(req.method==='POST'&&url.pathname==='/api/save'){
      const b=await body(req,450000),u=await authUser(req,b);if(!u)return send(res,401,{error:'Please log in again.'});
      const next=cleanSave(b),prev=await db.getSave(u);
      if(!next&&!b.reset)return send(res,200,{ok:true,ignored:true});   // an empty save only counts when the player chose New character
      const why=next&&next.save?checkSave(u,prev&&prev.save,next.save):null;
      if(why){console.log('Refused a save from '+u+': '+why);return send(res,409,{error:'The server refused this save: '+why+'.',refused:true});}
      await db.putSave(u,next);return send(res,200,{ok:true});
    }
    send(res,404,{error:'Not found'});
  }catch(e){console.error(e);send(res,500,{error:'Something went wrong on the server.'});}
});

// ---------- online play: share each player's presence with everyone else
const peers=new Map();   // peer id -> {ws, user, presence}
const wss=new WebSocketServer({server,path:'/ws',maxPayload:64*1024});
const out=(ws,m)=>{if(ws.readyState===1)ws.send(JSON.stringify(m));};
const all=(m,except)=>{const s=JSON.stringify(m);peers.forEach((p,id)=>{if(id!==except&&p.ws.readyState===1)p.ws.send(s);});};
wss.on('connection',async(ws,req)=>{
  const early=[];ws.on('message',r=>early.push(r));   // hold messages until the log-in is checked
  let u=null;try{u=await liveUser(new URL(req.url,'http://x').searchParams.get('t'));}catch(e){}
  if(!u){out(ws,{t:'bye',why:'Please log in again.'});return ws.close();}
  ws.removeAllListeners('message');
  peers.forEach((p,id)=>{if(p.user===u){out(p.ws,{t:'bye',why:'You logged in somewhere else.'});p.ws.close();}});   // one game per account
  const id=crypto.randomBytes(6).toString('hex');
  const me={ws,user:u,presence:{},alive:true};
  out(ws,{t:'hello',me:id,peers:[...peers].map(([pid,p])=>({peer:pid,presence:p.presence}))});
  peers.set(id,me);
  ws.on('pong',()=>{me.alive=true;});
  ws.on('message',raw=>{
    let m;try{m=JSON.parse(raw);}catch(e){return;}
    if(!m||m.t!=='p'||!m.patch||typeof m.patch!=='object')return;
    const next=Object.assign({},me.presence,m.patch);
    if(JSON.stringify(next).length>32000)return;    // keep each player's shared state small
    const joined=!Object.keys(me.presence).length;me.presence=next;
    if(m.patch.tr)noteDeal(id,me);
    all({t:joined?'j':'u',peer:id,presence:next},id);
  });
  ws.on('close',()=>{if(peers.get(id)===me){peers.delete(id);all({t:'l',peer:id});}});
  early.forEach(r=>ws.emit('message',r));
});
// A trade both sides confirmed, a duel stake set aside, a duel won: the server sees these pass by and lets the
// matching coins and items show up in the next save.
const dealt=new Set();
function noteDeal(id,me){
  const t=me.presence.tr;if(!t||typeof t!=='object'||typeof t.h!=='string'||!t.h)return;
  const p=peers.get(t.to),pt=p&&p.presence.tr;
  const once=k=>{if(dealt.has(k))return false;dealt.add(k);if(dealt.size>20000)dealt.clear();return true;};
  if(t.st==='done'&&pt&&pt.to===id&&pt.h===t.h&&(pt.st==='done'||pt.st==='conf')&&once('t|'+me.user+'|'+t.h))credit(me.user,offerValue(pt));   // trade: what they gave you
  if(t.st==='fight'&&once('f|'+me.user+'|'+t.h))credit(me.user,offerValue(t));                                                               // duel: your stake comes back if you win or it is called off
  if(t.st==='lost'&&p&&once('l|'+t.h))credit(p.user,offerValue(t));                                                                         // duel: the winner gets the loser's stake
}
setInterval(()=>peers.forEach((p,id)=>{if(!p.alive){p.ws.terminate();return;}p.alive=false;try{p.ws.ping();}catch(e){}}),30000);   // drop players whose connection died

openStore().then(s=>{db=s;server.listen(PORT,()=>console.log('Oakheart is running on port '+PORT));}).catch(e=>{console.error('\n*** Oakheart could not start: '+(e&&e.message||e)+' ***\n');process.exit(1);});
