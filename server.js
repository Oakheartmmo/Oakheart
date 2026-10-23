// Oakheart game server
// - serves the game (index.html)
// - accounts: sign up / log in, passwords stored as salted scrypt hashes
// - saves: each account's progress kept in a Postgres database (DATABASE_URL), or a local file when testing
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

// ---------- storage: Postgres when DATABASE_URL is set, otherwise a JSON file (for testing on your computer)
let db;
async function openStore(){
  if(process.env.DATABASE_URL){
    const {Pool}=require('pg');
    const url=process.env.DATABASE_URL,local=/localhost|127\.0\.0\.1/.test(url);
    const pool=new Pool({connectionString:url,ssl:local||process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:5});
    await pool.query(`CREATE TABLE IF NOT EXISTS accounts(username TEXT PRIMARY KEY, display TEXT NOT NULL, hash TEXT NOT NULL, salt TEXT NOT NULL, created TIMESTAMPTZ DEFAULT now());
      CREATE TABLE IF NOT EXISTS saves(username TEXT PRIMARY KEY REFERENCES accounts(username) ON DELETE CASCADE, data JSONB, updated TIMESTAMPTZ DEFAULT now());`);
    console.log('Using the Postgres database for accounts and saves.');
    return {
      async getAccount(u){const r=await pool.query('SELECT username,display,hash,salt FROM accounts WHERE username=$1',[u]);return r.rows[0]||null;},
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
    async addAccount(a){mem.accounts[a.username]=a;flush();},
    async getSave(u){return mem.saves[u]||null;},
    async putSave(u,d){mem.saves[u]=d;flush();}
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
const userKey=n=>String(n||'').trim().toLowerCase();
const goodName=n=>/^[A-Za-z0-9_ ]{3,14}$/.test(n)&&n.trim()===n&&!/  /.test(n);

// a few tries per minute per address, to slow down password guessing
const tries=new Map();
function tooMany(ip){const now=Date.now(),a=(tries.get(ip)||[]).filter(t=>now-t<60000);a.push(now);tries.set(ip,a);return a.length>10;}


// ---------- save checks (anti-cheat, level 1)
// Every save is compared with the account's last accepted save. XP and wealth (coins plus what your items sell for)
// can only grow as fast as a person could really earn them; anything faster is refused and the old save is kept.
// Trades and duel winnings seen by the server count as allowed gains.
const ITEM_RE=new RegExp("^(kn0|ub[0-4]|bs|fx|ar[0-4]|bw[0-4]|cf[0-7]|sd[0-4]|vg[0-4]|pf[0-5]|gm[0-4]|nk[0-4]|fth|rch|rbf|rrm|rwm|rgm|crm|cwm|cgm|hid|coin|rbo|rve|rbe|cbo|cve|cbe|hbo|hde|hbe|hwf|cch|cbf|log|lg[1-4]|fish|fs[1-7]|ore|or[1-4]|bar|bar[1-4]|axe[0-4]|net[0-4]|pik[0-4]|hd([0-9]|1[0-9]|2[0-3])|bd([0-7]|1[0-9]|2[01])|hn[0-3]|ft[0-3]|wp[0-4]|sp[0-5]|fl[0-4]|tw[0-4]|wd[0-4]|st[0-5]|bk[0-4]|pt([0-9]|1[0-9]|20)|sc[0-4]|sh[0-5]|cp[0-4]|bn[0-2]|sr[0-2]|qi0|qi1)$"),STACK_RE=new RegExp("^(fth|bn\\d|sr\\d|sd\\d)$");
const IV={"kn0":8,"ub0":10,"ub1":24,"ub2":56,"ub3":112,"ub4":208,"bs":3,"fx":4,"ar0":20,"ar1":48,"ar2":104,"ar3":208,"ar4":384,"bw0":28,"bw1":68,"bw2":152,"bw3":304,"bw4":560,"cf0":5,"cf1":12,"cf2":24,"cf3":8,"cf4":16,"cf5":32,"cf6":40,"cf7":60,"sd0":2,"sd1":7,"sd2":18,"sd3":40,"sd4":88,"vg0":1,"vg1":4,"vg2":9,"vg3":20,"vg4":40,"pf0":4,"pf1":6,"pf2":3,"pf3":5,"pf4":12,"pf5":18,"gm0":16,"gm1":36,"gm2":72,"gm3":160,"gm4":360,"nk0":28,"nk1":56,"nk2":104,"nk3":224,"nk4":480,"fth":1,"rch":2,"rbf":3,"rrm":4,"rwm":9,"rgm":16,"crm":8,"cwm":15,"cgm":24,"hid":4,"rbo":4,"rve":4,"rbe":8,"cbo":8,"cve":6,"cbe":13,"hbo":6,"hde":5,"hbe":12,"hwf":8,"cch":4,"cbf":5,"log":1,"lg1":6,"lg2":14,"lg3":28,"lg4":52,"fish":3,"fs1":8,"fs2":16,"fs3":4,"fs4":11,"fs5":20,"fs6":27,"fs7":38,"ore":5,"or1":12,"or2":26,"or3":50,"or4":90,"bar":8,"bar1":18,"bar2":40,"bar3":76,"bar4":136,"axe0":2,"axe1":72,"axe2":324,"axe3":923,"axe4":2203,"net0":2,"net1":16,"net2":48,"net3":120,"net4":280,"pik0":2,"pik1":72,"pik2":324,"pik3":923,"pik4":2203,"hd0":6,"hd1":6,"hd2":12,"hd3":32,"hd4":121,"hd5":378,"hd6":1026,"hd7":2386,"hd8":320,"hd9":480,"hd10":60,"hd11":160,"hd12":360,"hd13":800,"hd14":1800,"hd15":240,"hd16":120,"hd17":32,"hd18":80,"hd19":180,"hd20":400,"hd21":880,"hd22":1,"hd23":320,"bd0":8,"bd1":8,"bd2":14,"bd3":64,"bd4":218,"bd5":702,"bd6":1846,"bd7":4406,"bd10":108,"bd11":288,"bd12":640,"bd13":1440,"bd14":3240,"bd15":480,"bd16":60,"bd17":152,"bd18":340,"bd19":760,"bd20":1680,"bd21":1,"hn0":6,"hn1":97,"hn2":820,"hn3":2019,"ft0":6,"ft1":97,"ft2":820,"ft3":2019,"wp0":20,"wp1":97,"wp2":378,"wp3":1026,"wp4":2570,"sp0":32,"sp1":121,"sp2":432,"sp3":1128,"sp4":2754,"sp5":1,"fl0":54,"fl1":194,"fl2":648,"fl3":1641,"fl4":3855,"tw0":43,"tw1":194,"tw2":756,"tw3":2052,"tw4":5140,"wd0":24,"wd1":80,"wd2":220,"wd3":600,"wd4":1600,"st0":80,"st1":240,"st2":600,"st3":1800,"st4":4800,"st5":3600,"bk0":40,"bk1":140,"bk2":360,"bk3":960,"bk4":2600,"pt0":0,"pt1":0,"pt2":0,"pt3":0,"pt4":0,"pt5":0,"pt6":0,"pt7":0,"pt8":0,"pt9":0,"pt10":0,"pt11":0,"pt12":0,"pt13":0,"pt14":0,"pt15":0,"pt16":0,"pt17":0,"pt18":0,"pt19":0,"pt20":0,"sc0":4,"sc1":20,"sc2":56,"sc3":168,"sc4":480,"sh0":32,"sh1":121,"sh2":432,"sh3":1128,"sh4":2754,"sh5":160,"cp0":24,"cp1":56,"cp2":88,"cp3":104,"cp4":1,"bn0":3,"bn1":12,"bn2":52,"sr0":48,"sr1":160,"sr2":600,"qi0":0,"qi1":0};   // what a shop pays for each item
const BONE={bn0:20,bn1:60,bn2:250},SCR={sr0:150,sr1:500,sr2:2000},WKS=['wp','sp','fl','tw','wd','st'];
const XPK=['xp','fxp','mxp','cxp','sxp','fmxp','ckxp','dxp','hxp','akxp','fkxp','cfxp','mgxp','pxp','frxp','thxp'];
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
  ['hd','bd','hn','ft','sh','bw','bk','cp','nk','pt'].forEach(k=>{const t=g[k];if(Number.isInteger(t)&&t>=0&&ITEM_RE.test(k+t))add(k+t,1);});
  if(Number.isInteger(g.wp)&&g.wp>=0){const id=(WKS[g.wt]||'wp')+g.wp;if(ITEM_RE.test(id))add(id,1);}
  ['axe','net','pik'].forEach(k=>{const t=d[k];if(Number.isInteger(t)&&t>=0&&ITEM_RE.test(k+t))add(k+t,1);});
  let w=coins;for(const id in S.cnt)w+=(IV[id]||0)*S.cnt[id];
  if(d.ammo&&Number.isInteger(d.ammo.t)&&d.ammo.t>=0)w+=(IV['ar'+d.ammo.t]||0)/20*num(d.ammo.n,0,1e6,'arrows are impossible');
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
const authUser=(req,b)=>{const h=req.headers.authorization||'';return readToken(h.startsWith('Bearer ')?h.slice(7):(b&&b.token));};
const cleanSave=d=>{   // what a save may hold: the progress and the character, each as text
  if(!d||typeof d!=='object')return null;
  const s=typeof d.save==='string'&&d.save.length<400000?d.save:null,c=typeof d.char==='string'&&d.char.length<4000?d.char:null;
  return s||c?{save:s,char:c}:null;
};
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
      const u=authUser(req);if(!u)return send(res,401,{error:'Please log in again.'});
      const a=await db.getAccount(u);if(!a)return send(res,401,{error:'Please log in again.'});
      return send(res,200,{username:a.display});
    }
    if(req.method==='POST'&&url.pathname==='/api/save'){
      const b=await body(req,450000),u=authUser(req,b);if(!u)return send(res,401,{error:'Please log in again.'});
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
wss.on('connection',(ws,req)=>{
  const u=readToken(new URL(req.url,'http://x').searchParams.get('t'));
  if(!u){out(ws,{t:'bye',why:'Please log in again.'});return ws.close();}
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
