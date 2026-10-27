// vigile Web 控制台 — `vig logs --web` 启动的本地站点。
// 零依赖（node:http），与项目其余部分同一原则。
// 页面是单文件内嵌：列表 + 筛选 + 统计 + 单条详情 + 文件变更 + 实时刷新。

import http from "node:http";
import { connect, dbPath } from "./core.js";

// ---------------------------------------------------------------- 查询（与 CLI 同一过滤语义）
function buildWhere(q) {
  const where = [], params = [];
  const num = (v, d) => (v === undefined || v === null || v === "" ? d : Number(v));
  if (q.tool) { where.push("tool = ?"); params.push(q.tool); }
  if (q.category) { where.push("category = ?"); params.push(q.category); }
  if (q.status) { where.push("status = ?"); params.push(q.status); }
  if (q.risk) { where.push("risk = ?"); params.push(q.risk); }
  if (q.case) { where.push("case_name = ?"); params.push(q.case); }
  if (q.ticket) { where.push("ticket = ?"); params.push(q.ticket); }
  if (q.keyword) {
    where.push("(args_json LIKE ? OR output_digest LIKE ? OR error LIKE ? OR target LIKE ? OR session LIKE ? OR actor LIKE ?)");
    const k = `%${q.keyword}%`;
    params.push(k, k, k, k, k, k);
  }
  return { clause: where.length ? " WHERE " + where.join(" AND ") : "", params, num };
}

function queryRows(q) {
  const db = connect();
  const { clause, params, num } = buildWhere(q);
  const limit = num(q.limit, 500);
  const offset = num(q.offset, 0);
  return db.prepare(`SELECT * FROM audit_log${clause} ORDER BY ts_epoch DESC LIMIT ? OFFSET ?`)
    .all(...params, limit, offset);
}

function queryStats(q) {
  const db = connect();
  const { clause, params } = buildWhere(q);
  const one = (sql) => db.prepare(sql.replace(/§/g, clause)).all(...params);
  return {
    total: db.prepare(`SELECT COUNT(*) c FROM audit_log${clause}`).get(...params).c,
    byTool: one(`SELECT tool, COUNT(*) c, SUM(status='ok') ok, SUM(status!='ok') bad,
      ROUND(AVG(duration_ms)) avg_ms, MAX(duration_ms) max_ms FROM audit_log§
      GROUP BY tool ORDER BY c DESC LIMIT 30`),
    byStatus: one(`SELECT status, COUNT(*) c FROM audit_log§ GROUP BY status ORDER BY c DESC`),
    byCategory: one(`SELECT category, COUNT(*) c FROM audit_log§ GROUP BY category ORDER BY c DESC`),
    byRisk: one(`SELECT COALESCE(risk,'-') r, COUNT(*) c FROM audit_log§ GROUP BY r ORDER BY c DESC`),
    timeline: one(`SELECT substr(ts,1,13) h, COUNT(*) c FROM audit_log§ GROUP BY h ORDER BY h`),
    fileChanges: db.prepare(`SELECT COUNT(*) c FROM file_changes`).get().c,
  };
}

function queryFileChanges(q) {
  const db = connect();
  const limit = Number(q.limit) > 0 ? Number(q.limit) : 200;
  return db.prepare(`SELECT id, ts, file_path, op, added_lines, removed_lines, before_size, after_size,
      substr(diff,1,4000) diff, case_name FROM file_changes ORDER BY id DESC LIMIT ?`).all(limit);
}

function queryGet(id) {
  return connect().prepare("SELECT * FROM audit_log WHERE id = ?").get(id);
}

function queryVerify() {
  // 复用 core 的链校验会引入循环依赖，这里直接读链字段做轻量校验
  const db = connect();
  const rows = db.prepare(
    "SELECT id, prev_hash, hash FROM audit_log WHERE hash IS NOT NULL ORDER BY id").all();
  let prev = null, broken = 0, checked = 0;
  for (const r of rows) {
    checked++;
    const linkOk = (r.prev_hash === prev) || (prev === null && r.prev_hash === null);
    if (!linkOk) broken++;
    prev = r.hash;
  }
  return { checked, broken, ok: broken === 0 };
}

// ---------------------------------------------------------------- HTTP
export function serveWeb({ port = 8433, host = "127.0.0.1" } = {}) {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, "http://localhost");
    const q = Object.fromEntries(u.searchParams.entries());
    const send = (code, type, body) => {
      res.writeHead(code, { "Content-Type": type, "Cache-Control": "no-store" });
      res.end(body);
    };
    try {
      if (u.pathname === "/") return send(200, "text/html; charset=utf-8", PAGE_HTML);
      if (u.pathname === "/api/rows") return send(200, "application/json", JSON.stringify(queryRows(q)));
      if (u.pathname === "/api/stats") return send(200, "application/json", JSON.stringify(queryStats(q)));
      if (u.pathname === "/api/get") return send(200, "application/json", JSON.stringify(queryGet(Number(q.id)) || null));
      if (u.pathname === "/api/files") return send(200, "application/json", JSON.stringify(queryFileChanges(q)));
      if (u.pathname === "/api/verify") return send(200, "application/json", JSON.stringify(queryVerify()));
      return send(404, "text/plain", "not found");
    } catch (e) {
      send(500, "application/json", JSON.stringify({ error: String(e.message) }));
    }
  });
  return new Promise(resolve => {
    server.listen(port, host, () => resolve({ server, url: `http://${host}:${port}`, db: dbPath() }));
  });
}

// ---------------------------------------------------------------- 页面（内嵌单文件，无外部资源）
const PAGE_HTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>vigile — 审计控制台</title>
<style>
  :root{--bg:#0f1419;--panel:#1a2129;--line:#2a333e;--fg:#d7dde4;--dim:#8a95a5;
        --ok:#4caf50;--bad:#e5484d;--denied:#e5484d;--warn:#e7a13d;--link:#5aa9e6}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.5 "Cascadia Code",Consolas,monospace}
  header{display:flex;gap:16px;align-items:baseline;padding:10px 16px;background:var(--panel);border-bottom:1px solid var(--line)}
  header h1{margin:0;font-size:15px}
  header .db{color:var(--dim);font-size:11px}
  nav{display:flex;gap:4px;padding:8px 16px 0}
  nav button{background:none;border:1px solid var(--line);color:var(--dim);padding:4px 12px;cursor:pointer;border-radius:4px 4px 0 0;font:inherit}
  nav button.on{color:var(--fg);background:var(--panel);border-bottom-color:var(--panel)}
  main{padding:12px 16px}
  .filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
  .filters input,.filters select{background:var(--bg);border:1px solid var(--line);color:var(--fg);padding:4px 8px;border-radius:4px;font:inherit}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-bottom:14px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:10px 12px}
  .card h3{margin:0 0 6px;font-size:12px;color:var(--dim)}
  .card .n{font-size:22px}
  .bar{display:flex;height:8px;border-radius:4px;overflow:hidden;margin-top:4px}
  .bar div{background:var(--ok)} .bar .b{background:var(--bad)}
  table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:6px}
  th{color:var(--dim);text-align:left;font-weight:normal;font-size:11px;padding:6px 10px;border-bottom:1px solid var(--line)}
  td{padding:5px 10px;border-bottom:1px solid #212a34;vertical-align:top}
  tr:hover td{background:#202932}
  tr.row{cursor:pointer}
  .ok{color:var(--ok)} .bad{color:var(--bad)} .denied{color:var(--bad)} .failed{color:var(--bad)} .timeout{color:var(--warn)}
  .dim{color:var(--dim)} .small{font-size:11px}
  .timeline{display:flex;align-items:flex-end;gap:2px;height:70px;margin-top:8px}
  .timeline .col{flex:1;background:var(--link);border-radius:2px 2px 0 0;min-height:2px;position:relative}
  .timeline .col:hover::after{content:attr(data-tip);position:absolute;bottom:105%;left:50%;transform:translateX(-50%);
    background:#000;padding:3px 8px;border-radius:4px;white-space:nowrap;font-size:11px}
  dialog{background:var(--panel);border:1px solid var(--line);border-radius:8px;color:var(--fg);
    width:min(860px,92vw);max-height:86vh;overflow:auto;padding:0}
  dialog::backdrop{background:rgba(0,0,0,.6)}
  .dlg-h{display:flex;justify-content:space-between;padding:10px 16px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--panel)}
  .dlg-b{padding:12px 16px}
  .kv{display:grid;grid-template-columns:140px 1fr;gap:4px 12px}
  .kv b{color:var(--dim);font-weight:normal}
  pre{background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:8px;overflow:auto;white-space:pre-wrap;word-break:break-all}
  .diff{white-space:pre;font-size:11px}
  .diff .a{color:var(--ok)} .diff .d{color:var(--bad)}
  footer{padding:8px 16px;color:var(--dim);font-size:11px}
  .auto{color:var(--link);cursor:pointer}
</style>
</head>
<body>
<header>
  <h1>vigile 守夜人 · 审计控制台</h1>
  <span class="db" id="dbpath"></span>
  <span style="flex:1"></span>
  <label class="small dim"><input type="checkbox" id="auto" checked style="vertical-align:-2px"> 自动刷新 3s</label>
</header>
<nav>
  <button data-tab="logs" class="on">调用日志</button>
  <button data-tab="stats">统计分析</button>
  <button data-tab="files">文件变更</button>
</nav>
<main id="main">加载中…</main>
<footer id="foot"></footer>
<dialog id="dlg"><div class="dlg-h"><b id="dlg-title"></b><button onclick="dlg.close()" style="background:none;border:none;color:var(--dim);cursor:pointer;font:inherit">✕ 关闭</button></div><div class="dlg-b" id="dlg-body"></div></dialog>
<script>
const $ = s => document.querySelector(s);
const state = { tab:'logs', tool:'', status:'', category:'', keyword:'', limit:200 };
const esc = s => String(s??'').replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmtT = ts => { const t=String(ts||''); return t.replace('T',' ').replace('+08:00',''); };

async function api(p){ const r = await fetch(p); return r.json(); }

async function load(){
  const q = new URLSearchParams();
  for (const k of ['tool','status','category','keyword']) if (state[k]) q.set(k,state[k]);
  q.set('limit', state.limit);
  if (state.tab==='logs') return renderLogs(q);
  if (state.tab==='stats') return renderStats(q);
  if (state.tab==='files') return renderFiles();
}

function filtersHtml(opts, cur, key){
  return '<select onchange="state.'+key+'=this.value;load()"><option value="">'+opts.label+'</option>'
    + opts.items.map(i=>'<option '+(cur===i?'selected':'')+'>'+esc(i)+'</option>').join('') + '</select>';
}

async function renderLogs(q){
  const [rows, stats] = await Promise.all([api('/api/rows?'+q), api('/api/stats?'+q)]);
  const tools = stats.byTool.map(r=>r.tool);
  $('#main').innerHTML =
    '<div class="stats">'
    + '<div class="card"><h3>总调用</h3><div class="n">'+stats.total+'</div>'
    +   '<div class="bar"><div style="flex:'+(stats.total- stats.byStatus.filter(s=>s.status!=='ok').reduce((a,s)=>a+s.c,0))+'"></div><div class="b" style="flex:'+stats.byStatus.filter(s=>s.status!=='ok').reduce((a,s)=>a+s.c,0)+'"></div></div></div>'
    + '<div class="card"><h3>按状态</h3>' + stats.byStatus.map(s=>'<div>'+esc(s.status)+' <span class="'+(s.status==='ok'?'ok':'bad')+'">'+s.c+'</span></div>').join('') + '</div>'
    + '<div class="card"><h3>按分类</h3>' + stats.byCategory.map(s=>'<div>'+esc(s.category||'-')+' <span class="dim">'+s.c+'</span></div>').join('') + '</div>'
    + '<div class="card"><h3>风险分布</h3>' + stats.byRisk.map(s=>'<div>'+esc(s.r)+' <span class="'+(s.r==='write'?'bad':'dim')+'">'+s.c+'</span></div>').join('') + '</div>'
    + '</div>'
    + '<div class="filters">'
    + '<input placeholder="关键词（参数/输出/会话）" value="'+esc(state.keyword)+'" onchange="state.keyword=this.value;load()" style="flex:1;min-width:220px">'
    + filtersHtml({label:'工具',items:tools}, state.tool, 'tool')
    + filtersHtml({label:'状态',items:['ok','failed','denied','timeout']}, state.status, 'status')
    + filtersHtml({label:'分类',items:[...new Set(stats.byCategory.map(s=>s.category).filter(Boolean))]}, state.category, 'category')
    + '<select onchange="state.limit=+this.value;load()"><option '+(state.limit===200?'selected':'')+'>200</option><option '+(state.limit===1000?'selected':'')+'>1000</option><option '+(state.limit===5000?'selected':'')+'>5000</option></select>'
    + '</div>'
    + '<table><tr><th>#</th><th>时间</th><th>工具</th><th>动作</th><th>状态</th><th>耗时</th><th>来源</th><th>会话</th></tr>'
    + rows.map(r=>'<tr class="row" onclick="detail('+r.id+')">'
      + '<td class="dim">'+r.id+'</td>'
      + '<td class="small dim">'+fmtT(r.ts)+'</td>'
      + '<td><b>'+esc(r.tool)+'</b></td>'
      + '<td class="small">'+esc(r.action||'')+'</td>'
      + '<td class="'+esc(r.status)+'">'+esc(r.status)+'</td>'
      + '<td class="dim">'+(r.duration_ms==null?'-':r.duration_ms+'ms')+'</td>'
      + '<td class="small dim">'+esc(r.source)+'</td>'
      + '<td class="small dim">'+esc((r.session||'').split('@')[0])+'</td></tr>').join('')
    + '</table>';
  $('#foot').textContent = rows.length + ' 条 / 共 ' + stats.total + '（点击行看详情）';
}

async function renderStats(q){
  const s = await api('/api/stats?'+q);
  const maxC = Math.max(...s.timeline.map(t=>t.c), 1);
  const total = s.byTool.reduce((a,t)=>a+t.c,0);
  $('#main').innerHTML =
    '<div class="stats">'
    + '<div class="card"><h3>总调用</h3><div class="n">'+s.total+'</div><div class="small dim">文件变更 '+s.fileChanges+' 次</div></div>'
    + '<div class="card" style="grid-column:span 3"><h3>按小时分布</h3>'
    + '<div class="timeline">' + s.timeline.map(t=>'<div class="col" style="height:'+(t.c/maxC*100)+'%" data-tip="'+esc(t.h)+'时 · '+t.c+' 次"></div>').join('') + '</div></div>'
    + '</div>'
    + '<table><tr><th>工具</th><th>次数</th><th>占比</th><th>成功/失败</th><th>平均耗时</th><th>最慢</th></tr>'
    + s.byTool.map(t=>'<tr><td><b>'+esc(t.tool)+'</b></td><td>'+t.c+'</td>'
      + '<td><div class="bar" style="width:120px"><div style="flex:'+t.c+'"></div><div class="b" style="flex:'+(total-t.c)+'"></div></div></td>'
      + '<td><span class="ok">'+t.ok+'</span> / <span class="bad">'+t.bad+'</span></td>'
      + '<td class="dim">'+(t.avg_ms||0)+'ms</td><td class="dim">'+(t.max_ms||0)+'ms</td></tr>').join('')
    + '</table>';
  $('#foot').textContent = '统计基于当前筛选条件';
}

async function renderFiles(){
  const rows = await api('/api/files?limit=200');
  $('#main').innerHTML = '<table><tr><th>#</th><th>时间</th><th>文件</th><th>操作</th><th>+/−</th></tr>'
    + rows.map(r=>'<tr class="row" onclick="fileDetail('+r.id+')">'
      + '<td class="dim">'+r.id+'</td><td class="small dim">'+fmtT(r.ts)+'</td>'
      + '<td class="small" style="max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(r.file_path)+'</td>'
      + '<td>'+esc(r.op)+'</td>'
      + '<td><span class="ok">+'+r.added_lines+'</span> <span class="bad">−'+r.removed_lines+'</span></td></tr>').join('')
    + '</table>';
  $('#foot').textContent = rows.length + ' 条文件变更（点击行看 diff）';
}

async function detail(id){
  const r = await api('/api/get?id='+id);
  if (!r) return;
  $('#dlg-title').textContent = '#'+r.id+' · '+r.tool+' '+(r.action||'');
  const kv = [];
  for (const [k,v] of Object.entries(r)) {
    if (v===null||v===undefined) continue;
    if (['args_json','output_digest','error','meta_json'].includes(k)) {
      kv.push('<b>'+k+'</b><pre>'+esc(v)+'</pre>');
    } else if (['prev_hash','hash'].includes(k)) {
      kv.push('<b>'+k+'</b><span class="small dim">'+esc(v)+'</span>');
    } else {
      kv.push('<b>'+k+'</b><span class="'+(k==='status'?' '+esc(v):'')+'">'+esc(v)+'</span>');
    }
  }
  $('#dlg-body').innerHTML = '<div class="kv">'+kv.join('')+'</div>';
  dlg.showModal();
}

async function fileDetail(id){
  const rows = await api('/api/files?limit=200');
  const r = rows.find(x=>x.id===id);
  if (!r) return;
  $('#dlg-title').textContent = r.file_path;
  const diff = String(r.diff||'').split('\\n').map(l =>
    l.startsWith('+')?'<span class="a">'+esc(l)+'</span>'
    : l.startsWith('-')?'<span class="d">'+esc(l)+'</span>' : esc(l)).join('\\n');
  $('#dlg-body').innerHTML = '<div class="kv"><b>时间</b><span>'+fmtT(r.ts)+'</span><b>操作</b><span>'+esc(r.op)+'</span>'
    + '<b>大小</b><span class="dim">'+r.before_size+' → '+r.after_size+' bytes</span></div><pre class="diff">'+diff+'</pre>';
  dlg.showModal();
}

document.querySelectorAll('nav button').forEach(b => b.onclick = () => {
  document.querySelectorAll('nav button').forEach(x=>x.classList.remove('on'));
  b.classList.add('on'); state.tab = b.dataset.tab; load();
});

setInterval(() => { if ($('#auto').checked && !dlg.open) load(); }, 3000);
load();
api('/api/verify').then(v => {
  if (!v.ok) { document.body.insertAdjacentHTML('afterbegin','<div style="background:#5c1a1e;padding:6px 16px;color:#ffb4b4">⚠ hash 链校验异常：'+v.broken+' 处断裂</div>'); }
});
</script>
</body>
</html>`;
