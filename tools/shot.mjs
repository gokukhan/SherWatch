// Headless screenshot + console capture for the dashboard, via the Chrome DevTools Protocol.
// Usage: node tools/shot.mjs <url> <out.png> [width] [height] [waitMs] [view]
import { spawn } from 'node:child_process';
import { writeFileSync, existsSync } from 'node:fs';

const [url, out, w = '1600', h = '1000', waitMs = '7000', view = '', evalExpr = ''] = process.argv.slice(2);
const edge = ['C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Google/Chrome/Application/chrome.exe'].find(existsSync);
const port = 9333 + Math.floor(Math.random() * 500);
const proc = spawn(edge, [`--remote-debugging-port=${port}`, '--headless=new', '--disable-gpu', '--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--hide-scrollbars', `--window-size=${w},${h}`, '--no-first-run', '--user-data-dir=' + process.env.TEMP + '/nm-shot-' + port, 'about:blank'], { stdio: 'ignore' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let id = 0; const pending = new Map();
try {
  let targets;
  for (let i = 0; i < 40; i++) { try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); break; } catch { await sleep(250); } }
  const page = targets.find((t) => t.type === 'page');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  const logs = [];
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
    if (m.method === 'Runtime.consoleAPICalled' && ['error', 'warning'].includes(m.params.type)) logs.push(`[${m.params.type}] ` + m.params.args.map((a) => a.value ?? a.description ?? '').join(' '));
    if (m.method === 'Runtime.exceptionThrown') logs.push('[exception] ' + (m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text));
  };
  const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  await send('Runtime.enable'); await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: +w, height: +h, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url });
  await sleep(+waitMs);
  if (view) { await send('Runtime.evaluate', { expression: `document.querySelector('.nav-btn[data-view="${view}"]').click()` }); await sleep(3500); }
  if (evalExpr) {
    const r = await Promise.race([send('Runtime.evaluate', { expression: evalExpr, returnByValue: true, awaitPromise: true }), sleep(45000).then(() => null)]);
    console.log('eval', r ? JSON.stringify(r.result?.result?.value ?? r.result?.exceptionDetails?.text) : 'TIMEOUT (page unresponsive)');
  }
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(out, Buffer.from(shot.result.data, 'base64'));
  const metrics = await send('Runtime.evaluate', { expression: `JSON.stringify({scrollW: document.documentElement.scrollWidth, clientW: document.documentElement.clientWidth, globeCanvas: !!document.querySelector('.globe-host canvas'), conns: document.querySelector('#t-conns')?.textContent})`, returnByValue: true });
  console.log('metrics', metrics.result.result.value);
  console.log(logs.length ? logs.join('\n') : 'no console errors');
  ws.close();
} finally { proc.kill(); }
