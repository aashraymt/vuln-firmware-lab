// Render two terminal-style PNG "screenshots" from the captured output.
const { chromium } = require('playwright');

const C = { // simple ANSI-ish palette
  dim:'#7d8590', green:'#3fb950', cyan:'#39c5cf', red:'#f85149',
  yellow:'#d29922', fg:'#e6edf3', prompt:'#58a6ff', path:'#2ea043'
};

function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

// colourize a captured line for display
function color(line){
  let l = esc(line);
  l = l.replace(/\bPASS\b/g, `<span style="color:${C.green};font-weight:600">PASS</span>`);
  l = l.replace(/\bFAIL\b/g, `<span style="color:${C.red};font-weight:600">FAIL</span>`);
  l = l.replace(/ALL CHECKS PASSED/g, `<span style="color:${C.green};font-weight:700">ALL CHECKS PASSED</span>`);
  l = l.replace(/(13 passed, 0 failed)/g, `<span style="color:${C.green}">$1</span>`);
  l = l.replace(/^(== .* ==)$/g, `<span style="color:${C.cyan};font-weight:600">$1</span>`);
  l = l.replace(/(\[\+\])/g, `<span style="color:${C.green};font-weight:700">$1</span>`);
  l = l.replace(/(\[\*\])/g, `<span style="color:${C.cyan}">$1</span>`);
  l = l.replace(/(uid=0\(root\)[^<]*)/g, `<span style="color:${C.yellow};font-weight:600">$1</span>`);
  l = l.replace(/(SHELL via buffer @ 0x[0-9a-f]+)/g, `<span style="color:${C.green};font-weight:600">$1</span>`);
  l = l.replace(/(offset\s+: 72 bytes[^<]*)/g, `<span style="color:${C.fg}">$1</span>`);
  l = l.replace(/(\.\.\.tried[^<]*)/g, `<span style="color:${C.dim}">$1</span>`);
  return l;
}

function page(title, cmd, body){
  const lines = body.split('\n').map(color).join('<br>');
  return `<!doctype html><meta charset=utf-8><body style="margin:0">
  <div style="width:860px;background:#0d1117;border:1px solid #30363d;border-radius:10px;overflow:hidden;font-family:'SF Mono',ui-monospace,Menlo,Consolas,monospace">
    <div style="height:38px;background:#161b22;display:flex;align-items:center;padding:0 14px;border-bottom:1px solid #30363d">
      <span style="height:12px;width:12px;border-radius:50%;background:#ff5f56;margin-right:8px"></span>
      <span style="height:12px;width:12px;border-radius:50%;background:#ffbd2e;margin-right:8px"></span>
      <span style="height:12px;width:12px;border-radius:50%;background:#27c93f"></span>
      <span style="color:${C.dim};font-size:12.5px;margin-left:14px">${title}</span>
    </div>
    <div style="padding:16px 18px;font-size:13px;line-height:1.55;color:${C.fg};white-space:pre-wrap">
      <span style="color:${C.path}">aashray@vuln-fw</span><span style="color:${C.dim}">:</span><span style="color:${C.prompt}">~/vuln-firmware-lab</span><span style="color:${C.dim}">$</span> ${esc(cmd)}<br>${lines}
    </div>
  </div></body>`;
}

(async () => {
  const fs = require('fs');
  const verify = fs.readFileSync('/tmp/verify.out','utf8').trimEnd();
  const exploit = fs.readFileSync('/tmp/exploit.out','utf8').trimEnd();
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ deviceScaleFactor: 2 });
  for (const [name, title, cmd, body] of [
    ['verify_screenshot.png','make verify','make verify', verify],
    ['exploit_screenshot.png','make exploit','python3 exploit/exploit.py', exploit],
  ]) {
    const p = await ctx.newPage();
    await p.setContent(page(title, cmd, body), { waitUntil:'networkidle' });
    const el = await p.$('div');
    await el.screenshot({ path: '/home/claude/vuln-firmware-lab/docs/evidence/'+name });
    console.log('wrote', name);
    await p.close();
  }
  await browser.close();
})();
