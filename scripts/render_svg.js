// Render terminal-style SVG "screenshots" from captured output (text-based,
// uploadable to Notion via the attachment content path).
const fs = require('fs');

const C = { bg:'#0d1117', bar:'#161b22', border:'#30363d',
  dim:'#7d8590', green:'#3fb950', cyan:'#39c5cf', red:'#f85149',
  yellow:'#d29922', fg:'#e6edf3', prompt:'#58a6ff', path:'#2ea043' };

const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

// Turn one raw line into SVG tspans with color.
function spans(line){
  let l = esc(line);
  l = l.replace(/\bPASS\b/g, `<tspan fill="${C.green}" font-weight="600">PASS</tspan>`);
  l = l.replace(/\bFAIL\b/g, `<tspan fill="${C.red}" font-weight="600">FAIL</tspan>`);
  l = l.replace(/ALL CHECKS PASSED/g, `<tspan fill="${C.green}" font-weight="700">ALL CHECKS PASSED</tspan>`);
  l = l.replace(/(13 passed, 0 failed)/g, `<tspan fill="${C.green}">$1</tspan>`);
  l = l.replace(/^(== .* ==)$/,  `<tspan fill="${C.cyan}" font-weight="600">$1</tspan>`);
  l = l.replace(/(\[\+\])/g, `<tspan fill="${C.green}" font-weight="700">$1</tspan>`);
  l = l.replace(/(\[\*\])/g, `<tspan fill="${C.cyan}">$1</tspan>`);
  l = l.replace(/(uid=0\(root\)[^<]*)/g, `<tspan fill="${C.yellow}" font-weight="600">$1</tspan>`);
  l = l.replace(/(SHELL via buffer @ 0x[0-9a-f]+)/g, `<tspan fill="${C.green}" font-weight="600">$1</tspan>`);
  l = l.replace(/(\.\.\.tried[^<]*)/g, `<tspan fill="${C.dim}">$1</tspan>`);
  return l;
}

function render(cmd, body){
  const lines = body.split('\n');
  const W = 860, padX = 20, barH = 40, padTop = 54, lh = 22, fs = 13.5, padBot = 20;
  const promptSvg = `<tspan fill="${C.path}">aashray@vuln-fw</tspan>`
    + `<tspan fill="${C.dim}">:</tspan>`
    + `<tspan fill="${C.prompt}">~/vuln-firmware-lab</tspan>`
    + `<tspan fill="${C.dim}">$</tspan> `
    + `<tspan fill="${C.fg}">${esc(cmd)}</tspan>`;
  const all = [promptSvg, ...lines.map(spans)];
  const H = padTop + all.length*lh + padBot;
  const text = all.map((s,i)=>
    `<text x="${padX}" y="${padTop + i*lh}" xml:space="preserve" fill="${C.fg}">${s}</text>`
  ).join('\n');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,'DejaVu Sans Mono',monospace" font-size="${fs}">
  <rect x="0.5" y="0.5" width="${W-1}" height="${H-1}" rx="10" fill="${C.bg}" stroke="${C.border}"/>
  <path d="M0 ${barH} V10 a10 10 0 0 1 10 -10 H${W-10} a10 10 0 0 1 10 10 V${barH} Z" fill="${C.bar}"/>
  <line x1="0" y1="${barH}" x2="${W}" y2="${barH}" stroke="${C.border}"/>
  <circle cx="20" cy="20" r="6" fill="#ff5f56"/><circle cx="40" cy="20" r="6" fill="#ffbd2e"/><circle cx="60" cy="20" r="6" fill="#27c93f"/>
  <text x="84" y="24.5" fill="${C.dim}" font-size="12.5">${esc(cmd)}</text>
  ${text}
</svg>`;
}

const verify = fs.readFileSync('/tmp/verify.out','utf8').trimEnd();
const exploit = fs.readFileSync('/tmp/exploit.out','utf8').trimEnd();
fs.writeFileSync('docs/evidence/verify_screenshot.svg', render('make verify', verify));
fs.writeFileSync('docs/evidence/exploit_screenshot.svg', render('python3 exploit/exploit.py', exploit));
console.log('wrote verify_screenshot.svg', fs.statSync('docs/evidence/verify_screenshot.svg').size, 'bytes');
console.log('wrote exploit_screenshot.svg', fs.statSync('docs/evidence/exploit_screenshot.svg').size, 'bytes');
