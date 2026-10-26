// fix-logo.js — run with:  node fix-logo.js
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const root = __dirname;
const pub = path.join(root, 'public');

// 1) Find your logo (whatever it's currently called) and make clean copies
const candidates = ['logo.png', 'image.jpg.png', 'image.png', 'image.jpg'];
const found = candidates.find(f => fs.existsSync(path.join(pub, f)));
if (!found) {
  console.error('❌ No logo found inside the /public folder.');
  process.exit(1);
}
fs.copyFileSync(path.join(pub, found), path.join(pub, 'logo.png'));
fs.copyFileSync(path.join(pub, found), path.join(root, 'logo.png'));
console.log('✅ Logo copied to public/logo.png and logo.png (from ' + found + ')');

// 2) Fix every logo path in index.html
//    Tries /public/logo.png first, then /logo.png as a backup
const htmlPath = path.join(root, 'index.html');
let html = fs.readFileSync(htmlPath, 'utf8');
const OLD_IMG = 'src="public/image.jpg.png"';
const NEW_IMG = 'src="/public/logo.png" onerror="if(!this.dataset.t){this.dataset.t=1;this.src=\'/logo.png\'}"';
const count = html.split(OLD_IMG).length - 1;
html = html.split(OLD_IMG).join(NEW_IMG);
html = html.split("url('public/benedicto.jpg')").join("url('/public/benedicto.jpg')");
fs.writeFileSync(htmlPath, html);
console.log('✅ Fixed ' + count + ' logo reference(s) in index.html');

// 3) Force-add the files (works even if .gitignore is blocking them), commit, push
const run = cmd => execSync(cmd, { stdio: 'inherit', cwd: root });
const toAdd = ['public/logo.png', 'logo.png', 'public/benedicto.jpg', 'index.html']
  .filter(f => fs.existsSync(path.join(root, f)));
try {
  run('git add -f ' + toAdd.join(' '));
  try { run('git commit -m "Fix logo paths"'); } catch (e) { console.log('ℹ️ Nothing new to commit.'); }
  run('git push');
  console.log('\n🚀 Pushed! Wait for Render to show "Live", then test:');
  console.log('   https://benedictocollege-hrmss-1.onrender.com/public/logo.png');
} catch (e) {
  console.error('❌ Git step failed. Run these manually:\n   git add -f ' + toAdd.join(' ') + '\n   git commit -m "Fix logo paths"\n   git push');
}