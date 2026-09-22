const fs = require('fs');
const path = require('path');
const JavaScriptObfuscator = require('javascript-obfuscator');

const DIST_DIR = path.join(__dirname, '..', 'dist');

const OBFUSCATOR_OPTIONS = {
  target: 'node',
  compact: true,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.75,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.3,
  stringArray: true,
  stringArrayEncoding: ['base64'],
  stringArrayThreshold: 0.8,
  transformObjectKeys: true,
  numbersToExpressions: true,
  splitStrings: true,
  splitStringsChunkLength: 6,
  renameGlobals: false,
  selfDefending: false, // Set false to ensure compatibility with Electron IPC hooks
  disableConsoleOutput: false, // Keep stdout intact for critical security logs
};

function obfuscateFile(filePath) {
  if (!fs.existsSync(filePath)) {
    console.warn(`[Obfuscate] Skipping non-existent file: ${filePath}`);
    return;
  }
  console.log(`[Obfuscate] Hardening and obfuscating: ${path.basename(filePath)}...`);
  const code = fs.readFileSync(filePath, 'utf8');
  const obfuscatedResult = JavaScriptObfuscator.obfuscate(code, OBFUSCATOR_OPTIONS);
  fs.writeFileSync(filePath, obfuscatedResult.getObfuscatedCode(), 'utf8');
  console.log(`[Obfuscate] ✓ Successfully protected ${path.basename(filePath)}`);
}

function cleanSourceMaps(dir) {
  if (!fs.existsSync(dir)) return;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      cleanSourceMaps(fullPath);
    } else if (entry.name.endsWith('.map') || entry.name.endsWith('.d.ts')) {
      fs.unlinkSync(fullPath);
      console.log(`[Obfuscate] Removed debug artifact: ${entry.name}`);
    }
  }
}

function main() {
  console.log('[Obfuscate] Starting Bluebirds Secure Browser security hardening...');
  
  // 1. Obfuscate main.js and preload.js
  obfuscateFile(path.join(DIST_DIR, 'main.js'));
  obfuscateFile(path.join(DIST_DIR, 'preload.js'));

  // 2. Remove source maps and type definitions
  cleanSourceMaps(DIST_DIR);

  console.log('[Obfuscate] Security hardening complete.');
}

main();
