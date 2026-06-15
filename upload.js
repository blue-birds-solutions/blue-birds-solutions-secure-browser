const fs = require('fs');
const path = require('path');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

// 1. Parse .env file from the backend directory
function parseEnv() {
  const envPath = path.join(__dirname, '../backend/.env');
  if (!fs.existsSync(envPath)) {
    console.error(`[Upload] Error: .env file not found at ${envPath}`);
    process.exit(1);
  }

  const content = fs.readFileSync(envPath, 'utf8');
  const config = {};
  
  content.split('\n').forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    
    const index = trimmed.indexOf('=');
    if (index === -1) return;
    
    const key = trimmed.substring(0, index).trim();
    let val = trimmed.substring(index + 1).trim();
    
    // Strip surrounding quotes
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.substring(1, val.length - 1);
    }
    config[key] = val;
  });

  return config;
}

const env = parseEnv();

const requiredEnv = ['CLOUDFLARE_R2_ENDPOINT', 'CLOUDFLARE_R2_ACCESS_KEY_ID', 'CLOUDFLARE_R2_SECRET_ACCESS_KEY'];
const missing = requiredEnv.filter(k => !env[k]);
if (missing.length > 0) {
  console.error(`[Upload] Error: Missing R2 keys in backend/.env: ${missing.join(', ')}`);
  process.exit(1);
}

// 2. Initialize S3 client for R2
const s3Client = new S3Client({
  region: 'auto',
  endpoint: env.CLOUDFLARE_R2_ENDPOINT,
  credentials: {
    accessKeyId: env.CLOUDFLARE_R2_ACCESS_KEY_ID,
    secretAccessKey: env.CLOUDFLARE_R2_SECRET_ACCESS_KEY,
  },
});

const BUCKET_NAME = 'kalvion';
const RELEASE_DIR = path.join(__dirname, 'release');

// Helper to determine Content-Type
function getContentType(filename) {
  const ext = path.extname(filename).toLowerCase();
  switch (ext) {
    case '.yml':
    case '.yaml':
      return 'text/yaml';
    case '.dmg':
      return 'application/x-apple-diskimage';
    case '.exe':
      return 'application/x-msdownload';
    case '.blockmap':
      return 'application/octet-stream';
    case '.json':
      return 'application/json';
    default:
      return 'application/octet-stream';
  }
}

async function uploadFile(fileName) {
  const filePath = path.join(RELEASE_DIR, fileName);
  if (!fs.existsSync(filePath)) return;

  const fileStream = fs.createReadStream(filePath);
  const contentType = getContentType(fileName);
  
  console.log(`[Upload] Starting upload: ${fileName} (${contentType})...`);
  
  try {
    await s3Client.send(
      new PutObjectCommand({
        Bucket: BUCKET_NAME,
        Key: fileName,
        Body: fileStream,
        ContentType: contentType,
      })
    );
    console.log(`[Upload] Success: ${fileName} uploaded to R2 bucket "${BUCKET_NAME}"`);
  } catch (err) {
    console.error(`[Upload] Failed to upload ${fileName}:`, err);
    throw err;
  }
}

async function main() {
  if (!fs.existsSync(RELEASE_DIR)) {
    console.error(`[Upload] Error: Release directory not found at ${RELEASE_DIR}. Please run npm run build/dist first.`);
    process.exit(1);
  }

  const files = fs.readdirSync(RELEASE_DIR);
  // Upload only files matching installer extensions or metadata
  const targetFiles = files.filter(file => {
    const ext = path.extname(file).toLowerCase();
    return ['.dmg', '.exe', '.yml', '.blockmap'].includes(ext);
  });

  if (targetFiles.length === 0) {
    console.log('[Upload] No matching files (.dmg, .exe, .yml, .blockmap) found in release/.');
    return;
  }

  console.log(`[Upload] Found ${targetFiles.length} files to upload: ${targetFiles.join(', ')}`);

  for (const file of targetFiles) {
    await uploadFile(file);
  }

  console.log('[Upload] All files processed successfully!');
}

main().catch(err => {
  console.error('[Upload] Fatal error in main loop:', err);
  process.exit(1);
});
