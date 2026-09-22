const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');
const path = require('path');
const fs = require('fs');

module.exports = async function (context) {
  const { appOutDir, packager, electronPlatformName, arch } = context;
  const productName = packager.appInfo.productFilename;

  let extPath;
  if (electronPlatformName === 'darwin') {
    extPath = path.join(appOutDir, `${productName}.app`, 'Contents', 'MacOS', productName);
  } else if (electronPlatformName === 'win32') {
    extPath = path.join(appOutDir, `${productName}.exe`);
  } else {
    extPath = path.join(appOutDir, productName);
  }

  if (!fs.existsSync(extPath)) {
    console.warn(`[Fuses] Executable not found at ${extPath}, skipping fuse flipping.`);
    return;
  }

  console.log(`[Fuses] Hardening Electron binary with security fuses at: ${extPath}...`);

  try {
    await flipFuses(extPath, {
      version: FuseVersion.V1,
      [FuseV1Options.RunAsNode]: false,
      [FuseV1Options.EnableCookieEncryption]: true,
      [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
      [FuseV1Options.EnableNodeCliInspectArguments]: false,
      [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
      [FuseV1Options.OnlyLoadAppFromAsar]: true,
      resetAdHocDarwinSignature: electronPlatformName === 'darwin' && arch === 3,
    });

    console.log('[Fuses] ✓ Anti-debugging, anti-injection & ASAR integrity fuses permanently locked in executable!');
  } catch (err) {
    console.error('[Fuses] Failed to flip fuses:', err);
    // Do not throw to avoid failing unsupported build targets, but log loudly
  }
};
