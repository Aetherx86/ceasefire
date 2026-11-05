import { readFile, open } from "node:fs/promises";

                                     
               
                    
                      
                   
                            
                         
 

                                       
                      
                      
                                            
                                      
                       
 

export const CANONICAL_FUSES                                                                                                   = {
  runAsNode: {
    wireIndex: 0,
    description: "Disable ELECTRON_RUN_AS_NODE environment variable",
    expected: false,
    critical: true,
  },
  enableCookieEncryption: {
    wireIndex: 1,
    description: "Enable platform cookie store encryption",
    expected: true,
    critical: false,
  },
  onlyLoadAppFromAsar: {
    wireIndex: 2,
    description: "Ensure application code only loads from app.asar",
    expected: true,
    critical: true,
  },
  loadBrowserProcessSpecificCode: {
    wireIndex: 3,
    description: "Restrict node_main to browser process",
    expected: true,
    critical: false,
  },
  enableNodeCliInspectArguments: {
    wireIndex: 4,
    description: "Disable --inspect and --inspect-brk debugging flags in release",
    expected: false,
    critical: true,
  },
  enableEmbeddedAsarIntegrityValidation: {
    wireIndex: 5,
    description: "Validate SHA-256 header and block hashes on app.asar",
    expected: true,
    critical: true,
  },
  onlyLoadAppFromAsarStrict: {
    wireIndex: 6,
    description: "Strict isolation refusing non-asar fallback directories",
    expected: true,
    critical: true,
  },
};

const FUSE_SENTINEL = Buffer.from("dL7nAb"); // Common Electron fuse magic prefix

/**
 * Inspects a native binary or Mach-O executable for Electron fuse wire configurations.
 */
export async function inspectElectronFuses(binaryPath        )                                {
  const violations           = [];
  const fuses                                     = {};

  let buffer        ;
  try {
    buffer = await readFile(binaryPath);
  } catch (err) {
    return {
      binaryPath,
      fusesFound: false,
      fuses: {},
      allSecurityCriticalPassing: false,
      violations: [`Unable to open binary: ${(err         ).message}`],
    };
  }

  const sentinelIndex = buffer.indexOf(FUSE_SENTINEL);
  if (sentinelIndex === -1) {
    // If sentinel isn't found, default all fuses to unconfigured (unsafe)
    for (const [key, meta] of Object.entries(CANONICAL_FUSES)) {
      fuses[key] = {
        name: key,
        wireIndex: meta.wireIndex,
        description: meta.description,
        enabled: false,
        securityCritical: meta.critical,
        recommendation: `Enable fuse in build tooling (current: unconfigured/absent)`,
      };
      if (meta.critical && meta.expected) {
        violations.push(`Critical fuse '${key}' is not active or fuse sentinel missing`);
      }
    }

    return {
      binaryPath,
      fusesFound: false,
      fuses,
      allSecurityCriticalPassing: false,
      violations,
    };
  }

  // Parse wire values from sentinel
  const fuseVersion = buffer[sentinelIndex + FUSE_SENTINEL.length];
  let criticalPass = true;

  for (const [key, meta] of Object.entries(CANONICAL_FUSES)) {
    const byteOffset = sentinelIndex + FUSE_SENTINEL.length + 1 + meta.wireIndex;
    const wireValue = byteOffset < buffer.length ? buffer[byteOffset] : 0x00;
    const isEnabled = wireValue === 0x31 || wireValue === 0x01; // '1' or 0x01

    const passed = isEnabled === meta.expected;
    if (!passed && meta.critical) {
      criticalPass = false;
      violations.push(`Fuse violation: '${key}' expected ${meta.expected} but was ${isEnabled}`);
    }

    fuses[key] = {
      name: key,
      wireIndex: meta.wireIndex,
      description: meta.description,
      enabled: isEnabled,
      securityCritical: meta.critical,
      recommendation: passed ? "Optimal security configuration" : `Toggle fuse to ${meta.expected}`,
    };
  }

  return {
    binaryPath,
    fusesFound: true,
    fuses,
    allSecurityCriticalPassing: criticalPass,
    violations,
  };
}
