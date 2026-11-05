import { extractAsarArchive,                           } from "./asar.js";
import { inspectElectronFuses,                           } from "./fuses.js";
import { analyzeUnpackedAst,                         } from "./rea-bridge.js";

                                           
                    
                     
                         
                                    
                                    
                                  
                                            
                            
 

                               
                      
                   
 

/**
 * Executes an end-to-end defensive audit against an ASAR archive or unpacked directory.
 */
export async function auditApplication(
  targetPath        ,
  options               = {}
)                                    {
  const isAsar = targetPath.endsWith(".asar");
  const blockingReasons           = [];

  let extraction                                  ;
  let scanDir = targetPath;

  if (isAsar) {
    try {
      extraction = await extractAsarArchive(targetPath);
      scanDir = extraction.destinationDir;
      if (!extraction.unpackedCleanly) {
        blockingReasons.push("ASAR extraction encountered file system or traversal errors");
      }
    } catch (err) {
      blockingReasons.push(`Failed to extract ASAR archive: ${(err         ).message}`);
      return {
        timestamp: new Date().toISOString(),
        targetPath,
        isAsarArchive: true,
        astAnalysis: { scannedFiles: 0, totalAlerts: 0, alerts: [], securityScore: 0 },
        overallVerdict: "BLOCK",
        blockingReasons,
      };
    }
  }

  // Inspect Fuses if binaryPath is provided
  let fuseReport                                  ;
  if (options.binaryPath) {
    fuseReport = await inspectElectronFuses(options.binaryPath);
    if (!fuseReport.allSecurityCriticalPassing) {
      blockingReasons.push(...fuseReport.violations);
    }
  }

  // Run AST Analysis
  const astAnalysis = await analyzeUnpackedAst(scanDir);
  for (const alert of astAnalysis.alerts) {
    if (alert.severity === "CRITICAL") {
      blockingReasons.push(`[${alert.category}] ${alert.description} in ${alert.file}:${alert.line}`);
    }
  }

  let overallVerdict                            = "PASS";
  if (blockingReasons.length > 0) {
    overallVerdict = "BLOCK";
  } else if (astAnalysis.securityScore < 85) {
    overallVerdict = "WARN";
  }

  return {
    timestamp: new Date().toISOString(),
    targetPath,
    isAsarArchive: isAsar,
    extraction,
    fuseReport,
    astAnalysis,
    overallVerdict,
    blockingReasons,
  };
}
