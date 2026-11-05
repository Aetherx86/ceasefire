import { extractAsarArchive, type AsarExtractionResult } from "./asar.js";
import { inspectElectronFuses, type FuseInspectionReport } from "./fuses.js";
import { analyzeUnpackedAst, type AstAnalysisSummary } from "./rea-bridge.js";

export interface DefenseAttestationReport {
  timestamp: string;
  targetPath: string;
  isAsarArchive: boolean;
  extraction?: AsarExtractionResult;
  fuseReport?: FuseInspectionReport;
  astAnalysis: AstAnalysisSummary;
  overallVerdict: "PASS" | "WARN" | "BLOCK";
  blockingReasons: string[];
}

export interface AuditOptions {
  binaryPath?: string;
  strict?: boolean;
}

/**
 * Executes an end-to-end defensive audit against an ASAR archive or unpacked directory.
 */
export async function auditApplication(
  targetPath: string,
  options: AuditOptions = {}
): Promise<DefenseAttestationReport> {
  const isAsar = targetPath.endsWith(".asar");
  const blockingReasons: string[] = [];

  let extraction: AsarExtractionResult | undefined;
  let scanDir = targetPath;

  if (isAsar) {
    try {
      extraction = await extractAsarArchive(targetPath);
      scanDir = extraction.destinationDir;
      if (!extraction.unpackedCleanly) {
        blockingReasons.push("ASAR extraction encountered file system or traversal errors");
      }
    } catch (err) {
      blockingReasons.push(`Failed to extract ASAR archive: ${(err as Error).message}`);
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
  let fuseReport: FuseInspectionReport | undefined;
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

  let overallVerdict: "PASS" | "WARN" | "BLOCK" = "PASS";
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
