import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

                                        
               
                
                                                   
                                                                                               
                      
                   
 

                                     
                       
                      
                                  
                                   
 

/**
 * REA-inspired heuristic and static AST scanner for extracted JavaScript / TypeScript modules.
 */
export async function analyzeUnpackedAst(extractedDir        )                              {
  const alerts                          = [];
  let scannedFiles = 0;

  async function walk(dir        ) {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "node_modules" && !entry.name.startsWith(".")) {
          await walk(fullPath);
        }
      } else if (entry.isFile() && /\.(js|cjs|mjs|ts|html)$/i.test(entry.name)) {
        scannedFiles++;
        const content = await readFile(fullPath, "utf-8");
        const lines = content.split("\n");

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const lineNum = i + 1;

          // Check for nodeIntegration: true
          if (/nodeIntegration\s*:\s*true/i.test(line)) {
            alerts.push({
              file: fullPath,
              line: lineNum,
              severity: "CRITICAL",
              category: "ELECTRON_MISCONFIG",
              description: "nodeIntegration is explicitly enabled; renderer has direct OS access.",
              snippet: line.trim(),
            });
          }

          // Check for contextIsolation: false
          if (/contextIsolation\s*:\s*false/i.test(line)) {
            alerts.push({
              file: fullPath,
              line: lineNum,
              severity: "CRITICAL",
              category: "ELECTRON_MISCONFIG",
              description: "contextIsolation is disabled; prototype pollution can bridge renderer to preload.",
              snippet: line.trim(),
            });
          }

          // Check for unvalidated remote code evaluation: eval(), new Function()
          if (/\b(?:eval|new\s+Function)\s*\(/i.test(line) && !line.includes("// ceasefire:ignore")) {
            alerts.push({
              file: fullPath,
              line: lineNum,
              severity: "HIGH",
              category: "REMOTE_CODE_EXEC",
              description: "Dynamic code generation or eval invocation detected.",
              snippet: line.trim(),
            });
          }

          // Check for unsafe shell.openExternal without protocol filtering
          if (/shell\.openExternal\s*\(/i.test(line)) {
            alerts.push({
              file: fullPath,
              line: lineNum,
              severity: "HIGH",
              category: "ELECTRON_MISCONFIG",
              description: "shell.openExternal sink detected; requires strict http/https protocol whitelist.",
              snippet: line.trim(),
            });
          }

          // Check for raw ipcRenderer sendSync
          if (/ipcRenderer\.sendSync\s*\(/i.test(line)) {
            alerts.push({
              file: fullPath,
              line: lineNum,
              severity: "MEDIUM",
              category: "IPC_EXPOSURE",
              description: "Synchronous IPC communication detected; potential denial-of-service vector.",
              snippet: line.trim(),
            });
          }
        }
      }
    }
  }

  await walk(extractedDir);

  // Compute security score: starts at 100, drops per alert severity
  let penalty = 0;
  for (const alert of alerts) {
    if (alert.severity === "CRITICAL") penalty += 35;
    else if (alert.severity === "HIGH") penalty += 15;
    else if (alert.severity === "MEDIUM") penalty += 5;
    else penalty += 2;
  }

  const securityScore = Math.max(0, 100 - penalty);

  return {
    scannedFiles,
    totalAlerts: alerts.length,
    alerts,
    securityScore,
  };
}
