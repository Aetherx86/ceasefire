#!/usr/bin/env node

import { auditApplication, extractAsarArchive } from "@ceasefire/defender";
import { detectChallenge, HysteresisTracker } from "@ceasefire/waf";
import { renderAttackDefenseMatrix,                         } from "./visualizer.js";

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "--help" || command === "-h") {
    printHelp();
    process.exit(0);
  }

  if (command === "extract") {
    const inputIdx = args.indexOf("--input");
    const targetIdx = args.indexOf("--target");
    if (inputIdx === -1 || !args[inputIdx + 1]) {
      console.error("Error: --input <path-to-asar> is required");
      process.exit(1);
    }
    const input = args[inputIdx + 1];
    const target = targetIdx !== -1 ? args[targetIdx + 1] : undefined;

    console.log(`Extracting ASAR archive: ${input}...`);
    try {
      const res = await extractAsarArchive(input, target);
      console.log(`Successfully unpacked ${res.totalFiles} files (${res.totalBytes} bytes) to ${res.destinationDir}`);
      console.log(`SHA-256 Digest: ${res.archiveDigest}`);
      process.exit(0);
    } catch (err) {
      console.error(`Extraction failed: ${(err         ).message}`);
      process.exit(1);
    }
  }

  if (command === "audit") {
    const inputIdx = args.indexOf("--input");
    const binaryIdx = args.indexOf("--binary");
    if (inputIdx === -1 || !args[inputIdx + 1]) {
      console.error("Error: --input <path> is required");
      process.exit(1);
    }
    const input = args[inputIdx + 1];
    const binary = binaryIdx !== -1 ? args[binaryIdx + 1] : undefined;

    console.log(`Auditing target: ${input}...`);
    const report = await auditApplication(input, { binaryPath: binary });
    console.log(JSON.stringify(report, null, 2));

    if (report.overallVerdict === "BLOCK") {
      process.exit(2);
    }
    process.exit(0);
  }

  if (command === "visualize") {
    const events                       = [
      {
        phase: "Initial Ingestion",
        offenseVector: "Trojanized app.asar payload",
        defenseMechanism: "Atomic Sandboxed Unpacker",
        status: "QUARANTINED",
        details: "Path-confinement asserted; temp scratch isolated",
      },
      {
        phase: "Archive Traversals",
        offenseVector: "Directory slip (../evil.js)",
        defenseMechanism: "assertPathConfinement Guard",
        status: "BLOCKED",
        details: "Refused escape from scratch boundary",
      },
      {
        phase: "Runtime Execution",
        offenseVector: "ELECTRON_RUN_AS_NODE bypass",
        defenseMechanism: "Binary Electron Fuse Check",
        status: "BLOCKED",
        details: "onlyLoadAppFromAsar missing or disabled",
      },
      {
        phase: "AST Injection Sink",
        offenseVector: "nodeIntegration: true injection",
        defenseMechanism: "REA Static Application Graph",
        status: "INTERCEPTED",
        details: "Disallowed renderer root privileges",
      },
      {
        phase: "Edge WAF Evasion",
        offenseVector: "Rapid Turnstile header spoofing",
        defenseMechanism: "Deterministic DFA & Hysteresis",
        status: "MITIGATED",
        details: "Quarantined via rolling confirm ticks",
      },
    ];

    console.log(renderAttackDefenseMatrix(events));
    process.exit(0);
  }

  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exit(1);
}

function printHelp() {
  console.log(`
Ceasefire (@ceasefire/cli) - Sovereign Edge Runtime & Capability Defense Architecture

Usage:
  ceasefire extract --input <archive.asar> [--target <dir>]
  ceasefire audit --input <app.asar|dir> [--binary <bin>] [--strict]
  ceasefire inspect-waf --headers <headers.json> [--body <body>]
  ceasefire visualize
  ceasefire --help
`);
}

main().catch((err) => {
  console.error(`Ceasefire CLI Error: ${err.message}`);
  process.exit(1);
});
