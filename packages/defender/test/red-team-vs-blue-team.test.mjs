import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { assertPathConfinement } from "../src/asar.js";
import { analyzeUnpackedAst } from "../src/rea-bridge.js";
import { inspectElectronFuses, CANONICAL_FUSES } from "../src/fuses.js";
import { detectChallenge, HysteresisTracker, signEnvelope, verifySignature } from "../../waf/src/index.js";
import { GatekeeperMesh, SandboxEnvironment } from "../../core/src/index.js";
import { renderAttackDefenseMatrix } from "../../cli/src/visualizer.js";

describe("🔥 Ceasefire Sandboxed Adversarial Suite: Red Team vs. Blue Team", () => {
  const events = [];

  it("Scenario 1 [Offense: Path Traversal Slip] vs. [Defense: Confinement Barrier]", async () => {
    const sandboxDir = await mkdtemp(join(tmpdir(), "ceasefire-test-sandbox-"));

    try {
      // Red Team: tries to resolve a path outside the destination root
      const maliciousPath = "../../etc/shadow";

      assert.throws(
        () => {
          assertPathConfinement(maliciousPath, sandboxDir);
        },
        /Path traversal escape detected/,
        "Blue Team must throw a traversal error"
      );

      events.push({
        phase: "Path Confinement",
        offenseVector: "Directory slip: ../../etc/shadow",
        defenseMechanism: "assertPathConfinement()",
        status: "BLOCKED",
        details: "Prevented arbitrary filesystem escape outside sandbox root",
      });
    } finally {
      await rm(sandboxDir, { recursive: true, force: true });
    }
  });

  it("Scenario 2 [Offense: Injected nodeIntegration & eval] vs. [Defense: REA AST Gate]", async () => {
    const sandboxDir = await mkdtemp(join(tmpdir(), "ceasefire-test-ast-"));

    try {
      // Red Team: Crafts a trojanized renderer configuration
      const maliciousCode = `
        const mainWindow = new BrowserWindow({
          webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
          }
        });
        eval("require('child_process').execSync('id')");
      `;

      await writeFile(join(sandboxDir, "injected_main.js"), maliciousCode);

      // Blue Team: Scans the directory using REA static AST analysis
      const analysis = await analyzeUnpackedAst(sandboxDir);

      assert.equal(analysis.scannedFiles, 1);
      assert.ok(analysis.totalAlerts >= 3, "Expected at least 3 critical/high alerts");
      assert.ok(analysis.securityScore <= 30, `Security score should be penalised heavily: got ${analysis.securityScore}`);

      const hasNodeIntegrationAlert = analysis.alerts.some(
        (a) => a.category === "ELECTRON_MISCONFIG" && a.snippet?.includes("nodeIntegration")
      );
      assert.ok(hasNodeIntegrationAlert, "Expected nodeIntegration alert");

      events.push({
        phase: "AST Inspection",
        offenseVector: "nodeIntegration + eval() injection",
        defenseMechanism: "analyzeUnpackedAst() Gate",
        status: "INTERCEPTED",
        details: `Security score collapsed to ${analysis.securityScore}/100, flagged critical misconfigs`,
      });
    } finally {
      await rm(sandboxDir, { recursive: true, force: true });
    }
  });

  it("Scenario 3 [Offense: Unsigned Binary / Stripped Fuses] vs. [Defense: Fuse Verifier]", async () => {
    const sandboxDir = await mkdtemp(join(tmpdir(), "ceasefire-test-fuse-"));

    try {
      // Red Team: An executable without the Electron fuse sentinel
      const dummyBinPath = join(sandboxDir, "unsigned_electron");
      await writeFile(dummyBinPath, Buffer.from("DUMMY_UNFUSED_BINARY_PAYLOAD"));

      // Blue Team: Inspects binary fuses
      const fuseReport = await inspectElectronFuses(dummyBinPath);

      assert.equal(fuseReport.fusesFound, false, "No fuse sentinel should be recognized");
      assert.equal(fuseReport.allSecurityCriticalPassing, false, "Security critical must fail on unfused binary");
      assert.ok(fuseReport.violations.length > 0, "Violations must be logged");

      events.push({
        phase: "Binary Hardening",
        offenseVector: "Unfused / Stripped Electron binary",
        defenseMechanism: "inspectElectronFuses() Sentinel",
        status: "BLOCKED",
        details: "Refused execution due to missing embedded ASAR integrity fuse",
      });
    } finally {
      await rm(sandboxDir, { recursive: true, force: true });
    }
  });

  it("Scenario 4 [Offense: Rapid WAF Flap & Turnstile Evasion] vs. [Defense: DFA Hysteresis]", () => {
    // Red Team: Simulates intermittent CDN caching flap (stock available -> unavailable -> available)
    const tracker = new HysteresisTracker(false, { restockConfirmTicks: 2, outOfStockConfirmTicks: 2 });

    // Tick 1: Attacker attempts single-tick ghost restock
    const tick1 = tracker.observe(true);
    assert.equal(tick1.currentEffectiveValue, false, "Tick 1 must remain unconfirmed (flap suppressed)");
    assert.equal(tick1.isFlapSuppressed, true);

    // Tick 2: Attacker sustains stock state -> now confirmed
    const tick2 = tracker.observe(true);
    assert.equal(tick2.currentEffectiveValue, true, "Tick 2 confirmed restock");
    assert.equal(tick2.isFlapSuppressed, false);

    // Red Team: Sends Turnstile challenge response
    const challenge = detectChallenge(403, { server: "cloudflare", "cf-mitigated": "challenge" }, "<html>__cf_chl_opt</html>");
    assert.equal(challenge.vendor, "cloudflare");
    assert.equal(challenge.isChallengeInterstitial, true);

    events.push({
      phase: "Edge WAF Evasion",
      offenseVector: "Single-tick CDN state spoofing",
      defenseMechanism: "HysteresisTracker & DFA",
      status: "MITIGATED",
      details: "Single-tick flap successfully quarantined; Turnstile challenge detected",
    });
  });

  it("Scenario 5 [Offense: Privilege Escalation] vs. [Defense: Gatekeeper Capability Fence]", () => {
    const mesh = new GatekeeperMesh();

    // Red Team: Attempts to execute an admin action without any capability grant
    const hasAdminAccess = mesh.checkAccess("system/kernel", "ADMIN");
    assert.equal(hasAdminAccess, false, "Must deny unauthorized capability request");

    // Red Team: Proposes privileged mutation -> Blue Team traps it into simulation
    const action = mesh.proposeAction("database/drop_table", { table: "users" }, () => ({
      simulatedOutcome: "table dropped (virtual)",
    }));

    assert.equal(action.status, "SIMULATED");
    assert.deepEqual(action.simulatedResult, { simulatedOutcome: "table dropped (virtual)" });

    // Operator rejects the red team action
    const resolved = mesh.resolveAction(action.actionId, false);
    assert.equal(resolved.status, "REJECTED");

    events.push({
      phase: "Privilege Escalation",
      offenseVector: "Unauthorized database/drop_table call",
      defenseMechanism: "Gatekeeper Non-Blocking Mesh",
      status: "BLOCKED",
      details: "Trapped mutation in virtual simulation; operator rejected execution",
    });

    // Output live terminal visualization of all attack phases
    console.log("\n" + renderAttackDefenseMatrix(events) + "\n");
  });
});
