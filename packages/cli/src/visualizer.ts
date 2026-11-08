export interface AttackDefenseEvent {
  phase: string;
  offenseVector: string;
  defenseMechanism: string;
  status: "INTERCEPTED" | "BLOCKED" | "QUARANTINED" | "MITIGATED";
  details: string;
}

/**
 * Terminal visualizer rendering Red Team simulated attacks vs Blue Team defensive intercepts.
 */
export function renderAttackDefenseMatrix(events: AttackDefenseEvent[]): string {
  const lines: string[] = [];
  lines.push("┌────────────────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  CEASEFIRE SANDBOXED ATTACK & DEFENSE SIMULATION VISUALIZER                            │");
  lines.push("├──────────────────────┬───────────────────────────┬──────────────────────────┬──────────┤");
  lines.push("│ Attack Phase         │ Red Team Attack Vector    │ Blue Team Defense Counter│ Status   │");
  lines.push("├──────────────────────┼───────────────────────────┼──────────────────────────┼──────────┤");

  for (const ev of events) {
    const phase = pad(ev.phase, 20);
    const offense = pad(ev.offenseVector, 25);
    const defense = pad(ev.defenseMechanism, 24);
    const status = pad(ev.status, 8);
    lines.push(`│ ${phase} │ ${offense} │ ${defense} │ ${status} │`);
  }

  lines.push("└──────────────────────┴───────────────────────────┴──────────────────────────┴──────────┘");
  return lines.join("\n");
}

function pad(str: string, length: number): string {
  if (str.length > length) {
    return str.slice(0, length - 3) + "...";
  }
  return str.padEnd(length, " ");
}
