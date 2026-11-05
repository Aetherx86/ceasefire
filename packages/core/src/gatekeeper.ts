import { randomUUID } from "node:crypto";

export type CapabilityPrivilege = "READ" | "WRITE" | "EXECUTE" | "ADMIN";

export interface CapabilityGrant {
  grantId: string;
  resourcePattern: string;
  privilege: CapabilityPrivilege;
  expiresAtMs: number;
}

export interface GatekeeperAction<TParams = unknown, TResult = unknown> {
  actionId: string;
  operation: string;
  parameters: TParams;
  submittedAtIso: string;
  status: "SIMULATED" | "APPROVED" | "REJECTED" | "COMMITTED";
  simulatedResult?: TResult;
  committedResult?: TResult;
}

/**
 * Ceasefire Gatekeeper Mesh: enforces local-first capability boundaries and non-blocking two-phase simulation.
 */
export class GatekeeperMesh {
  private grants: Map<string, CapabilityGrant> = new Map();
  private actionJournal: Map<string, GatekeeperAction> = new Map();

  public registerGrant(grant: Omit<CapabilityGrant, "grantId">): CapabilityGrant {
    const fullGrant: CapabilityGrant = {
      ...grant,
      grantId: `grant_${randomUUID().slice(0, 8)}`,
    };
    this.grants.set(fullGrant.grantId, fullGrant);
    return fullGrant;
  }

  public checkAccess(resource: string, privilege: CapabilityPrivilege): boolean {
    const now = Date.now();
    for (const grant of this.grants.values()) {
      if (grant.expiresAtMs > now && this.matchesPattern(resource, grant.resourcePattern)) {
        if (this.privilegeSatisfied(grant.privilege, privilege)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Proposes an action. Privileged mutations are simulated non-blockingly without halting execution.
   */
  public proposeAction<TParams, TResult>(
    operation: string,
    parameters: TParams,
    simulator: (p: TParams) => TResult
  ): GatekeeperAction<TParams, TResult> {
    const actionId = `act_${randomUUID().slice(0, 8)}`;
    const simulatedResult = simulator(parameters);

    const record: GatekeeperAction<TParams, TResult> = {
      actionId,
      operation,
      parameters,
      submittedAtIso: new Date().toISOString(),
      status: "SIMULATED",
      simulatedResult,
    };

    this.actionJournal.set(actionId, record as GatekeeperAction);
    return record;
  }

  public resolveAction(actionId: string, approve: boolean): GatekeeperAction {
    const action = this.actionJournal.get(actionId);
    if (!action) throw new Error(`Action '${actionId}' not found in journal`);

    if (action.status !== "SIMULATED") {
      throw new Error(`Action '${actionId}' is already resolved to '${action.status}'`);
    }

    if (approve) {
      action.status = "APPROVED";
      action.committedResult = action.simulatedResult;
    } else {
      action.status = "REJECTED";
    }

    return action;
  }

  public getPendingActions(): GatekeeperAction[] {
    return Array.from(this.actionJournal.values()).filter((a) => a.status === "SIMULATED");
  }

  private matchesPattern(resource: string, pattern: string): boolean {
    if (pattern === "*") return true;
    if (pattern.endsWith("*")) return resource.startsWith(pattern.slice(0, -1));
    return resource === pattern;
  }

  private privilegeSatisfied(granted: CapabilityPrivilege, requested: CapabilityPrivilege): boolean {
    const levels: Record<CapabilityPrivilege, number> = {
      READ: 1,
      WRITE: 2,
      EXECUTE: 3,
      ADMIN: 4,
    };
    return levels[granted] >= levels[requested];
  }
}
