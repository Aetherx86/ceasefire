import { randomUUID } from "node:crypto";

                                                                         

                                  
                  
                          
                                 
                      
 

                                                                         
                   
                    
                      
                         
                                                              
                            
                            
 

/**
 * Ceasefire Gatekeeper Mesh: enforces local-first capability boundaries and non-blocking two-phase simulation.
 */
export class GatekeeperMesh {
          grants                               = new Map();
          actionJournal                                = new Map();

         registerGrant(grant                                  )                  {
    const fullGrant                  = {
      ...grant,
      grantId: `grant_${randomUUID().slice(0, 8)}`,
    };
    this.grants.set(fullGrant.grantId, fullGrant);
    return fullGrant;
  }

         checkAccess(resource        , privilege                     )          {
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
         proposeAction                  (
    operation        ,
    parameters         ,
    simulator                         
  )                                     {
    const actionId = `act_${randomUUID().slice(0, 8)}`;
    const simulatedResult = simulator(parameters);

    const record                                     = {
      actionId,
      operation,
      parameters,
      submittedAtIso: new Date().toISOString(),
      status: "SIMULATED",
      simulatedResult,
    };

    this.actionJournal.set(actionId, record                    );
    return record;
  }

         resolveAction(actionId        , approve         )                   {
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

         getPendingActions()                     {
    return Array.from(this.actionJournal.values()).filter((a) => a.status === "SIMULATED");
  }

          matchesPattern(resource        , pattern        )          {
    if (pattern === "*") return true;
    if (pattern.endsWith("*")) return resource.startsWith(pattern.slice(0, -1));
    return resource === pattern;
  }

          privilegeSatisfied(granted                     , requested                     )          {
    const levels                                      = {
      READ: 1,
      WRITE: 2,
      EXECUTE: 3,
      ADMIN: 4,
    };
    return levels[granted] >= levels[requested];
  }
}
