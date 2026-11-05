import { resolve, relative, isAbsolute } from "node:path";

                                
                         
                                
                         
 

export class SandboxEnvironment {
          policy               ;

  constructor(policy                         = {}) {
    this.policy = {
      allowedRoots: (policy.allowedRoots ?? []).map((r) => resolve(r)),
      allowOutboundNetwork: policy.allowOutboundNetwork ?? false,
      maxMemoryBytes: policy.maxMemoryBytes ?? 512 * 1024 * 1024, // 512MB default
    };
  }

         validateFileSystemAccess(targetPath        )       {
    const absTarget = resolve(targetPath);
    let allowed = false;

    for (const root of this.policy.allowedRoots) {
      const rel = relative(root, absTarget);
      if (!rel.startsWith("..") && !isAbsolute(rel)) {
        allowed = true;
        break;
      }
    }

    if (!allowed && this.policy.allowedRoots.length > 0) {
      throw new Error(`Sandbox confinement violation: '${targetPath}' is outside authorized sandboxes [${this.policy.allowedRoots.join(", ")}]`);
    }
  }

         validateNetworkEgress(destinationHost        )       {
    if (!this.policy.allowOutboundNetwork) {
      throw new Error(`Sandbox network violation: outbound network prohibited (target: '${destinationHost}')`);
    }
  }

         getPolicy()                {
    return { ...this.policy };
  }
}
