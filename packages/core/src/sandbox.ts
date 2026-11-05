import { resolve, relative, isAbsolute } from "node:path";

export interface SandboxPolicy {
  allowedRoots: string[];
  allowOutboundNetwork: boolean;
  maxMemoryBytes: number;
}

export class SandboxEnvironment {
  private policy: SandboxPolicy;

  constructor(policy: Partial<SandboxPolicy> = {}) {
    this.policy = {
      allowedRoots: (policy.allowedRoots ?? []).map((r) => resolve(r)),
      allowOutboundNetwork: policy.allowOutboundNetwork ?? false,
      maxMemoryBytes: policy.maxMemoryBytes ?? 512 * 1024 * 1024, // 512MB default
    };
  }

  public validateFileSystemAccess(targetPath: string): void {
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

  public validateNetworkEgress(destinationHost: string): void {
    if (!this.policy.allowOutboundNetwork) {
      throw new Error(`Sandbox network violation: outbound network prohibited (target: '${destinationHost}')`);
    }
  }

  public getPolicy(): SandboxPolicy {
    return { ...this.policy };
  }
}
