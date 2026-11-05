import { spawn } from "node:child_process";
import { mkdtemp, rm, readdir, readFile, stat } from "node:fs/promises";
import { join, resolve, relative, isAbsolute } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";

                                     
               
               
                 
 

                                       
                      
                         
                     
                     
                                 
                        
                           
                   
 

/**
 * Validates that an extraction target path does not escape the destination directory.
 */
export function assertPathConfinement(targetPath        , rootDir        )       {
  const resolvedTarget = resolve(rootDir, targetPath);
  const resolvedRoot = resolve(rootDir);
  const rel = relative(resolvedRoot, resolvedTarget);

  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`Path traversal escape detected: '${targetPath}' resolves outside '${rootDir}'`);
  }
}

/**
 * Extracts an ASAR archive atomically to a dedicated scratch or destination directory.
 */
export async function extractAsarArchive(
  archivePath        ,
  explicitDestDir         
)                                {
  const destDir = explicitDestDir ?? (await mkdtemp(join(tmpdir(), "ceasefire-asar-extract-")));
  const errors           = [];

  // Compute overall archive SHA-256 digest
  const archiveBuffer = await readFile(archivePath);
  const archiveDigest = createHash("sha256").update(archiveBuffer).digest("hex");

  // Execute extraction via npx @electron/asar extract
  await new Promise      ((res, rej) => {
    const child = spawn("npx", ["@electron/asar", "extract", resolve(archivePath), resolve(destDir)], {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("close", (code) => {
      if (code === 0) {
        res();
      } else {
        rej(new Error(`npx @electron/asar extract failed with code ${code}: ${stderr}`));
      }
    });

    child.on("error", (err) => {
      rej(err);
    });
  });

  // Build recursive manifest and check for path traversals
  const manifest                       = [];
  let totalBytes = 0;

  async function walk(dir        , relPrefix = "") {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      const relPath = join(relPrefix, entry.name);

      assertPathConfinement(relPath, destDir);

      if (entry.isDirectory()) {
        await walk(fullPath, relPath);
      } else if (entry.isFile()) {
        const fileStat = await stat(fullPath);
        const fileBytes = await readFile(fullPath);
        const fileHash = createHash("sha256").update(fileBytes).digest("hex");

        totalBytes += fileStat.size;
        manifest.push({
          path: relPath,
          size: fileStat.size,
          sha256: fileHash,
        });
      }
    }
  }

  try {
    await walk(destDir);
  } catch (err) {
    errors.push(`Manifest scan failure: ${(err         ).message}`);
  }

  return {
    archivePath,
    destinationDir: destDir,
    totalFiles: manifest.length,
    totalBytes,
    manifest,
    archiveDigest,
    unpackedCleanly: errors.length === 0,
    errors,
  };
}
