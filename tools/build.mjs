import { readdir, readFile, writeFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { stripTypeScriptTypes } from "node:module";

async function buildAll() {
  const packages = ["core", "defender", "waf", "cli"];

  for (const pkg of packages) {
    const srcDir = join("packages", pkg, "src");
    const distDir = join("packages", pkg, "dist");
    await mkdir(distDir, { recursive: true });

    let entries;
    try {
      entries = await readdir(srcDir);
    } catch {
      continue;
    }

    for (const file of entries) {
      if (file.endsWith(".ts")) {
        const fullSrc = join(srcDir, file);
        const code = await readFile(fullSrc, "utf-8");
        const stripped = stripTypeScriptTypes(code, { mode: "strip" });

        // Write directly as .js in srcDir for ES module resolution
        const destJs = join(srcDir, file.replace(/\.ts$/, ".js"));
        await writeFile(destJs, stripped, "utf-8");

        // Also write to distDir as .mjs
        const distMjs = join(distDir, file.replace(/\.ts$/, ".mjs"));
        await writeFile(distMjs, stripped, "utf-8");
      }
    }
  }

  console.log("✅ Ceasefire: all packages compiled and types stripped via Node built-ins.");
}

buildAll().catch((err) => {
  console.error("Build failed:", err);
  process.exit(1);
});
