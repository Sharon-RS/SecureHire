import { copyFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = path.join(projectRoot, "node_modules", "bootstrap", "dist");
const destination = path.join(projectRoot, "app", "static", "vendor", "bootstrap");

await mkdir(path.join(destination, "css"), { recursive: true });
await mkdir(path.join(destination, "js"), { recursive: true });
await copyFile(path.join(source, "css", "bootstrap.min.css"), path.join(destination, "css", "bootstrap.min.css"));
await copyFile(path.join(source, "js", "bootstrap.bundle.min.js"), path.join(destination, "js", "bootstrap.bundle.min.js"));
await copyFile(path.join(projectRoot, "node_modules", "bootstrap", "LICENSE"), path.join(destination, "LICENSE"));
console.log("Copied Bootstrap assets into app/static/vendor/bootstrap.");
