// Local Markdown files/fragments only; this does not fetch external URLs.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve, extname } from "node:path";

const files = process.argv.slice(2);
if (!files.length) files.push(...execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" }).split("\0").filter(p => /\.md$/i.test(p)));
const withoutCode = text => text.replace(/^\s*(`{3,}|~{3,})[^\n]*\n[\s\S]*?^\s*\1\s*$/gm, "");
const slug = text => text.toLowerCase().replace(/\[([^\]]+)\]\([^)]*\)/g, "$1").replace(/<[^>]*>/g, "").replace(/[^\p{L}\p{M}\p{N}_\-\s]/gu, "").replace(/\s/g, "-");
const anchorCache = new Map();
function anchors(file) {
  if (anchorCache.has(file)) return anchorCache.get(file);
  const text = withoutCode(readFileSync(file, "utf8"));
  const result = new Set(), counts = new Map();
  for (const match of text.matchAll(/^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$/gm)) {
    const base = slug(match[1]), count = counts.get(base) ?? 0;
    result.add(count ? `${base}-${count}` : base); counts.set(base, count + 1);
  }
  for (const match of text.matchAll(/<(?:a|[a-z][\w-]*)\b[^>]*\b(?:id|name)=["']([^"']+)["']/gi)) result.add(match[1]);
  anchorCache.set(file, result); return result;
}
let checked = 0, failures = 0;
function check(file, target, offset, original) {
  if (/^(?:[a-z][a-z\d+.-]*:|\/\/)/i.test(target)) return;
  const line = original.slice(0, offset).split("\n").length;
  const fail = reason => { console.error(`${file}:${line}: ${target}: ${reason}`); failures++; };
  let path, fragment;
  try { const hash = target.indexOf("#"); path = decodeURIComponent((hash < 0 ? target : target.slice(0, hash)).split("?")[0]); fragment = hash < 0 ? "" : decodeURIComponent(target.slice(hash + 1)); }
  catch { fail("invalid URL encoding"); return; }
  const destination = path ? resolve(dirname(file), path) : resolve(file);
  checked++;
  if (!existsSync(destination)) { fail("missing file"); return; }
  if (fragment && extname(destination).toLowerCase() === ".md" && !anchors(destination).has(fragment)) fail("missing heading/anchor");
}
for (const file of files) {
  if (!existsSync(file)) continue; // An unstaged deletion may remain in the index.
  const original = readFileSync(file, "utf8");
  // Keep offsets stable when excluding fenced examples.
  const text = original.replace(/^\s*(`{3,}|~{3,})[^\n]*\n[\s\S]*?^\s*\1\s*$/gm, block => block.replace(/[^\n]/g, " ")).replace(/(`+)[^\n]*?\1/g, block => " ".repeat(block.length));
  const refs = new Map();
  const label = value => value.trim().replace(/\s+/g, " ").toLowerCase();
  for (const match of text.matchAll(/^ {0,3}\[([^\]]+)\]:\s*(<[^>]+>|\S+)/gm)) {
    const target = match[2].replace(/^<|>$/g, ""); refs.set(label(match[1]), target); check(file, target, match.index, original);
  }
  for (const match of text.matchAll(/!?\[[^\]\n]*\]\(\s*(<[^>]+>|(?:[^\s()]|\([^()]*\))+)(?:\s+["'][^\n]*?["'])?\s*\)/g)) check(file, match[1].replace(/^<|>$/g, ""), match.index, original);
  for (const match of text.matchAll(/!?\[([^\]\n]+)\]\[([^\]\n]*)\]/g)) {
    if (!refs.has(label(match[2] || match[1]))) { console.error(`${file}:${text.slice(0, match.index).split("\n").length}: undefined reference ${match[2] || match[1]}`); failures++; }
  }
}
console.log(`Checked ${checked} local links in ${files.length} Markdown files; ${failures} failures. External URLs are not checked.`);
process.exitCode = failures ? 1 : 0;
