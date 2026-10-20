import { lstatSync, readFileSync, mkdirSync, openSync, writeSync, fsyncSync, closeSync, renameSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { z } from "zod";

export const CONFIG_PATH = process.env.MESSENGER_MCP_CONFIG ?? join(homedir(), ".config", "messenger-personal-mcp", "config.json");
export const STATE_DIR = process.env.MESSENGER_STATE_DIR ?? join(homedir(), "Library", "Application Support", "messenger-cli");
export type Perm = "read" | "write";
export const idSchema = z.string().regex(/^[1-9][0-9]{0,19}$/);
const ruleSchema = z.object({ name: z.string().max(1000), kind: z.enum(["dm", "group"]), jid: z.string().max(100), read: z.boolean(), write: z.boolean(), group: z.boolean().optional() }).strict().refine(r => r.kind !== "group" || r.group === true);
const configSchema = z.object({ version: z.literal(1), permissions: z.array(z.enum(["read", "write"])), confirm_send: z.literal(true), chats: z.record(idSchema, ruleSchema) }).strict();
export type Config = z.infer<typeof configSchema>;
export type ChatRule = z.infer<typeof ruleSchema>;
export const defaultConfig = (): Config => ({ version: 1, permissions: ["read"], confirm_send: true, chats: {} });
export function loadConfig(path = CONFIG_PATH): Config {
  try {
    const st = lstatSync(path);
    if (!st.isFile() || st.isSymbolicLink() || (st.mode & 0o077) || st.size > 1024*1024) throw new Error("private file required");
    return configSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return defaultConfig();
    throw new Error("Permission configuration is invalid or not private; access denied.");
  }
}
export function saveConfig(cfg: Config, path = CONFIG_PATH): void {
  const valid = configSchema.parse(cfg), dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink() || (st.mode & 0o077)) throw new Error("Permission directory must have mode 700.");
  const temp = join(dir, `.policy-${randomBytes(12).toString("hex")}`);
  let fd: number | undefined;
  try {
    fd = openSync(temp, "wx", 0o600); writeSync(fd, JSON.stringify(valid, null, 2)+"\n"); fsyncSync(fd); closeSync(fd); fd = undefined;
    renameSync(temp, path);
  } finally { if (fd !== undefined) closeSync(fd); try { unlinkSync(temp); } catch {} }
}
export function toolPerms(value = process.env.MESSENGER_MCP_PERMISSIONS ?? "read,write"): Set<Perm> {
  const parts = value.split(",").map(x=>x.trim()).filter(Boolean);
  if (parts.some(p=>p!=="read" && p!=="write")) throw new Error("Invalid Messenger tool permission ceiling.");
  return new Set(parts as Perm[]);
}
export function allowed(perm: Perm, id: string, cfg: Config, ceiling: Set<Perm>): boolean {
  if (!idSchema.safeParse(id).success || !ceiling.has(perm) || !cfg.permissions.includes(perm) || !Object.hasOwn(cfg.chats,id)) return false;
  const r = cfg.chats[id];
  return (r.kind!=="group" || r.group===true) && r[perm]===true;
}
export function ruleFingerprint(rule: ChatRule): string { return JSON.stringify(rule); }
