import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { verifyChutesInstance } from "../packages/chutes/src/evidence.js";

const directory = process.env.CHUTES_TEST_EVIDENCE_DIR;
const evidenceTest = directory ? test : test.skip;
evidenceTest("real Chutes evidence authenticates the client nonce, instance ML-KEM key and host SPKI", async () => {
  const load = async (name: string) => JSON.parse(await readFile(join(directory!, name), "utf8"));
  const discovery = await load("keyed-discovery.public.json");
  const evidence = await load("keyed-evidence.body");
  const challenge = (await load("keyed-evidence.request.json")).nonce;
  for (let index = 0; index < evidence.evidence.length; index++) {
    const entry = evidence.evidence[index];
    const key = discovery.instances.find((i: any) => i.instance_id === entry.instance_id).e2e_pubkey;
    const collateral = await load(`keyed-instance-${index}.collateral.json`);
    const check = (item: unknown, nonce = challenge, pubkey = key) => verifyChutesInstance(item, pubkey, nonce, AbortSignal.timeout(10000), { collateral: async () => collateral });
    const rating = await check(entry);
    assert.equal(rating.host, 1);
    for (const [item, nonce, pubkey] of [
      [entry, "00".repeat(32), key],
      [entry, challenge, Buffer.alloc(1184).toString("base64")],
      [{ ...entry, certificate: evidence.evidence[(index + 1) % evidence.evidence.length].certificate }, challenge, key],
      [{ ...entry, signature: Buffer.alloc(256).toString("base64") }, challenge, key],
      [{ ...entry, quote: Buffer.alloc(640).toString("base64") }, challenge, key],
    ]) await assert.rejects(check(item, nonce, pubkey));
  }
});
