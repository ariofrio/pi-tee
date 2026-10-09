import assert from "node:assert/strict";
import { test } from "node:test";
import { parseChutesCatalog } from "../packages/chutes/src/catalog.js";

const raw = { id: "test/Chat-TEE", chute_id: "08901219-159f-55a7-87cf-9d0d02744668", confidential_compute: true,
  context_length: 8192, max_output_length: 1024, supported_features: ["tools", "reasoning"],
  pricing: { prompt: 0.2, completion: 0.4, input_cache_read: 0.02 } };

test("Chutes catalog offers only declared confidential tool-capable chat models with a chute ID", () => {
  const models = parseChutesCatalog({ data: [raw, { ...raw, id: "ordinary", confidential_compute: false },
    { ...raw, id: "no-tools", supported_features: [] }, { ...raw, id: "no-chute", chute_id: undefined }] });
  assert.equal(models.length, 1);
  assert.equal(models[0]!.id, raw.id);
  assert.equal(models[0]!.reasoning, true);
  assert.equal(models[0]!.cost.input, 0.2);
  assert.equal(models[0]!.teeCapability, "declared");
});
