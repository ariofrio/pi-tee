import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePolicy } from "../packages/core/src/policy.js";

test("positions disclose trust through their strict and loose defaults", () => {
  const expected = {
    "public-builds": ["public-release", "current", "verified", "none"],
    "public-builds-trust-host": ["public-release", "stale", "unchecked", "none"],
    "trust-provider": ["provider-controlled", "current", "verified", "any"],
    "trust-provider-and-host": ["provider-controlled", "stale", "unchecked", "any"],
  };
  for (const [position, values] of Object.entries(expected)) {
    const p = parsePolicy(position);
    assert.deepEqual([p.code, p.host, p.gpu, p.egress], values);
    assert.equal(p.build, position.startsWith("public") ? "publisher-workflow" : undefined);
    assert.equal(p.review, position.startsWith("public") ? "none" : undefined);
    assert.equal(p.verifier, "local");
    assert.equal(p.appraisal, "per-request");
  }
  assert.equal(parsePolicy().egress, "metadata");
});

test("all 35 valid four-axis combinations have exactly one truthful position", () => {
  let accepted = 0;
  for (const code of ["public-release", "fixed-private", "provider-controlled"]) {
    for (const host of ["current", "outdated-firmware", "stale"]) {
      for (const gpu of ["verified", "gaps", "unchecked"]) {
        for (const egress of ["none", "metadata", "any"]) {
          const position = code === "public-release"
            ? host === "current" && gpu === "verified" ? "public-builds" : "public-builds-trust-host"
            : host === "current" && gpu === "verified" ? "trust-provider" : "trust-provider-and-host";
          const setting = `${position},code=${code},host=${host},gpu=${gpu},egress=${egress}`;
          if ((host === "stale" && gpu !== "unchecked") || (code !== "public-release" && egress !== "any")) {
            assert.throws(() => parsePolicy(setting), /TEE_POLICY_INVALID/, setting);
          } else {
            const policy = parsePolicy(setting);
            assert.deepEqual([policy.code, policy.host, policy.gpu, policy.egress], [code, host, gpu, egress]);
            accepted++;
            for (const wrong of ["public-builds", "public-builds-trust-host", "trust-provider", "trust-provider-and-host"].filter(p => p !== position)) {
              assert.throws(() => parsePolicy(setting.replace(position, wrong)), /TEE_POLICY_INVALID/, wrong);
            }
          }
        }
      }
    }
  }
  assert.equal(accepted, 35);
});

test("grammar, unsupported refinements and obsolete names fail with migration guidance", () => {
  for (const setting of ["", "typo", "Public-Builds", " public-builds", "public-builds, egress=metadata", "public-builds,egress=metadata ", "public-builds,", "public-builds,unknown=x", "public-builds,code=bad", "public-builds,host=bad", "public-builds,gpu=bad", "public-builds,egress=bad", "public-builds,build=bad", "public-builds,review=bad", "public-builds,verifier=bad", "public-builds,appraisal=bad", "public-builds,host=current,host=current", "trust-provider,build=signed", "trust-provider-and-host,review=none"]) {
    assert.throws(() => parsePolicy(setting), /TEE_POLICY_INVALID/, setting);
  }
  for (const build of ["reproduced", "reproduced-off-github", "signed"]) assert.throws(() => parsePolicy(`public-builds,build=${build}`), /not yet supported/);
  for (const review of ["window", "pinned"]) assert.throws(() => parsePolicy(`public-builds,review=${review}`), /not yet supported/);

  assert.throws(() => parsePolicy("sdk"), /trust-provider-and-host/);
  assert.throws(() => parsePolicy("approved"), /public-builds,review=pinned.*not yet supported/);
  const ignored = parsePolicy("trust-provider-and-host,verifier=nras");
  assert.match(ignored.warnings.join(" "), /no effect.*gpu=unchecked/);
  assert.deepEqual(parsePolicy("trust-provider,verifier=nras").warnings, []);
  assert.equal(parsePolicy("public-builds,egress=metadata,appraisal=reuse").appraisal, "reuse");
});
