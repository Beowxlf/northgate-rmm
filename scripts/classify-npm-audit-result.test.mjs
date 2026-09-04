import assert from "node:assert/strict";
import test from "node:test";

import { isRetryableAuditFailure } from "./classify-npm-audit-result.mjs";

test("allows only explicit registry transport failures to retry", () => {
  for (const message of [
    "network timeout at: https://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
    "502 Bad Gateway - POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
    "503 Service Unavailable - POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
    "504 Gateway Time-out - POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
    "request to https://registry.npmjs.org/-/npm/v1/security/advisories/bulk failed, reason: socket hang up",
  ]) {
    assert.equal(isRetryableAuditFailure({ message, error: {} }), true);
  }
});

test("never retries a vulnerability report, clean report, or unknown failure", () => {
  for (const value of [
    {
      auditReportVersion: 2,
      vulnerabilities: { example: { severity: "high" } },
      metadata: { vulnerabilities: { high: 1 } },
    },
    { auditReportVersion: 2, vulnerabilities: {}, metadata: {} },
    { message: "unexpected failure", error: {} },
    { message: "503 Service Unavailable - POST https://registry.npmjs.org" },
    {
      message:
        "503 Service Unavailable - POST https://mirror.test/-/npm/v1/security/advisories/bulk",
      error: {},
    },
    {
      message:
        "503 Service Unavailable - POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
      error: "unstructured",
    },
    null,
    "malformed",
  ]) {
    assert.equal(isRetryableAuditFailure(value), false);
  }
});
