import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { runOpenSsl, verifyCmsDetached } from "./lib/verify-cms.mjs";

const temporaryRoot = fs.mkdtempSync(
  path.join(os.tmpdir(), "northgate-rmm-cms-test-"),
);
try {
  const keyPath = path.join(temporaryRoot, "signer.key");
  const certificatePath = path.join(temporaryRoot, "signer.pem");
  const contentPath = path.join(temporaryRoot, "receipt.json");
  const signaturePath = path.join(temporaryRoot, "receipt.cms.pem");
  const content = '{"planId":"ngp-test"}\n';
  fs.writeFileSync(contentPath, content, "utf8");
  assert.equal(
    runOpenSsl([
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      "/CN=NorthGate VM Factory Test Approval Signer",
      "-days",
      "1",
      "-keyout",
      keyPath,
      "-out",
      certificatePath,
    ]).status,
    0,
    "test approval certificate generation failed",
  );
  assert.equal(
    runOpenSsl([
      "cms",
      "-sign",
      "-binary",
      "-in",
      contentPath,
      "-signer",
      certificatePath,
      "-inkey",
      keyPath,
      "-outform",
      "PEM",
      "-out",
      signaturePath,
      "-nosmimecap",
      "-md",
      "sha256",
    ]).status,
    0,
    "test approval receipt signing failed",
  );
  const certificate = new X509Certificate(fs.readFileSync(certificatePath));
  const fingerprint = `sha256:${certificate.fingerprint256
    .replaceAll(":", "")
    .toLowerCase()}`;
  const signature = fs.readFileSync(signaturePath, "utf8");
  assert.equal(verifyCmsDetached(content, signature, fingerprint), true);
  assert.equal(
    verifyCmsDetached(`${content}tampered`, signature, fingerprint),
    false,
  );
  assert.equal(
    verifyCmsDetached(content, signature, `sha256:${"0".repeat(64)}`),
    false,
  );
  console.log("Factory CMS verification tests: 3 passed.");
} finally {
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}
