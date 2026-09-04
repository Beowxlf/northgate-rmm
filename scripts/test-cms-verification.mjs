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
  const issuedAt = new Date(Date.now() + 1000)
    .toISOString()
    .replace(".000Z", "Z");
  const approvedAt = new Date(Date.now() + 2000)
    .toISOString()
    .replace(".000Z", "Z");
  const content = `${JSON.stringify({ planId: "ngp-test", issuedAt, approvedAt })}\n`;
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

  const weakKeyPath = path.join(temporaryRoot, "weak-signer.key");
  const weakCertificatePath = path.join(temporaryRoot, "weak-signer.pem");
  const weakSignaturePath = path.join(temporaryRoot, "weak-receipt.cms.pem");
  assert.equal(
    runOpenSsl([
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      "/CN=algorithm: sha256",
      "-days",
      "1",
      "-keyout",
      weakKeyPath,
      "-out",
      weakCertificatePath,
    ]).status,
    0,
    "weak-digest test certificate generation failed",
  );
  assert.equal(
    runOpenSsl([
      "cms",
      "-sign",
      "-binary",
      "-in",
      contentPath,
      "-signer",
      weakCertificatePath,
      "-inkey",
      weakKeyPath,
      "-outform",
      "PEM",
      "-out",
      weakSignaturePath,
      "-nosmimecap",
      "-md",
      "md5",
    ]).status,
    0,
    "weak-digest test receipt signing failed",
  );
  const weakCertificate = new X509Certificate(
    fs.readFileSync(weakCertificatePath),
  );
  const weakFingerprint = `sha256:${weakCertificate.fingerprint256
    .replaceAll(":", "")
    .toLowerCase()}`;
  assert.equal(
    verifyCmsDetached(
      content,
      fs.readFileSync(weakSignaturePath, "utf8"),
      weakFingerprint,
    ),
    false,
  );

  const outsideContentPath = path.join(temporaryRoot, "outside-receipt.json");
  const outsideSignaturePath = path.join(
    temporaryRoot,
    "outside-receipt.cms.pem",
  );
  const outsideContent = `${JSON.stringify({
    planId: "ngp-outside-validity",
    issuedAt: "2100-01-01T00:00:00Z",
    approvedAt: "2100-01-01T00:01:00Z",
  })}\n`;
  fs.writeFileSync(outsideContentPath, outsideContent, "utf8");
  assert.equal(
    runOpenSsl([
      "cms",
      "-sign",
      "-binary",
      "-in",
      outsideContentPath,
      "-signer",
      certificatePath,
      "-inkey",
      keyPath,
      "-outform",
      "PEM",
      "-out",
      outsideSignaturePath,
      "-nosmimecap",
      "-md",
      "sha256",
    ]).status,
    0,
    "outside-validity test receipt signing failed",
  );
  assert.equal(
    verifyCmsDetached(
      outsideContent,
      fs.readFileSync(outsideSignaturePath, "utf8"),
      fingerprint,
    ),
    false,
  );
  console.log("Factory CMS verification tests: 5 passed.");
} finally {
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}
