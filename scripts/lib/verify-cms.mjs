import { X509Certificate } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

function opensslExecutable() {
  if (process.platform !== "win32") return "openssl";
  const gitOpenSsl = "C:\\Program Files\\Git\\usr\\bin\\openssl.exe";
  return fs.existsSync(gitOpenSsl) ? gitOpenSsl : "openssl";
}

export function runOpenSsl(arguments_, options = {}) {
  return spawnSync(opensslExecutable(), arguments_, {
    encoding: "utf8",
    windowsHide: true,
    ...options,
  });
}

function sectionAlgorithms(lines, sectionIndex) {
  const sectionIndent = lines[sectionIndex].search(/\S/);
  const algorithms = [];
  for (let index = sectionIndex + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.trim() === "") continue;
    const indent = line.search(/\S/);
    if (indent <= sectionIndent) break;
    const match = /^\s*algorithm:\s*([^\s(]+)/.exec(line);
    if (match) algorithms.push(match[1].toLowerCase());
  }
  return algorithms;
}

function usesOnlySha256Digests(details) {
  const lines = details.replaceAll("\r\n", "\n").split("\n");
  const digestSets = lines
    .map((line, index) => (line.trim() === "digestAlgorithms:" ? index : -1))
    .filter((index) => index >= 0);
  if (digestSets.length !== 1) return false;
  const declaredAlgorithms = sectionAlgorithms(lines, digestSets[0]);
  if (declaredAlgorithms.length !== 1 || declaredAlgorithms[0] !== "sha256")
    return false;

  const signerStart = lines.findIndex((line) => line.trim() === "signerInfos:");
  if (signerStart < 0) return false;
  const signerDigests = lines
    .map((line, index) =>
      index > signerStart && line.trim() === "digestAlgorithm:" ? index : -1,
    )
    .filter((index) => index >= 0);
  return (
    signerDigests.length === 1 &&
    signerDigests.every((index) => {
      const algorithms = sectionAlgorithms(lines, index);
      return algorithms.length === 1 && algorithms[0] === "sha256";
    })
  );
}

export function verifyCmsDetached(
  content,
  signature,
  expectedCertificateSha256,
) {
  if (
    typeof content !== "string" ||
    typeof signature !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(expectedCertificateSha256 ?? "")
  )
    return false;

  const temporaryRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "northgate-rmm-cms-"),
  );
  try {
    const contentPath = path.join(temporaryRoot, "content.json");
    const signaturePath = path.join(temporaryRoot, "signature.pem");
    const signerPath = path.join(temporaryRoot, "signer.pem");
    const verifiedPath = path.join(temporaryRoot, "verified.json");
    fs.writeFileSync(contentPath, content, "utf8");
    fs.writeFileSync(signaturePath, signature, "utf8");
    const signatureDetails = runOpenSsl([
      "cms",
      "-cmsout",
      "-print",
      "-inform",
      "PEM",
      "-in",
      signaturePath,
    ]);
    if (
      signatureDetails.status !== 0 ||
      !usesOnlySha256Digests(signatureDetails.stdout)
    )
      return false;
    const verification = runOpenSsl([
      "cms",
      "-verify",
      "-binary",
      "-inform",
      "PEM",
      "-in",
      signaturePath,
      "-content",
      contentPath,
      "-noverify",
      "-signer",
      signerPath,
      "-out",
      verifiedPath,
    ]);
    if (verification.status !== 0) return false;
    if (fs.readFileSync(verifiedPath, "utf8") !== content) return false;
    const signerText = fs.readFileSync(signerPath, "utf8");
    if ((signerText.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length !== 1)
      return false;
    const signer = new X509Certificate(signerText);
    const fingerprint = `sha256:${signer.fingerprint256
      .replaceAll(":", "")
      .toLowerCase()}`;
    if (fingerprint !== expectedCertificateSha256) return false;

    const receipt = JSON.parse(content);
    const issuedAt = Date.parse(receipt.issuedAt ?? "");
    const approvedAt = Date.parse(receipt.approvedAt ?? "");
    const validFrom = Date.parse(signer.validFrom);
    const validTo = Date.parse(signer.validTo);
    return (
      Number.isFinite(issuedAt) &&
      Number.isFinite(approvedAt) &&
      Number.isFinite(validFrom) &&
      Number.isFinite(validTo) &&
      validFrom <= issuedAt &&
      issuedAt <= approvedAt &&
      approvedAt <= validTo
    );
  } catch {
    return false;
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}
