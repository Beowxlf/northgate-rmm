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
      !/digestAlgorithms:[\s\S]*algorithm:\s*sha256\b/.test(
        signatureDetails.stdout,
      )
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
    const signer = new X509Certificate(fs.readFileSync(signerPath));
    const fingerprint = `sha256:${signer.fingerprint256
      .replaceAll(":", "")
      .toLowerCase()}`;
    return fingerprint === expectedCertificateSha256;
  } catch {
    return false;
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}
