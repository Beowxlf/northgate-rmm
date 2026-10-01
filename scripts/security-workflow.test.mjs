import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { load as loadYaml } from "js-yaml";

const workflow = loadYaml(
  fs.readFileSync(".github/workflows/security.yml", "utf8"),
);
const steps = workflow.jobs.scan.steps;

test("independent security checks retain failures and run after earlier failures", () => {
  const independentChecks = [
    "Audit Python tool dependencies",
    "Audit isolated Semgrep dependencies",
    "Check Python formatting",
    "Lint Python",
    "Check Python types",
    "Test Phase 1 Python domain slice",
    "Scan Phase 1 Python with Bandit",
    "Check Phase 2 Go agent",
    "Check Windows agent types and pointers",
    "Build and test the Phase 2 Debian package in isolation",
    "Build and test the server Debian package in isolation",
    "Run Semgrep JavaScript checks",
    "Run Semgrep Python checks",
    "Run Semgrep Go checks",
    "Audit workflows with Zizmor",
    "Scan for secrets with Gitleaks",
    "Validate workflows with actionlint",
    "Validate documentation links with Lychee",
  ];
  for (const name of independentChecks) {
    const step = steps.find((candidate) => candidate.name === name);
    assert.ok(step, `missing required check: ${name}`);
    assert.equal(step.if, "${{ !cancelled() }}", name);
    assert.notEqual(step["continue-on-error"], true, name);
  }
  assert.match(
    steps.find((step) => step.name === "Test Phase 1 Python domain slice").run,
    /--cov-fail-under=90/,
  );
  const npmEnforcement = steps.find(
    (step) => step.name === "Enforce npm advisory audit result",
  );
  assert.equal(npmEnforcement.if, "${{ always() }}");
  assert.equal(npmEnforcement.run, 'test "$NPM_AUDIT_OUTCOME" = "success"');
});

test("server qualification uses the current wheel version end to end", () => {
  const packaging = steps.find(
    (step) =>
      step.name === "Build and test the server Debian package in isolation",
  ).run;
  assert.match(packaging, /tomllib/);
  assert.match(packaging, /test "\$#" -eq 1/);
  assert.match(packaging, /cmp "\$application_wheel"/);
  assert.doesNotMatch(packaging, /0\.1\.0(?:\.dev0|~dev0)/);
  assert.match(
    packaging,
    /sh \/test-package\.sh[\s\S]*"\$application_version"/,
  );
  const packageTest = fs.readFileSync(
    "server/packaging/debian/test-package.sh",
    "utf8",
  );
  assert.match(packageTest, /expected_application_version="\$\{3:\?/);
  assert.match(packageTest, /"northgate-rmm": sys\.argv\[1\]/);
});

test("link validation retains repository-wide supported-file coverage", () => {
  const linkCheck = steps.find(
    (step) => step.name === "Validate documentation links with Lychee",
  );
  assert.ok(linkCheck);
  assert.match(linkCheck.run, /(?:^|\s)\.\s*$/);
  assert.doesNotMatch(linkCheck.run, /\*\*\/\*\.md/);
});
