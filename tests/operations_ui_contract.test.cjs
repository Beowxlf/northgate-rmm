const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {test} = require('node:test');

const source = fs.readFileSync(
  path.join(__dirname, '../src/northgate_rmm/operations_ui.js'),
  'utf8',
);

test('case workspace exposes professional triage and filtering controls', () => {
  for (const contract of [
    'data-ops-case-priority',
    'data-ops-case-type',
    'data-ops-case-sort',
    'Investigation checklist',
    'Linked security alerts',
    'containment_status',
    'resolution_code',
  ]) assert.ok(source.includes(contract), contract);
});

test('security alert actions carry explanations and preserve case context', () => {
  assert.ok(source.includes('data-ops="info"'));
  assert.ok(source.includes('Open response tools'));
  assert.ok(source.includes('lockedCase: Boolean(caseId)'));
  assert.ok(source.includes('existing permissions'));
  assert.ok(source.includes('Detection facts'));
});
