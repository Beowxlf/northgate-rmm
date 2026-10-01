// Focused DOM contract test; this does not claim a real-browser acceptance run.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const {randomUUID} = require('node:crypto');

class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.dataset = {}; this._value = undefined; }
  get value() { return this._value ?? (this.tag === 'select' ? this.children[0]?.value ?? '' : ''); }
  set value(v) { this._value = v; }
  append(...children) { children.forEach(child => { child.parent = this; this.children.push(child); }); }
  replaceChildren(...children) { this.children.forEach(child => { child.parent = null; }); this.children = []; this.append(...children); if (this.tag === 'select') this._value = undefined; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); this.parent = null; }
  setAttribute(name, value) { this.attrs[name] = value; }
  hasAttribute(name) { return name === 'data-safe-retry' ? this.dataset.safeRetry === 'true' : Object.hasOwn(this.attrs, name); }
  querySelectorAll(tag) { return this.children.flatMap(child => [...(child.tag === tag ? [child] : []), ...child.querySelectorAll(tag)]); }
  querySelector(selector) { return selector === '[data-safe-retry]' ? this.querySelectorAll('button').find(button => button.dataset.safeRetry === 'true') ?? null : null; }
}

async function fixture(outcomes = []) {
  const posts = [], container = new Element('div'), window = {};
  const tools = [{id: 'sysinternals', name: 'Sysinternals', profiles: ['startup', 'trust'], builtin: false}, {id: 'connectivity', name: 'Connectivity', profiles: ['dns', 'tls'], builtin: true}];
  const fetch = async (url, options = {}) => {
    if (options.method === 'POST') {
      posts.push(JSON.parse(options.body));
      const outcome = outcomes.shift();
      if (outcome instanceof Error) throw outcome;
      if (outcome?.status === 200) return {ok: true, json: async () => outcome.result};
      if (outcome) return {ok: false, status: outcome.status, headers: {get: () => outcome.marked ? 'rejected-before-queue' : null}, text: async () => 'Invalid path'};
      return {ok: true, json: async () => ({job: posts.at(-1).request_id})};
    }
    return {ok: true, json: async () => ({csrf: 'test-session-token', tools, jobs: []})};
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../src/northgate_rmm/tool_catalog_ui.js'), 'utf8'), {
    document: {createElement: tag => new Element(tag)}, window, fetch,
    crypto: {randomUUID}, setTimeout: () => 0, clearTimeout: () => {},
  });
  const cleanup = window.NorthGateTools.mount(container, 'endpoint');
  await new Promise(setImmediate);
  const [tool, profile] = container.querySelectorAll('select');
  const run = async () => { container.querySelectorAll('button').find(button => button.textContent === 'Run').onclick(); await new Promise(setImmediate); };
  return {container, tool, profile, posts, run, cleanup};
}

test('trust blank input retains default and only explicit file is transmitted', async () => {
  const f = await fixture();
  f.profile.value = 'trust'; f.profile.onchange();
  const input = f.container.querySelectorAll('input').find(input => input.name === 'path');
  assert.ok(input.attrs['aria-label'].includes('Optional local file'));
  await f.run();
  assert.deepEqual(f.posts[0].inputs, {});
  input.value = 'C:\\Ops files\\example.exe';
  await f.run();
  assert.deepEqual(f.posts[1].inputs, {path: input.value});
  assert.equal(f.posts[1].profile, 'trust');
  f.cleanup();
});

test('switching to logon startup removes trust path and conveys limited scope', async () => {
  const f = await fixture();
  f.profile.value = 'trust'; f.profile.onchange();
  f.container.querySelectorAll('input').find(input => input.name === 'path').value = 'C:\\Ops\\sample.exe';
  f.profile.value = 'startup'; f.profile.onchange();
  assert.equal(f.container.querySelectorAll('input').some(input => input.name === 'path'), false);
  assert.equal(f.profile.children[0].textContent, 'Logon startup');
  assert.ok(f.container.querySelectorAll('p').some(p => p.textContent.includes('Logon startup entries only')));
  await f.run();
  assert.deepEqual(f.posts[0].inputs, {});
  assert.equal(f.posts[0].profile, 'startup');
  f.cleanup();
});

test('changing unrelated diagnostic profile preserves entered host', async () => {
  const f = await fixture();
  f.tool.value = 'connectivity'; f.tool.onchange();
  f.container.querySelectorAll('input').find(input => input.name === 'host').value = 'lab.example';
  f.profile.value = 'tls'; f.profile.onchange();
  await f.run();
  assert.deepEqual(f.posts[0].inputs, {host: 'lab.example', port: 443});
  f.cleanup();
});

test('marked first-attempt validation rejection permits correction with a new UUID', async () => {
  const f = await fixture([{status: 400, marked: true}]);
  f.profile.value = 'trust'; f.profile.onchange();
  const input = f.container.querySelectorAll('input').find(input => input.name === 'path');
  input.value = 'not an absolute path';
  await f.run();
  assert.equal(f.tool.disabled, false);
  assert.equal(input.disabled, false);
  assert.equal(f.container.querySelectorAll('button').some(button => button.textContent === 'Retry safely'), false);
  input.value = 'C:\\Ops\\corrected.exe';
  await f.run();
  assert.notEqual(f.posts[0].request_id, f.posts[1].request_id);
  assert.deepEqual(f.posts[1].inputs, {path: input.value});
  f.cleanup();
});

test('unmarked post-queue error preserves the original body and UUID', async () => {
  const f = await fixture([{status: 400, marked: false}, {status: 500, marked: false}]);
  await f.run();
  assert.equal(f.tool.disabled, true);
  const retry = f.container.querySelectorAll('button').find(button => button.textContent === 'Retry safely');
  retry.onclick(); await new Promise(setImmediate);
  assert.equal(f.tool.disabled, true);
  assert.equal(f.posts.length, 2);
  assert.deepEqual(f.posts[0], f.posts[1]);
  f.cleanup();
});

test('a later marked rejection cannot clear uncertainty from an in-flight first attempt', async () => {
  const f = await fixture([new Error('Connection lost'), {status: 400, marked: true}]);
  await f.run();
  const retry = f.container.querySelectorAll('button').find(button => button.textContent === 'Retry safely');
  retry.onclick(); await new Promise(setImmediate);
  assert.equal(f.tool.disabled, true);
  assert.equal(f.posts.length, 2);
  assert.deepEqual(f.posts[0], f.posts[1]);
  f.cleanup();
});

for (const result of [{}, {job: 'another-request'}]) {
  test('unconfirmed successful response retains its UUID: ' + JSON.stringify(result), async () => {
    const f = await fixture([{status: 200, result}]);
    await f.run();
    assert.equal(f.tool.disabled, true);
    const retry = f.container.querySelectorAll('button').find(button => button.textContent === 'Retry safely');
    retry.onclick(); await new Promise(setImmediate);
    assert.deepEqual(f.posts[0], f.posts[1]);
    assert.equal(f.tool.disabled, false);
    f.cleanup();
  });
}
