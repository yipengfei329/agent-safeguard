import test from 'node:test';
import assert from 'node:assert/strict';
import {compile, defaults} from '../dist/core.js';

const fingerprint = 'a19c7e2d03f8b6a4';
const manifest = `<assemblyIdentity name="Synthetic.App" publicKeyToken="${fingerprint}" language="*" />`;
const engine = compile(defaults, {diagnostics: true});

test('recognizes the public fingerprint in a Windows assembly manifest', () => {
  for (const snippet of [
    manifest,
    `<assemblyIdentity\n name='Synthetic.App'\n publicKeyToken='${fingerprint.toUpperCase()}'\n />`,
    `const manifest = \`\n${manifest}\n\``,
    `manifest.xml:17: ${manifest}`,
    JSON.stringify({stdout: manifest}),
  ]) assert.equal(engine.scan(snippet, 'tool.result', 'Bash').blocked, false);
});

test('recognizes short 16-hex fingerprints as non-secret across XML and structured contexts while blocking 32-hex and mixed secrets', () => {
  for (const snippet of [
    `publicKeyToken="${fingerprint}"`,
    `<service publicKeyToken="${fingerprint}"/>`,
    {publicKeyToken: fingerprint},
  ]) assert.equal(engine.scan(snippet, 'tool.result', 'Bash').blocked, false);
  for (const snippet of [
    `<assemblyIdentity publicKeyToken="${fingerprint.repeat(2)}"/>`,
    '<assemblyIdentity publicKeyToken="qR7_mN2-zP8_vL4-tX9"/>',
    {publicKeyToken: fingerprint.repeat(2)},
  ]) assert.equal(engine.scan(snippet, 'tool.result', 'Bash').rule, 'security.credentials');
});

test('the manifest does not exempt nearby secret values or independent signatures', () => {
  for (const [snippet, rule] of [
    [`${manifest}\napiKey="${fingerprint.repeat(2)}"`, 'security.credentials'],
    [manifest.replace('/>', 'password="qR7_mN2-zP8_vL4-tX9"/>'), 'security.credentials'],
    [`${manifest}\nhostname: SyntheticHost`, 'identity.environment'],
    [`${manifest}\ndeviceId: SYNTHETIC123456`, 'identity.device'],
    [`${manifest}\nghp_${'Z'.repeat(36)}`, 'security.credentials'],
  ]) assert.equal(engine.scan(snippet, 'tool.result', 'Bash').rule, rule);
  const config = structuredClone(defaults);
  config.rules.unshift({
    id: 'custom.synthetic', enabled: true, sources: ['tool.result'], action: 'block',
    detector: {kind: 'exact', values: [fingerprint], caseSensitive: true},
  });
  assert.equal(compile(config).scan(manifest).rule, 'custom.synthetic');
});
