import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,readFileSync,statSync,rmSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {compile,defaults,safeReason} from '../dist/core.js';
import {collectLocalIdentity,syncLocalIdentityConfig} from '../src/local-identity.js';
import redactProfile from '../config/redact-results.json' with {type:'json'};

const secret='sY9!nT4_hE7#tI2-cK8';
const sources=['tool.input','tool.result','user.prompt','prompt.context'];

const realWorldCleanSnippets=[
  ['upper-snake-constant','const DEFAULT_TOKEN = "USER_PROFILE";\nconst COOKIE_SECRET = "SESSION_AUTH_COOKIE_V2";'],
  ['pascal-snake-identifier','const header = { token: "User_Profile", secret: "Invalid_Token_Error" };'],
  ['two-letter-prefix-kebab','export const step = { apiKey: "id-verification", token: "sk-dev-placeholder" };'],
  ['colon-urn-and-scopes','{"token": "urn:ietf:params:oauth:token-type:jwt", "secret": "oauth2:read:org_tokens"}'],
  ['dot-namespaced-i18n-key','{"password": "Auth.Password.ResetTitle", "apiToken": "Settings.Api.TokenLabel"}'],
  ['short-hex-fingerprints','{"publicKeyToken": "6595b64144ccf1df", "commitKey": "a1b2c3d4e5f6", "spanToken": "4bf92f3577b34da6"}'],
  ['long-compound-english-word','const token = "cryptographicauthentication";'],
  ['ui-password-expiry-notice','{"password": "Your password expired 3 days ago!"}'],
  ['ui-password-question','{"password": "Forgot your password? Retry in 30s"}'],
  ['ui-password-attempts','{"password": "Invalid password, 2 attempts remaining!"}'],
  ['ui-password-min-chars','{"password": "Password (min 8 chars)"}'],
  ['server-bind-hostnames','server.listen({ hostname: "127.0.0.1", port: 3000 });\nconst bind = { hostname: "0.0.0.0", ipv6: { hostname: "[::1]" } };'],
  ['reserved-rfc-hostnames','{"hostname": "localhost", "peer": {"hostname": "api.example.com"}, "test": {"hostname": "svc.test"}}'],
  ['service-role-hostnames','services:\n  cache:\n    hostname: redis\n  queue:\n    hostname: worker\n  db:\n    hostname: postgres'],
  ['mock-device-identifiers','{"device_id": "device-1", "udid": "unknown", "serialNumber": "test-serial-01", "emulator": {"deviceId": "emulator-5554"}}'],
  ['reserved-broadcast-multicast-macs','ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff mcast 01:00:5e:00:00:fb ipv6mcast 33:33:00:00:00:01 doc 00:00:5e:00:53:af'],
  ['sandbox-stripe-and-aws-doc-example','const testKey = "sk_test_51SyntheticSandboxValue123456"; const docKey = "AKIAIOSFODNN7EXAMPLE";'],
  ['sequential-provider-ui-placeholders','const placeholder = "sk-proj-1234567890abcdefghij";\n// Authorization: Bearer sk-proj-0123456789abcdefghij\nlet token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";\nconst mockGitlab = "glpat-your-api-token-placeholder";\nconst dummyJwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fake_signature_for_testing_only";\nconst curlCmd = "OPENAI_API_KEY=sk-proj-1234567890abcdefghij curl -H \'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\' https://api.example.com";'],
];

test('multi-language real-world code and config patterns pass with zero false positives while preserving adjacent detections',()=>{
  const engine=compile();
  for(const [id,snippet] of realWorldCleanSnippets){
    for(const source of sources){
      assert.equal(engine.scan(snippet,source,'Read').blocked,false,`${id} (${source})`);
      assert.equal(engine.scan(`${snippet}\npassword="${secret}"`,source,'Read').rule,'security.credentials',`${id} + adjacent credential`);
    }
    assert.equal(engine.scan(`${snippet}\nether aa:bb:cc:dd:ee:ff`,'tool.result','Bash').rule,'identity.device',`${id} + adjacent personal MAC`);
    assert.equal(engine.scan(`${snippet}\nhostname: SyntheticWorkstation`,'tool.result','Bash').rule,'identity.environment',`${id} + adjacent personal host`);
  }
});

test('expanded high-specificity provider signatures detect bare tokens across ecosystems',()=>{
  const engine=compile();
  const generated='9fK2mP8xQ4vL7nR3tW6yZ1bC5dG8jH4kM2pN';
  const providerTokens=[
    ['anthropic-admin','sk-ant-admin01-'+generated],
    ['openai-proj','sk-proj-'+generated],
    ['openai-svcacct','sk-svcacct-'+generated],
    ['github-pat','ghp_'+generated],
    ['github-fine-grained','github_pat_11ABCDEFG_'+generated],
    ['gitlab-pat','glpat-'+generated.slice(0,24)],
    ['slack-bot','xoxb-123456789-987654321-'+generated.slice(0,24)],
    ['aws-akia','AKIA9X7K2M4P8Q3R6V5N'],
    ['aws-asia','ASIA9X7K2M4P8Q3R6V5N'],
    ['google-api','AIza'+generated.slice(0,35)],
    ['stripe-live','sk_live_'+generated.slice(0,24)],
    ['stripe-webhook','whsec_'+generated.slice(0,28)],
    ['huggingface','hf_'+generated.slice(0,34)],
    ['npm-token','npm_'+generated.slice(0,32)],
    ['pypi-token','pypi-'+generated+'ABCD1234'],
    ['sendgrid','SG.'+generated.slice(0,20)+'.'+generated.slice(0,28)],
  ];
  for(const [id,token] of providerTokens){
    const hit=engine.scan(`const fixture = "${token}";`,'tool.result','Read');
    assert.equal(hit.rule,'security.credentials',id);
    assert.equal(hit.reason,'token-format',id);
    const mixed=engine.scan(`const placeholder = "sk-proj-1234567890abcdefghij";\nconst leaked = "${token}";`,'tool.result','Edit');
    assert.equal(mixed.rule,'security.credentials',`${id} after sequential placeholder`);
    assert.equal(mixed.reason,'token-format',`${id} after sequential placeholder`);
  }
});

test('Schema 2 default profile aligns tool.input with outbound flow and blocks active [IP_n] placeholder writeback',()=>{
  const cfg=structuredClone(redactProfile);
  for(const r of cfg.rules){
    if(r.detector.kind==='ip'){
      r.detector.mode='any';
      delete r.detector.country;
      delete r.detector.onUnknown;
      delete r.detector.cidrs;
    }
  }
  const engine=compile(cfg);
  // Model-authored test secrets in Write/Edit tool.input are not blocked by generic heuristics,
  // while exact personal values and inbound tool.result / user.prompt remain protected.
  assert.equal(engine.scan({content:`const mockApiKey = "${secret}";`},'tool.input','Write').blocked,false);
  assert.equal(engine.scan({stdout:`const realApiKey = "${secret}";`},'tool.result','Read').rule,'security.credentials');
  assert.equal(engine.scan(`api_key=${secret}`,'user.prompt').rule,'security.credentials');
  assert.equal(engine.scan('SYNTHETIC_DEVICE_ID_0001','tool.input','Write').rule,'personal.synthetic-value');

  // Before any IP is redacted in this instance, "[IP_1]" in source code is allowed.
  assert.equal(engine.scan({content:'assert.equal(label, "[IP_1]")'},'tool.input','Write').blocked,false);

  // Once an IP is redacted to [IP_1], writing or executing [IP_1] in tool.input is blocked.
  const redacted=engine.inspectAndTransform({result:{stdout:'peer=203.0.113.17',stderr:'',interrupted:false}},'tool.result','Bash');
  assert.equal(redacted.kind,'redacted');
  const writeback=engine.scan({content:'endpoint = "http://[IP_1]:8080"'},'tool.input','Write');
  assert.equal(writeback.blocked,true);
  assert.equal(writeback.rule,'network.address');
  assert.equal(writeback.reason,'redaction.placeholder-input');
  assert.equal(safeReason(writeback.reason),'redaction.placeholder-input');
  // Unallocated [IP_9] does not false-trigger.
  assert.equal(engine.scan({content:'note = "[IP_9]"'},'tool.input','Write').blocked,false);
});

test('mixed runtime logs (Go standard log, ISO-8601 tracing, Python logging) redact IPs alongside stack braces',()=>{
  const cfg=structuredClone(redactProfile);
  for(const r of cfg.rules){
    if(r.detector.kind==='ip'){
      r.detector.mode='any';
      delete r.detector.country;
      delete r.detector.onUnknown;
      delete r.detector.cidrs;
    }
  }
  const engine=compile(cfg);
  const logs=[
    '2026/01/15 12:00:00 dial tcp 203.0.113.17:443: i/o timeout\n    testing.tRunner(0x1, {0x2})',
    '2026-01-15T12:00:00.123Z WARN connect failed remote=203.0.113.17:8443\n    at Socket.connect ({fd: 3})',
    'INFO:urllib3.connectionpool:Starting new HTTPS connection to 203.0.113.17:443\nTraceback: ValueError({"code": 1})',
  ];
  for(const stdout of logs){
    const decision=engine.inspectAndTransform({result:{stdout,stderr:'',interrupted:false}},'tool.result','Bash');
    assert.equal(decision.kind,'redacted',stdout);
    assert(!decision.value.result.stdout.includes('203.0.113.17'));
    assert(decision.value.result.stdout.includes('[IP_1]'));
  }
});

test('local identity sync collects synthetic machine fingerprints, disables generic hostname guessing, and never leaks values to CLI output',()=>{
  const values=collectLocalIdentity({
    platform:'darwin',
    hostname:()=>'Synthetic-Studio.local',
    networkInterfaces:()=>({
      lo0:[{internal:true,mac:'00:00:00:00:00:00'}],
      en0:[{internal:false,mac:'a2:b3:c4:d5:e6:f7'}],
    }),
    exec:(cmd,args)=>{
      if(cmd==='scutil'){
        return ({ComputerName:'Synthetic Studio Mac\n',LocalHostName:'Synthetic-Studio\n',HostName:'localhost\n'})[args[1]]??'';
      }
      if(cmd==='ioreg'){
        return '+-o Root  {\n  "IOPlatformSerialNumber" = "SYNTHSERIAL99"\n  "IOPlatformUUID" = "22222222-3333-4444-5555-666666666666"\n}\n';
      }
      return '';
    },
  });
  assert(values.includes('Synthetic-Studio.local'));
  assert(values.includes('Synthetic-Studio'));
  assert(values.includes('Synthetic Studio Mac'));
  assert(values.includes('SYNTHSERIAL99'));
  assert(values.includes('22222222-3333-4444-5555-666666666666'));
  assert(values.includes('a2:b3:c4:d5:e6:f7'));
  assert(values.includes('a2-b3-c4-d5-e6-f7'));
  assert(!values.includes('localhost'));

  const synced=syncLocalIdentityConfig(redactProfile,values);
  const engine=compile(synced);
  // Generic non-local hostnames in project files no longer trigger false positives,
  // while actual synced machine identifiers block even without a field name!
  assert.equal(engine.scan('hostname: CustomProjectService','tool.result','Read').blocked,false);
  for(const probe of ['Darwin synthetic-studio.local 24.0.0','Serial: synthserial99','UUID 22222222-3333-4444-5555-666666666666','A2-B3-C4-D5-E6-F7']){
    for(const source of ['tool.input','tool.result','user.prompt']){
      assert.equal(engine.scan(probe,source,'Bash').rule,'personal.local-identity',`${probe} (${source})`);
    }
  }

  // Linux machine-id collection path with synthetic data.
  const linuxValues=collectLocalIdentity({
    platform:'linux',
    hostname:()=>'synthetic-devbox',
    networkInterfaces:()=>({}),
    readFile:()=>'9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c\n',
  });
  assert.deepEqual(linuxValues,['synthetic-devbox','9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c']);

  // CLI draft creation permissions and output hygiene check in isolated temp dir.
  const dir=mkdtempSync(join(tmpdir(),'safeguard-local-sync-'));
  try{
    const src=join(dir,'source.json'),draft=join(dir,'draft.json');
    writeFileSync(src,JSON.stringify(redactProfile));
    const run=spawnSync(process.execPath,[
      '--input-type=module','-e',
      `import {readFileSync,writeFileSync} from 'node:fs';
       import {compile} from './dist/core.js';
       import {syncLocalIdentityConfig} from './src/local-identity.js';
       const orig=JSON.parse(readFileSync(${JSON.stringify(src)},'utf8'));
       const next=syncLocalIdentityConfig(orig,['SYNTHETIC_HOST_MARKER']);
       compile(next);
       writeFileSync(${JSON.stringify(draft)},JSON.stringify(next,null,2),{mode:0o600,flag:'wx'});
       console.log(JSON.stringify({ok:true,syncedCount:1}));`
    ],{cwd:resolve('.'),encoding:'utf8'});
    assert.equal(run.status,0);
    assert(!(run.stdout+run.stderr).includes('SYNTHETIC_HOST_MARKER'));
    if(process.platform!=='win32')assert.equal(statSync(draft).mode&0o777,0o600);
    assert.equal(compile(JSON.parse(readFileSync(draft,'utf8'))).scan('SYNTHETIC_HOST_MARKER','tool.result','Bash').rule,'personal.local-identity');
  }finally{
    rmSync(dir,{recursive:true,force:true});
  }
});
