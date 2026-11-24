import {test} from 'node:test';
import assert from 'node:assert/strict';
import {compile, defaults} from './strict-engine.mjs';
import {credentialReason} from '../src/credentials.js';

const clean = [
 ['grep switch label joins another source line', 'src/fake.go:21:case "ask", "ask-secret":\nsrc/fake.go:26:item := Question{Secret: cmd == "ask-secret"}'],
 ['quoted switch label', 'case "secret":\n    return result'],
 ['command names and identifiers', 'ask-secret: enabled\nrefresh-token-command: enabled\nmy_password = setting\ntokenizer = scanner'],
 ['Go bool member', 'item := Question{Secret: cmd == "ask-secret", AllowOther: true}'],
 ['Go variable member', 'opts := Options{Token: config.Token, Secret: false}'],
 ['grep Go variable member', 'src/config.go:12:    Token: sessionToken,'],
 ['Swift type', 'public var secret: Bool = false\nprivate let apiKey: String? = nil'],
 ['Swift parameter', 'func ask(secret: Bool = false, token: String) {}'],
 ['TypeScript members', 'interface Config {\n token: string;\n password?: string;\n}'],
 ['TypeScript parameter', 'function connect(token: string, secret: boolean = false) {}'],
 ['JavaScript reference', 'const token = config.token; const secret = getSecret();'],
 ['Python declaration ref', 'self.password = os.environ.get("PASSWORD")'],
 ['empty typed constructor', 'public var secret: Foundation.Data = Data()'],
 ['shell references', 'export TOKEN=$SESSION_TOKEN\npassword=${PASSWORD}\napi_key=${CONFIG_API_KEY}'],
 ['redaction', 'password=[REDACTED]\ntoken=********\nsecret=<masked>'],
 ['data booleans are not strings', '{"secret": false, "token": null}'],
 ['separated grep header not YAML value', 'password:\nsrc/other.go:12: value'],
 ['indented grep header not YAML value', 'password:\n  src/other.go:12: value'],
 ['no missing-value join', 'token=\nnext_command --help'],
 ['comparison', 'token == expectedToken; token != otherToken;'],
 ['weak env string', 'password=true'],
 ['dot-bearing password', 'password=first.second.third'],
 ['structured type string', {secret:'Bool'}],
 ['structured expression string', {token:'config.sessionToken'}],
 ['structured code-looking string', {password:'getSecret()'}],
 ['structured boolean-looking string', {password:'true'}],
 ['structured multiline string', {token:'first\nsecond'}],
 ['explicit type name as value', 'password=String'],
 ['raw type word not declaration', 'secret: Bool'],
];
const syntheticSecret = 'sY9!nT4_hE7#tI2-cK8';
const blocked = [
 ['env string', `password=${syntheticSecret}`],
 ['hash-bearing password', `password=#${syntheticSecret}`],
 ['shell option', `tool --password=${syntheticSecret}`],
 ['shell quoted option', `tool --api-key="${syntheticSecret}"`],
 ['quoted object literal', `opts := Options{Password: "${syntheticSecret}", Secret: false}`],
 ['Swift initializer', `private let token: String = "${syntheticSecret}"`],
 ['typed parameter initializer', `function connect(token: string = "${syntheticSecret}") {}`],
 ['Swift parameter initializer', `func connect(password: String = "${syntheticSecret}") {}`],
 ['code property assignment', `config.password = "${syntheticSecret}"`],
 ['multiline quoted value', `token =\n    "${syntheticSecret}"`],
 ['multiline unindented quoted value', `token =\n"${syntheticSecret}"`],
 ['YAML multiline scalar', `password:\n  ${syntheticSecret}`],
 ['YAML block scalar', `token: |\n  ${syntheticSecret}`],
 ['JSON literal', `{"token": "${syntheticSecret}"}`],
 ['HTTP authorization', `Authorization: Bearer ${syntheticSecret}`],
 ['HTTP Basic', 'Authorization: Basic c3ludGhldGljOnBhc3N3b3Jk'],
 ['comment includes actual credential', `// token=${syntheticSecret}`],
 ['literal next to allowed statement', `const token = getToken(); password=${syntheticSecret}`],
 ['encoded literal', 'let secret: Data = Data(base64Encoded: "U1lOVEhFVElDX1NFQ1JFVA==")'],
 ['Buffer literal', 'const token = Buffer.from("U1lOVEhFVElDX1RPS0VO", "base64")'],
 ['password URL', 'https://example:SYNTHETIC_PASSWORD@proxy.example.invalid'],
 ['private key', '-----BEGIN PRIVATE KEY-----'],
 ['bare provider token format', 'ghp_'+'A'.repeat(36)],
 ['bare Anthropic format', 'sk-ant-api03-'+'A'.repeat(40)],
 ['bare Slack format', 'xoxb-1234567890-1234567890-SYNTHETIC'],
 ['JWT format', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJTWU5USEVUSUMifQ.'+'A'.repeat(32)],
];
// YAML block scalars are introduced by | or > and contain the value below.
for (const [name,value,expected] of [...clean.map(x=>[x[0],x[1],false]),...blocked.map(x=>[x[0],x[1],true])]) {
 test('credentials: '+name,()=>{
  for(const source of ['user.prompt','tool.input','tool.result','prompt.context']) {
   const result=compile().scan(value,source,'Bash');
   assert.equal(result.blocked,expected,`${source}: ${name}`);
   if(expected)assert.equal(result.rule,'security.credentials');
  }
 });
}
test('clean source plus genuine secret never exempts the surrounding result',()=>{
 const e=compile();
 for(const [,value] of clean) {
  assert.equal(e.scan(value+'\npassword='+syntheticSecret).rule,'security.credentials');
  assert.equal(e.scan({stdout:value,stderr:'token='+syntheticSecret}).rule,'security.credentials');
 }
});
test('field boundaries do not suffix-match command names',()=>{
 for(const name of ['secret','token','password','api_key']) for(const prefix of ['ask-','my_','fetch.unknown-']) {
  assert.equal(credentialReason(`${prefix}${name}:\nnext/file.go:5: item`),null);
 }
});
test('diagnostic reasons never include matched text',()=>{
 assert.equal(credentialReason('token='+syntheticSecret),'unquoted-value');
 assert.equal(credentialReason(`const token = "${syntheticSecret}"`),'literal-value');
 assert.equal(credentialReason(syntheticSecret,'token'),'structured-value');
});

const fixtureToken = 'sk-dummy-secret-value';
const goFixture = `func fixture() {\n  env := map[string]string{"APP_API_TOKEN": "${fixtureToken}"}\n}`;

test('full descriptive key placeholders pass in token and password fields', () => {
 const engine = compile();
 for (const value of [
  {stdout: goFixture + '\n1:func fixture() {\n', stderr: ''},
  {stderr: goFixture, isError: true},
  {apiToken: 'sk-super-secret-value'},
  {apiToken: 'sk-qrzvp-secret-value'},
  {password: fixtureToken},
 ]) assert.equal(engine.scan(value, 'tool.result', 'Bash').blocked, false);
});

test('key placeholders preserve adjacent, independently formatted, and exact detections', () => {
 const engine = compile();
 for (const [extra, rule] of [
  [`password="${syntheticSecret}"`, 'security.credentials'],
  ['api_token="sk-dummy-secret-value-Z8r6W2m5"', 'security.credentials'],
  ['sk-ant-api03-' + 'Z'.repeat(36), 'security.credentials'],
  [`https://acct:${fixtureToken}@service.example.invalid`, 'security.credentials'],
  ['hostname: SyntheticHost', 'identity.environment'],
  ['deviceId: SYNTHETIC123456', 'identity.device'],
 ]) assert.equal(engine.scan(`${goFixture}\n${extra}`, 'tool.result', 'Bash').rule, rule, extra);
 assert.equal(engine.scan({apiToken: 'sk-dummy-secret-value-Z8r6W2m5'}).rule, 'security.credentials');
 const config = structuredClone(defaults);
 config.rules.push({
  id: 'custom.fixture', enabled: true, sources: ['tool.result'], action: 'block',
  detector: {kind: 'exact', values: [fixtureToken], caseSensitive: true},
 });
 assert.equal(compile(config).scan(goFixture).rule, 'custom.fixture');
});
