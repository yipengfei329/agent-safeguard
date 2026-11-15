import {test} from 'node:test';
import assert from 'node:assert/strict';
import {compile} from './strict-engine.mjs';
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
];
const blocked = [
 ['env string', 'password=SYNTHETIC_PASSWORD'],
 ['weak env string', 'password=true'],
 ['dot-bearing password', 'password=first.second.third'],
 ['hash-bearing password', 'password=#SYNTHETIC_PASSWORD'],
 ['shell option', 'tool --password=SYNTHETIC_PASSWORD'],
 ['shell quoted option', 'tool --api-key="SYNTHETIC_API_KEY"'],
 ['quoted object literal', 'opts := Options{Password: "SYNTHETIC_PASSWORD", Secret: false}'],
 ['Swift initializer', 'private let token: String = "SYNTHETIC_TOKEN"'],
 ['typed parameter initializer', 'function connect(token: string = "SYNTHETIC_TOKEN") {}'],
 ['Swift parameter initializer', 'func connect(password: String = "SYNTHETIC_PASSWORD") {}'],
 ['code property assignment', 'config.password = "SYNTHETIC_PASSWORD"'],
 ['multiline quoted value', 'token =\n    "SYNTHETIC_TOKEN"'],
 ['multiline unindented quoted value', 'token =\n"SYNTHETIC_TOKEN"'],
 ['YAML multiline scalar', 'password:\n  SYNTHETIC_PASSWORD'],
 ['YAML block scalar', 'token: |\n  SYNTHETIC_TOKEN'],
 ['JSON literal', '{"token": "SYNTHETIC_TOKEN"}'],
 ['structured type string', {secret:'Bool'}],
 ['structured expression string', {token:'config.sessionToken'}],
 ['structured code-looking string', {password:'getSecret()'}],
 ['structured boolean-looking string', {password:'true'}],
 ['structured multiline string', {token:'first\nsecond'}],
 ['explicit type name as value', 'password=String'],
 ['raw type word not declaration', 'secret: Bool'],
 ['HTTP authorization', 'Authorization: Bearer SYNTHETIC_TOKEN'],
 ['HTTP Basic', 'Authorization: Basic c3ludGhldGljOnBhc3N3b3Jk'],
 ['comment includes actual credential', '// token=SYNTHETIC_TOKEN'],
 ['literal next to allowed statement', 'const token = getToken(); password=SYNTHETIC_PASSWORD'],
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
  assert.equal(e.scan(value+'\npassword=SYNTHETIC_PASSWORD').rule,'security.credentials');
  assert.equal(e.scan({stdout:value,stderr:'token=SYNTHETIC_TOKEN'}).rule,'security.credentials');
 }
});
test('field boundaries do not suffix-match command names',()=>{
 for(const name of ['secret','token','password','api_key']) for(const prefix of ['ask-','my_','fetch.unknown-']) {
  assert.equal(credentialReason(`${prefix}${name}:\nnext/file.go:5: item`),null);
 }
});
test('diagnostic reasons never include matched text',()=>{
 assert.equal(credentialReason('token=SYNTHETIC_TOKEN'),'unquoted-value');
 assert.equal(credentialReason('const token = "SYNTHETIC_TOKEN"'),'literal-value');
 assert.equal(credentialReason('SYNTHETIC_TOKEN','token'),'structured-value');
});
