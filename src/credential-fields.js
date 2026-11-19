// Candidate names must end in a credential role. Splitting complete words
// keeps DB_PASSWORD / serviceApiToken while rejecting notpassword and metadata
// such as token_count / password_label. This is not a substring allowlist.
function fieldWords(name) {
  if(!name||name.length>256)return [];
  const leaf=name.split('.').at(-1).replace(/^--/,'').replace(/\?$/,'').replace(/^["']|["']$/g,'');
  return leaf.replace(/([A-Z]+)([A-Z][a-z])/g,'$1_$2').replace(/([a-z0-9])([A-Z])/g,'$1_$2').toLowerCase().split(/[_-]+/).filter(Boolean);
}

// The Windows manifest attribute identifies a signing key, not a credential.
// Require a complete start tag with ordinary XML attributes on both sides.
const xmlAttribute = String.raw`[ \t\r\n]+[A-Za-z_][\w.:-]*[ \t\r\n]*=[ \t\r\n]*(?:"[^"<]*"|'[^'<]*')`;
const assemblyPrefix = new RegExp(String.raw`^<assemblyIdentity(?:${xmlAttribute})*[ \t\r\n]+$`);
const assemblySuffix = new RegExp(String.raw`^(?:"[^"<\\]*"|'[^'<\\]*')(?:${xmlAttribute})*[ \t\r\n]*/?>`);
function assemblyTokenEvidence(before, rhs) {
  const start = before.lastIndexOf('<');
  return start !== -1 && assemblyPrefix.test(before.slice(start)) && assemblySuffix.test(rhs)
    ? 'assembly-identity'
    : 'value';
}

// This is evidence about one field, never an exemption for its value. The
// value policy must independently recognize a complete diagnostic label.
export function credentialFieldEvidence(name) {
  if (name === 'publicKeyToken') return assemblyTokenEvidence;
  return /err/i.test(name)&&['err','error'].includes(fieldWords(name)[0])?'diagnostic-label':'value';
}
export function credentialFieldKind(name) {
  const words=fieldWords(name);
  const last=words.at(-1),prior=words.at(-2);
  // Preserve historically supported collapsed spellings as complete words.
  if(['apikey','accesskey','privatekey','secretkey','accesstoken','refreshtoken','clientsecret'].includes(last))return 'token';
  if(last==='password'||last==='passwd')return 'password';
  if(last==='token'&&!['max','min','num','total'].includes(prior))return 'token';
  if(last==='secret'||last==='authorization'||last==='key'&&['api','private','secret','access'].includes(prior))return 'token';
  return null;
}
