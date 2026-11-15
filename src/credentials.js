import {placeholder,secretValue} from './credential-values.js';
import {credentialFieldKind} from './credential-fields.js';
import {assignmentMatchers,assignmentReason} from './assignment-values.js';
const policy={matchers:assignmentMatchers(undefined,/password|passwd|token|secret|authorization|key/i),classify:credentialFieldKind,accept:secretValue};
const privateKey = /-----BEGIN (?:(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/;
const credentialURL = /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@?#"'<>]*:([^\s/@?#"'<>]+)@/gi;
// Deliberately specific formats, not generic entropy or every "sk-" identifier.
const signature = /\b(?:sk-ant-api\d{2}-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|xox[baprs]-[A-Za-z0-9-]{20,}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{20,})\b/;

export function credentialReason(text,key='',budget=()=>{}) {
  if(privateKey.test(text))return 'private-key';
  if(signature.test(text))return 'token-format';
  credentialURL.lastIndex=0;
  for(const m of text.matchAll(credentialURL))if(!placeholder(m[1]))return 'url-password';
  return assignmentReason(text,key,policy,budget);
}
export function hasCredentials(text,key='',budget) {
  return credentialReason(text,key,budget)!==null;
}
