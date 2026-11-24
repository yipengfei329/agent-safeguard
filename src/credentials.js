import {placeholder,secretValue} from './credential-values.js';
import {credentialFieldKind} from './credential-fields.js';
import {assignmentMatchers,assignmentReason} from './assignment-values.js';
const policy={matchers:assignmentMatchers(undefined,/password|passwd|token|secret|authorization|key/i),classify:credentialFieldKind,accept:secretValue};
const privateKey = /-----BEGIN (?:(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/;
const credentialURL = /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@?#"'<>]*:([^\s/@?#"'<>]+)@/gi;
// High-specificity provider formats checked independently of field context.
const signature = /\b(?:sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|(?!(?:AKIA|ASIA)[0-9A-Z]{9}EXAMPLE\b)(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|(?:sk|rk)_live_[0-9A-Za-z]{20,}|whsec_[0-9A-Za-z]{24,}|hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{30,}|pypi-[A-Za-z0-9_-]{40,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{20,})\b/;

export function credentialReason(text,key='',budget=()=>{},syntax) {
  if(privateKey.test(text))return 'private-key';
  if(signature.test(text))return 'token-format';
  credentialURL.lastIndex=0;
  for(const m of text.matchAll(credentialURL))if(!placeholder(m[1]))return 'url-password';
  return assignmentReason(text,key,policy,budget,syntax);
}
export function hasCredentials(text,key='',budget) {
  return credentialReason(text,key,budget)!==null;
}
