import {symbolName,symbolReference} from './symbol-values.js';
import {atomicEvidence,phraseEvidence,credentialAtoms,labelEvidence} from './credential-shape.js';
// Candidate-local negative evidence, followed by positive secret evidence.
// These are syntax/value heuristics, not proof that a credential is invalid.
// Explicit provider formats and exact rules are checked independently.
import {placeholder} from './value-syntax.js';
export {placeholder,readQuoted} from './value-syntax.js';

// Whole-value vocabulary, never substring stopwords such as "test" or "example".
const labelWords = new Set('access refresh authentication authorization api client secret token password passwd key aws input field required optional'.split(' '));
function descriptiveValue(value,name) {
  if(value.length>256)return false;
  const words=value.toLowerCase().split(/[_-]/);
  if(words.length>=2&&words.every(w=>labelWords.has(w)))return true;
  // Lowercase word labels are common in token enums and isolated diff lines.
  // Retain ordinary password passphrases and unsegmented opaque alpha tokens.
  if(!/pass(?:word|wd)/i.test(name)&&/^[a-z]{3,}(?:[-_][a-z]{3,})+$/.test(value))return true;
  if(/^(?:application|text|image|audio|video|multipart)\/[a-z][a-z0-9.+-]*$/i.test(value))return true;
  // Readable locators only: no query, fragment, userinfo, opaque path segment,
  // or arbitrary random value is exempted by the mere presence of a slash.
  if(/^(?:\.{0,2}\/)(?:[a-z][a-z._-]*\/)+[a-z][a-z._-]*$/i.test(value))return true;
  if(/^[a-z][a-z0-9+.-]*:\/\/[a-z0-9.-]+(?::[0-9]+)?(?:\/[a-z._-]+)*\/?$/i.test(value))return true;
  if(/^\^?\[(?:\\.|[^\]\\])+\](?:[+*?]|\{\d+(?:,\d*)?\})\$?$/.test(value))return true;
  // UI instructions, not a blanket passphrase exemption. Mixed opaque words
  // or punctuation disqualify this path; arbitrary multiword passwords remain.
  if(/^[a-z\s\d'".,!?-]+$/i.test(value)&&
    value.replace(/['".,!?-]/g,' ').trim().split(/\s+/).every(word=>/^(?:[A-Z]?[a-z]+|\d+)$/.test(word))&&
    /^(?:(?:please\s+)?(?:enter|provide|specify|confirm)\s+(?:your\s+|the\s+)?|password\s+(?:must|should)\s+)/i.test(value)&&
    /\b(?:password|token|key|secret)\b/i.test(value))return true;
  return false;
}

// Inspect fixed pieces independently; interpolation syntax is not entropy and
// pieces separated by an unknown value cannot be concatenated. Balanced braces
// and quoted expression strings are opaque. An unfinished expression keeps the
// fixed prefix, but does not invent a literal suffix. Not a language evaluator.
function* templateLiterals(value,budget) {
  let start=0;
  for(let i=0;i<value.length;i++){
    if((i&127)===0)budget();
    const opener=value.slice(i,i+2);
    if(opener!=='${'&&opener!=='{{')continue;
    yield value.slice(start,i);
    let depth=opener==='${'?1:2,quote='';i+=2;
    for(;i<value.length&&depth;i++){
      if((i&127)===0)budget();
      const c=value[i];
      if(quote){if(c==='\\')i++;else if(c===quote)quote='';continue;}
      if(c==='"'||c==="'"||c==='`')quote=c;
      else if(c==='{'){if(++depth>64)throw Error('TEMPLATE_DEPTH_LIMIT');}
      else if(c==='}')depth--;
    }
    start=i;i--;
  }
  yield value.slice(start);
}

// A separator adjoining an interpolation is a boundary, not extra secret
// material. Only recognize an already-supported descriptive token label at
// that boundary; do not trim arbitrary credentials or exempt whole templates.
function templateLabel(part,name) {
  if(/pass(?:word|wd)/i.test(name)||part.length>256)return false;
  const label=part.replace(/^[-_]+|[-_]+$/g,'');
  return label!==part&&label.length>=3&&descriptiveValue(label,name);
}

export function secretValue(value, name='', budget=()=>{}, evidence='value') {
  value=value.trim();
  // Only an explicit name slot can reinterpret an uppercase identifier. Plain
  // fields, quoted passwords and structured values retain value semantics.
  if(evidence==='symbol-name'&&symbolName(value))return false;
  const password=/pass(?:word|wd)/i.test(name);
  // This whole-value shape cannot contain interpolation or a secret atom.
  // Evaluate it before the more expensive expression/prose classifiers.
  if(!password&&labelEvidence(value))return false;
  if(value.length<8||placeholder(value)||/^(?:changeme|change_me|placeholder|redacted|your[_ -](?:api[_ -]?key|password|token|secret)(?:[_ -]here)?|insert[_ -](?:api[_ -]?key|password|token|secret)[_ -]here)$/i.test(value))return false;
  if(value.includes('${')||value.includes('{{')){
    for(const part of templateLiterals(value,budget))if(!templateLabel(part,name)&&secretValue(part,name,budget))return true;
    return false;
  }
  if(symbolReference(value))return false;
  if(/^(?:true|false|null|nil|undefined|None|Bool|String|boolean|string|number)$/i.test(value))return false;
  if(/^[A-Za-z][a-z]{2,}(?:[A-Z][a-z]{2,})+$/.test(value))return false;
  if(/^[A-Za-z_$][\w$]*(?:[?.][A-Za-z_$][\w$]*)+(?:\([^\r\n]*\))?$/.test(value)||/^[A-Za-z_$][\w$]*\([^\r\n]*\)$/.test(value))return false;
  if(/^(?:&(?:'[A-Za-z_]\w*[ \t]+)?(?:mut[ \t]+)?)?[A-Za-z_]\w*(?:::\w+)*(?:<[^=\r\n]+>)?(?:\[\]|\?)?$/.test(value)&&/[<>&?:]/.test(value))return false;
  if(descriptiveValue(value,name))return false;
  // Authentication schemes describe a carrier, not part of the opaque value.
  if(/^(?:Bearer|Basic)[ \t]+/i.test(value))return secretValue(value.replace(/^(?:Bearer|Basic)[ \t]+/i,''),name,budget);
  if(/[ \t]/.test(value)&&!password)return false;
  if(atomicEvidence(value,password)||password&&phraseEvidence(value))return true;
  // Evaluate material on either side of syntax independently. Do not concatenate
  // labels or count their delimiters as password complexity. Candidate-local
  // label/reference filtering still applies to each piece. A real key wrapped
  // in brackets is checked, never a whole-value bracket exemption.
  for(const m of value.matchAll(credentialAtoms)){
    budget();
    if(m[0].length<8||m[0].length===value.length)continue;
    if(secretValue(m[0],name,budget))return true;
  }
  return false;
}
