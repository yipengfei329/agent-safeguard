import {symbolReference} from './symbol-values.js';
import {atomicEvidence,phraseEvidence,credentialAtoms,labelEvidence} from './credential-shape.js';
import {placeholder} from './value-syntax.js';
export {placeholder,readQuoted} from './value-syntax.js';

function nonSecretLocatorOrPattern(value) {
  if(value.length>256)return false;
  if(/^(?:application|text|image|audio|video|multipart)\/[a-z][a-z0-9.+-]*$/i.test(value))return true;
  if(/^(?:\.{0,2}\/)(?:[a-z][a-z._-]*\/)+[a-z][a-z._-]*$/i.test(value))return true;
  if(/^[a-z][a-z0-9+.-]*:\/\/[a-z0-9.-]+(?::[0-9]+)?(?:\/[a-z._-]+)*\/?$/i.test(value))return true;
  if(/^\^?\[(?:\\.|[^\]\\])+\](?:[+*?]|\{\d+(?:,\d*)?\})\$?$/.test(value))return true;
  return false;
}

// Inspect fixed pieces independently; interpolation syntax is not entropy and
// pieces separated by an unknown value cannot be concatenated.
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

export function secretValue(value, name='', budget=()=>{}) {
  value=value.trim();
  const password=/pass(?:word|wd)/i.test(name);
  if(value.length<8||placeholder(value)||labelEvidence(value,password))return false;
  if(value.includes('${')||value.includes('{{')){
    for(const part of templateLiterals(value,budget))if(secretValue(part,name,budget))return true;
    return false;
  }
  if(symbolReference(value))return false;
  if(/^[A-Za-z_$][\w$]*(?:[?.][A-Za-z_$][\w$]*)+(?:\([^\r\n]*\))?$/.test(value)||/^[A-Za-z_$][\w$]*\([^\r\n]*\)$/.test(value))return false;
  if(/^(?:&(?:'[A-Za-z_]\w*[ \t]+)?(?:mut[ \t]+)?)?[A-Za-z_]\w*(?:::\w+)*(?:<[^=\r\n]+>)?(?:\[\]|\?)?$/.test(value)&&/[<>&?:]/.test(value))return false;
  if(nonSecretLocatorOrPattern(value))return false;
  if(/^(?:Bearer|Basic)[ \t]+/i.test(value))return secretValue(value.replace(/^(?:Bearer|Basic)[ \t]+/i,''),name,budget);
  if(/[ \t]/.test(value)&&!password)return false;
  if(atomicEvidence(value,password)||password&&phraseEvidence(value))return true;
  for(const m of value.matchAll(credentialAtoms)){
    budget();
    if(m[0].length<8||m[0].length===value.length)continue;
    if(secretValue(m[0],name,budget))return true;
  }
  return false;
}
