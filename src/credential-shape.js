// Positive evidence for actual credential material. Identifier separators
// (- _ . /) segment human names; they never supply secret character complexity.
// Precompiled disjoint-separator regexes avoid per-candidate array allocations.
const tokenAlphabet=/^[A-Za-z0-9_+./-]+={0,2}$/;
const passwordAlphabet=/^[A-Za-z0-9_+/.!@#%&*?-]+$/;
export const credentialAtoms=/[A-Za-z0-9_+/.!@#%&*?-]+/g;
const secretSymbols=/[!@#%&*?+=]/;

const segWord='(?:[a-z]{1,23}|[A-Z]{1,23}|[A-Z][a-z]{1,22}|[A-Za-z][a-z]{2,20}(?:[A-Z][a-z]{2,20})+)';
const segNum='\\d{1,6}';
const segTagToken='(?:(?:[a-z]{1,20}|[A-Z]{1,20}|[A-Z][a-z]{1,19})\\d{1,6}|\\d{1,6}(?:[a-z]{3,20}|[A-Z]{3,20}|[A-Z][a-z]{2,19})|[a-z]\\d{1,3}[a-z])';
const segTagPassword='(?:(?:[a-z]{1,20}|[A-Z]{1,20})\\d{1,6}|[A-Z][a-z]{1,19}\\d|\\d{1,6}(?:[a-z]{3,20}|[A-Z]{3,20}|[A-Z][a-z]{2,19})|[a-z]\\d{1,3}[a-z])';
const tokenSeg='(?:'+segWord+'|'+segNum+'|'+segTagToken+')';
const passwordSeg='(?:'+segWord+'|'+segNum+'|'+segTagPassword+')';
const tokenLabelRe=new RegExp('^[-_./]*'+tokenSeg+'(?:[-_./]+'+tokenSeg+')*[-_./]*$');
const passwordLabelRe=new RegExp('^[-_./]*'+passwordSeg+'(?:[-_./]+'+passwordSeg+')*[-_./]*$');
const shortPrefixedRe=new RegExp('^[-_./]*'+segWord+'(?:[-_./]+'+segWord+'){0,2}[-_./]+([a-z0-9]{2,11}|[A-Z0-9]{2,11})[-_./]*$');
const hexOnlyRe=/^[0-9a-f]+$/i;
const uuidShape=/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const onlySeparators=/^[-_./]+$/;

export function labelEvidence(value,password=false) {
  if(!value||value.length>128||value.endsWith('=')||hexOnlyRe.test(value)||uuidShape.test(value))return false;
  if(onlySeparators.test(value)||(password?passwordLabelRe:tokenLabelRe).test(value))return true;
  if(!password){
    const tail=shortPrefixedRe.exec(value)?.[1];
    if(tail&&/[a-z]/i.test(tail)&&/\d/.test(tail))return true;
  }
  return false;
}

export function atomicEvidence(value,password=false) {
  if(value.length<8)return null;
  const encoded=tokenAlphabet.test(value),mixed=passwordAlphabet.test(value);
  if(!encoded&&!mixed)return null;
  if(labelEvidence(value,password))return null;
  const sample=value.slice(0,256);
  const entropy=diversity(sample);
  if(hexOnlyRe.test(sample)){
    return sample.length>=(password?24:32)&&entropy>=3?'opaque-token':null;
  }
  const categories=Number(/[a-z]/.test(sample))+Number(/[A-Z]/.test(sample))+Number(/[0-9]/.test(sample))+Number(secretSymbols.test(sample));
  if(encoded&&(
    /[0-9]/.test(sample)&&/[A-Za-z]/.test(sample)&&sample.length>=12&&entropy>=3||
    categories>=2&&sample.length>=20&&entropy>=3.5||
    sample.length>=24&&entropy>=4.1))return 'opaque-token';
  if(password&&sample.length>=8&&categories>=3&&entropy>=2.5||
    mixed&&/[!@#%&*?]/.test(sample)&&sample.length>=12&&categories>=(password?2:3)&&entropy>=3)return 'mixed-secret';
  return null;
}

// Multiword passphrases require 4+ words, letters, digits and password symbols,
// and must not be UI validation/instruction prose.
const uiMetaWords=/\b(?:please|enter|provide|specify|confirm|must|should|cannot|invalid|incorrect|wrong|missing|required|expired|expires|forgot|reset|retry|attempts?|remaining|characters?|chars?|digits?|letters?|uppercase|lowercase|minimum|maximum|least|between|match|again|error|failed|warning)\b/i;
export function phraseEvidence(value) {
  if(!/^[A-Za-z0-9_!@#%&*?.,' -]+$/.test(value)||!/[ \t]/.test(value)||/\?$/.test(value)||uiMetaWords.test(value))return null;
  const words=value.trim().split(/\s+/);
  if(words.length<4||!/[A-Za-z]/.test(value)||!/[0-9]/.test(value)||!/[!@#%&*?]/.test(value))return null;
  return diversity(value.slice(0,256))>=3?'password-phrase':null;
}

function diversity(sample) {
  const counts=new Map();for(const c of sample)counts.set(c,(counts.get(c)||0)+1);
  let entropy=0;for(const count of counts.values()){const p=count/sample.length;entropy-=p*Math.log2(p);}
  return entropy;
}
