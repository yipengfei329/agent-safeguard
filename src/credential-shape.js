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
export const providerPrefixRe=/^(?:sk-ant-(?:api|admin)\d{2}-|sk-(?:proj|svcacct|admin)-|gh[pousr]_|github_pat_(?:[A-Za-z0-9]+_)?|glpat-|xox[baprs]-(?:\d+-)*|(?:AKIA|ASIA)|AIza|(?:sk|rk)_(?:live|test)_|whsec_|hf_|npm_|pypi-|SG\.)/;
const qwerty='qwertyuiopasdfghjklzxcvbnm';

// Zero-allocation check for human-typed ascending/descending/keyboard dummy runs
// (e.g. 1234567890abcdefghij) whose zero-order character diversity is artificially high.
export function syntheticSequence(value) {
  if(!value||value.length<8||value.length>256)return false;
  let start=0;
  if(
    value.startsWith('sk-')||value.startsWith('gh')||value.startsWith('glpat-')||
    value.startsWith('xox')||value.startsWith('AKIA')||value.startsWith('ASIA')||
    value.startsWith('AIza')||value.startsWith('rk_')||value.startsWith('whsec_')||
    value.startsWith('hf_')||value.startsWith('npm_')||value.startsWith('pypi-')||value.startsWith('SG.')
  ){
    const m=providerPrefixRe.exec(value);
    if(m)start=m[0].length;
  }
  let digitMask=0,alphaMask=0,distinct=0,alnumCount=0,seqSteps=0,prev=0;
  for(let i=start;i<value.length;i++){
    let code=value.charCodeAt(i);
    if(code>=65&&code<=90)code+=32;
    const isDigit=code>=48&&code<=57;
    const isLower=code>=97&&code<=122;
    if(!isDigit&&!isLower)continue;
    if(isDigit){const bit=1<<(code-48);if(!(digitMask&bit)){digitMask|=bit;distinct++;}}
    else{const bit=1<<(code-97);if(!(alphaMask&bit)){alphaMask|=bit;distinct++;}}
    if(alnumCount>0){
      const prevDigit=prev>=48&&prev<=57;
      if(prevDigit===isDigit&&Math.abs(code-prev)===1)seqSteps++;
      else if(
        (prev===57&&(code===48||code===97))||(prev===48&&(code===49||code===97))||
        (prev===102&&code===48)||(prev===122&&(code===48||code===49||code===97))||
        (!prevDigit&&!isDigit&&qwerty.includes(String.fromCharCode(prev,code)))
      )seqSteps++;
    }
    prev=code;
    alnumCount++;
  }
  return alnumCount>=8&&distinct>=4&&seqSteps*4>=(alnumCount-1)*3;
}

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
  if(labelEvidence(value,password)||syntheticSequence(value))return null;
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
