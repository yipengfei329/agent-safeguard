// Positive evidence for actual credential material. Structural delimiters are
// not a secret alphabet: combining '<', a label, ':' and '>' must not raise a
// harmless reference above an entropy threshold. No placeholder names here.
const tokenAlphabet=/^[A-Za-z0-9_+./-]+={0,2}$/;
const passwordAlphabet=/^[A-Za-z0-9_+/.!@#%&*?-]+$/;
export const credentialAtoms=/[A-Za-z0-9_+/.!@#%&*?-]+/g;
// A short numeric prefix/suffix does not make a word-shaped label opaque.
// This is bounded morphology, not a dictionary or a test-file exception. It
// cannot establish whether a label-shaped value is a working credential.
const word='(?:[a-z]{3,20}|[A-Z]{3,20}|[A-Z][a-z]{2,19})';
const words=word+'(?:[-_]'+word+'){0,2}';
const numberedLabel=new RegExp('^(?:'+words+'[-_]?\\d{1,6}|\\d{1,6}[-_]?'+words+')$');
const prefixedShortMaterial=new RegExp('^'+words+'[-_]([a-z0-9]{2,11}|[A-Z0-9]{2,11})$');
export function labelEvidence(value) {
  if(value.length>64||/^[a-f0-9]+$/i.test(value))return false;
  if(numberedLabel.test(value))return true;
  // A readable prefix must not supply the missing length of a short, uniform-
  // case alphanumeric suffix. Preserve longer material and mixed-case suffixes.
  const suffix=prefixedShortMaterial.exec(value)?.[1];
  return !!suffix&&/[a-z]/i.test(suffix)&&/\d/.test(suffix);
}
export function atomicEvidence(value,password=false) {
  if(value.length<8)return null;
  const encoded=tokenAlphabet.test(value),mixed=passwordAlphabet.test(value);
  if(!encoded&&!mixed)return null;
  // Password fields keep their existing evidence requirements: word+number
  // passwords can be real. Explicit provider signatures/exact rules run outside
  // this generic heuristic and retain precedence.
  if(!password&&labelEvidence(value))return null;
  const sample=value.slice(0,256);
  const categories=Number(/[a-z]/.test(sample))+Number(/[A-Z]/.test(sample))+Number(/[0-9]/.test(sample))+Number(/[^a-zA-Z0-9]/.test(sample));
  const entropy=diversity(sample);
  if(encoded&&(
    sample.length>=12&&categories>=2&&/[0-9\W_]/.test(sample)&&entropy>=3||
    sample.length>=24&&entropy>=3.5))return 'opaque-token';
  if(password&&sample.length>=8&&categories>=3&&entropy>=2.5||
    mixed&&/[^a-zA-Z0-9]/.test(sample)&&sample.length>=12&&categories>=(password?2:3)&&entropy>=3)return 'mixed-secret';
  return null;
}

// Password phrases are a separate value shape, not a fallback that scores any
// long string. Keep multiword passwords; ordinary API-token prose is not one.
export function phraseEvidence(value) {
  if(!/^[A-Za-z0-9_!@#%&*?.,' -]+$/.test(value)||!/[ \t]/.test(value))return null;
  const words=value.trim().split(/\s+/);
  if(words.length<4||!/[A-Za-z]/.test(value)||!/[0-9]/.test(value)||!/[!@#%&*?]/.test(value))return null;
  return diversity(value.slice(0,256))>=3?'password-phrase':null;
}

function diversity(sample) {
  const counts=new Map();for(const c of sample)counts.set(c,(counts.get(c)||0)+1);
  let entropy=0;for(const count of counts.values()){const p=count/sample.length;entropy-=p*Math.log2(p);}
  return entropy;
}
