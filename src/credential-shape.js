// Positive evidence for actual credential material. Structural delimiters are
// not a secret alphabet: combining '<', a label, ':' and '>' must not raise a
// harmless reference above an entropy threshold. No placeholder names here.
const tokenAlphabet=/^[A-Za-z0-9_+./-]+={0,2}$/;
const passwordAlphabet=/^[A-Za-z0-9_+/.!@#%&*?-]+$/;
export const credentialAtoms=/[A-Za-z0-9_+/.!@#%&*?-]+/g;
export function atomicEvidence(value,password=false) {
  if(value.length<8)return null;
  const encoded=tokenAlphabet.test(value),mixed=passwordAlphabet.test(value);
  if(!encoded&&!mixed)return null;
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
