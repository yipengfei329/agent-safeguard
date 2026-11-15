// Shared scalar syntax; independent of credential or identity policy.
const reference = /^(?:\$\{[A-Za-z_][\w.:-]*\}|\$[A-Za-z_][\w]*|\{\{[ \t]*[\w.]+[ \t]*\}\}|%[A-Za-z_][\w]*%)$/;
const redacted = /^(?:\*{3,}|\[REDACTED\]|<redacted>|<masked>|<(?:your[-_ ]?)?(?:access[-_ ]?|refresh[-_ ]?|api[-_ ]?)?(?:password|token|key|secret)>)$/i;
export function placeholder(value) { return reference.test(value) || redacted.test(value); }

// Preserve source length separately from decoded value length. Escaping must
// not inflate entropy or misalign a following concatenation/initializer.
export function readQuoted(text,raw=false) {
  const quote=text[0];if(!['"',"'",'`'].includes(quote))return null;
  const delimiter=quote!=='`'&&text.startsWith(quote.repeat(3))?quote.repeat(3):quote;
  let value='';
  for(let i=delimiter.length;i<text.length;i++){
    const c=text[i];
    if(c===quote&&text.startsWith(delimiter,i))return {value,length:i+delimiter.length,complete:true};
    if(c==='\\'&&i+1<text.length){
      const next=text[++i],hex=text.slice(i+1,i+(next==='u'?5:3));
      if(raw)value+='\\'+next;
      else if((next==='u'&&/^[0-9a-f]{4}$/i.test(hex))||(next==='x'&&/^[0-9a-f]{2}$/i.test(hex))){value+=String.fromCharCode(parseInt(hex,16));i+=hex.length;}
      else if(Object.hasOwn({n:1,r:1,t:1,b:1,f:1,v:1},next))value+=({n:'\n',r:'\r',t:'\t',b:'\b',f:'\f',v:'\v'})[next];
      else if(next===quote||next==='\\'||next==='/')value+=next;
      else value+='\\'+next;
    }else value+=c;
  }
  return {value,length:text.length,complete:false};
}

// Static Python string prefixes and Rust hash-delimited raw strings. Dynamic
// f-strings / tagged templates are expressions, not opaque literal values.
export function readSourceQuoted(text) {
  const plain=readQuoted(text);if(plain)return plain;
  const rust=text.match(/^r(#{1,8})"/);
  if(rust){const end=text.indexOf('"'+rust[1],rust[0].length);return {value:text.slice(rust[0].length,end<0?undefined:end),length:end<0?text.length:end+1+rust[1].length,complete:end>=0};}
  const prefix=text.match(/^(?:[rRuUbB]|[rR][bB]|[bB][rR])(?=["'])/);
  if(!prefix)return null;
  const found=readQuoted(text.slice(prefix[0].length),/[rR]/.test(prefix[0]));
  return found?{...found,length:found.length+prefix[0].length}:null;
}
