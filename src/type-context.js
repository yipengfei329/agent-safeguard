// A small lexical classifier for complete TS interface/object-type declarations.
// No full-language AST claim. Comments and strings cannot open a declaration;
// incomplete declarations grant no exemption. Only field token offsets are
// returned, never a whole-line/file allow decision.
export function typeFieldOffsets(text,budget=()=>{}) {
  const fields=new Set();
  if(!/\b(?:interface|type)\s+[A-Za-z_$]/.test(text))return fields;
  // Treat slash-delimited expressions as opaque when looking for type headers.
  // A division expression mistaken for a regex can only remove an exemption;
  // regex contents must never manufacture a type scope around later code.
  const tokens=/\/\/[^\r\n]*|\/\*[\s\S]*?\*\/|\/(?:\\.|\[(?:\\.|[^\]\\\r\n])*\]|[^\/\\\r\n])+\/[a-z]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|[A-Za-z_$][\w$]*|[^\s]/g;
  let pending=null,depth=0,candidates=[],previous=null,previousEnd=0;
  for(const m of text.matchAll(tokens)){
    budget();const t=m[0];
    if(t.startsWith('//')||t.startsWith('/*'))continue;
    const prior=previous,newline=/[\r\n]/.test(text.slice(previousEnd,m.index));previous=t;previousEnd=m.index+t.length;
    const literal=/^["'`/]/.test(t),word=/^[A-Za-z_$]/.test(t);
    if(depth){
      if(t==='{'){if(++depth>64)throw Error('TYPE_DEPTH_LIMIT');}
      else if(t==='}'&&--depth===0){for(const at of candidates)fields.add(at);candidates=[];}
      else if(word||literal)candidates.push(m.index);
      continue;
    }
    if(pending){
      if(m.index-pending.start>512||literal||/[;()]/.test(t)){pending=null;continue;}
      if(!pending.name){if(!word){pending=null;continue;}pending.name=true;continue;}
      if(t==='=')pending.equals=true;
      else if(t==='{'){
        if(pending.kind==='interface'||pending.equals){depth=1;candidates=[];}
        pending=null;
      }else if(pending.equals){pending=null;}
      continue;
    }
    if((t==='type'||t==='interface')&&(prior===null||newline||/^(?:export|declare|default|[;{}:+-])$/.test(prior)))pending={kind:t,start:m.index,name:false,equals:false};
  }
  return fields;
}
