// A small lexical classifier for complete TS interface/object-type declarations.
// No full-language AST claim. Comments and strings cannot open a declaration;
// incomplete declarations grant no exemption. Only field token offsets are
// returned, never a whole-line/file allow decision.
export function typeFieldOffsets(text,budget=()=>{},context) {
  if(context?.text===text)return context.fields;
  const fields=new Set();
  const complete=()=>{if(context){context.text=text;context.fields=fields;}return fields;};
  if(!/\b(?:interface|type)\s+[A-Za-z_$]/.test(text))return complete();
  // Treat slash-delimited expressions as opaque when looking for type headers.
  // A division expression mistaken for a regex can only remove an exemption;
  // regex contents must never manufacture a type scope around later code.
  const tokens=/\/\/[^\r\n]*|\/\*[\s\S]*?\*\/|\/(?:\\.|\[(?:\\.|[^\]\\\r\n])*\]|[^\/\\\r\n])+\/[a-z]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|[A-Za-z_$][\w$]*|[0-9]+|[^\s]/g;
  const bodyTokens=/\/\/[^\r\n]*|\/\*[\s\S]*?\*\/|\/(?:\\.|\[(?:\\.|[^\]\\\r\n])*\]|[^\/\\\r\n])+\/[a-z]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|(?<![\w$])[A-Za-z_$][\w$.-]*[ \t]*\??[ \t]*:|[{}]/g;
  // Outside a declaration only opaque tokens and type headers are interesting.
  // Examine the gap's final token in native regex code instead of visiting all
  // unrelated identifiers, numbers and punctuation in JavaScript.
  const outerTokens=new RegExp(tokens.source.replace('[A-Za-z_$][\\w$]*|[0-9]+|[^\\s]', '(?<![\\w$])(?:interface|type)(?![\\w$])'),'g');
  const boundaryToken=/^(?:export|declare|default|[;{}:+-])$/;
  const gapBoundary=(gap,prior)=>{
    const trimmed=gap.trimEnd();
    // Trim once: an unanchored newline-plus-whitespace-tail regex would retry
    // the same long whitespace run for every newline on adversarial input.
    if(/[\r\n]/.test(gap.slice(trimmed.length)))return true;
    if(!trimmed)return prior;
    return /(?:^|[^\w$])(?:export|declare|default)$|[;{}:+-]$/.test(trimmed);
  };
  let pending=null,depth=0,candidates=[],cursor=0,boundary=true;
  let m;
  while(true){
    const lexer=pending?tokens:outerTokens;lexer.lastIndex=cursor;
    if((m=lexer.exec(text))===null)break;
    budget();const t=m[0];
    if(!pending)boundary=gapBoundary(text.slice(cursor,m.index),boundary);
    cursor=m.index+t.length;
    if(t.startsWith('//')||t.startsWith('/*')){if(/[\r\n]/.test(t))boundary=true;continue;}
    const priorBoundary=boundary;boundary=boundaryToken.test(t);
    if(pending){
      const literal=/^["'`/]/.test(t),word=/^[A-Za-z_$]/.test(t);
      if(m.index-pending.start>512||literal||/[;()]/.test(t)){pending=null;continue;}
      if(!pending.name){if(!word){pending=null;continue;}pending.name=true;continue;}
      if(t==='=')pending.equals=true;
      else if(t==='{'){
        if(pending.kind==='interface'||pending.equals){
          // Inside a declaration only braces, opaque lexical tokens and field
          // starts matter. Native regex search skips ordinary type words and
          // punctuation without dispatching one JS iteration per source token.
          bodyTokens.lastIndex=cursor;depth=1;candidates=[];
          let body;
          while((body=bodyTokens.exec(text))!==null){
            budget();const value=body[0];
            if(value==='{'){if(++depth>64)throw Error('TYPE_DEPTH_LIMIT');}
            else if(value==='}'){
              if(--depth===0){for(const at of candidates)fields.add(at);break;}
            }else if(!value.startsWith('//')&&!value.startsWith('/*'))candidates.push(body.index);
          }
          if(!body)break; // Incomplete bodies grant no exemption.
          cursor=bodyTokens.lastIndex;boundary=true;
        }
        pending=null;
      }else if(pending.equals){pending=null;}
      continue;
    }
    if((t==='type'||t==='interface')&&priorBoundary)pending={kind:t,start:m.index,name:false,equals:false};
  }
  return complete();
}
