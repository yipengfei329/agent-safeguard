// Trust only explicit simulator metadata in the same device record. This is a
// classification heuristic, not authentication of the source of tool output.
const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const deviceKey=/^(?:device[_ -]?id|udid)$/i;
const platform=/^(?:iOS|tvOS|watchOS|visionOS) Simulator$/;
export function simulatorIdentifier(record,key,value){
  return record!==null&&typeof record==='object'&&!Array.isArray(record)&&
    Object.hasOwn(record,'platform')&&typeof record.platform==='string'&&platform.test(record.platform)&&
    deviceKey.test(key)&&typeof value==='string'&&uuid.test(value);
}

// Keep offsets unchanged while removing grep's line/context prefixes. Recognize
// complete JSON records embedded in logs; incomplete or ambiguous records retain
// strict device inspection. Never exempt an entire log or nested child record.
export function maskSimulatorIdentifiers(text,budget){
  if(!text.includes('Simulator')||!/(?:device[_ -]?id|udid)/i.test(text))return text;
  const clean=text.replace(/^(?:[^\r\n:]{1,256}:)?\d+[:-]/gm,m=>' '.repeat(m.length));
  const stack=[],ranges=[];
  const tokens=/"(?:\\.|[^"\\])*"|[{}]/g;
  for(const token of clean.matchAll(tokens)){
    budget();const value=token[0],at=token.index;
    if(value==='{'){
      if(stack.length>=64)throw Error('SIMULATOR_DEPTH_LIMIT');
      stack.push({start:at,simulator:false});
    }else if(value==='}'){
      const frame=stack.pop();if(!frame?.simulator||at-frame.start>65536)continue;
      const fragment=clean.slice(frame.start,at+1);let record;
      try{record=JSON.parse(fragment);}catch{continue;}
      if(!record||typeof record.platform!=='string'||!platform.test(record.platform))continue;
      let depth=0;
      for(const part of fragment.matchAll(/"(?:\\.|[^"\\])*"|[{}\[\]]/g)){
        budget();const v=part[0];
        if(v==='{'||v==='['){depth++;continue;}
        if(v==='}'||v===']'){depth--;continue;}
        if(depth!==1)continue;
        if(!/^"(?:device[_ -]?id|udid)"$/i.test(v)&&!v.includes('\\'))continue;
        let key;try{key=JSON.parse(v);}catch{continue;}
        if(!deviceKey.test(key))continue;
        const rhs=fragment.slice(part.index+v.length).match(/^\s*:\s*"([a-f0-9-]{36})"/i);
        if(rhs&&simulatorIdentifier(record,key,rhs[1])){
          const start=frame.start+part.index+v.length+rhs[0].indexOf('"')+1;
          ranges.push([start,start+36]);
        }
      }
    }else if(stack.length){
      if(value!=='"platform"'&&!value.includes('\\'))continue;
      let key;try{key=JSON.parse(value);}catch{continue;}
      if(key==='platform'&&/^\s*:\s*"(?:iOS|tvOS|watchOS|visionOS) Simulator"/.test(clean.slice(at+value.length,at+value.length+80)))stack[stack.length-1].simulator=true;
    }
  }
  if(!ranges.length)return text;
  ranges.sort((a,b)=>a[0]-b[0]);let end=0,result='';
  for(const [start,stop] of ranges){if(start<end)continue;result+=text.slice(end,start)+' '.repeat(stop-start);end=stop;}
  return result+text.slice(end);
}
