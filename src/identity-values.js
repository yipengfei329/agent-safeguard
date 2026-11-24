import {placeholder} from './value-syntax.js';
import {assignmentMatchers,assignmentReason} from './assignment-values.js';
import ipaddr from 'ipaddr.js';

const deviceShape=/^[\p{L}\p{N}][\p{L}\p{N}_.:-]*$/u;
const encodedDeviceShape=/^[A-Za-z0-9+/_-]+={0,2}$/;
const hostShape=/^[\p{L}\p{N}_](?:[\p{L}\p{N}_.-]*[\p{L}\p{N}_-])?\.?$/u;
const computerShape=/^[\p{L}\p{N}\p{So}][\p{L}\p{M}\p{N}\p{So}\p{Sk}\u200d ._'’()-]*$/u;

// Standard non-personal hostnames, generic service roles, and mock/test tags.
// IP literals are delegated to network.address so 127.0.0.1 / 0.0.0.0 stay clean.
const reservedHost=/^(?:localhost|localhost\.localdomain|broadcasthost|ip6-localhost|ip6-loopback|(?:[\w-]+\.)*(?:localhost|example|example\.(?:com|org|net)|test))\.?$/i;
const genericHostWord=/^(?:placeholder|default|unknown|none|unset|auto|local|client|server|worker|redis|postgres|mysql|mongo|db|api|web|app|proxy|gateway|backend|frontend|service|docker|host|hostname|(?:test|mock|dummy|sample|fake|example|demo|dev)[-_](?:host|hostname|server)(?:[-_]\d+)?|(?:host|hostname|server)[-_](?:id|name|\d+))$/i;
const genericDeviceWord=/^(?:placeholder|default|unknown|none|unset|auto|device|serial|udid|simulator|emulator(?:-\d+)?|(?:test|mock|dummy|sample|fake|example|demo|dev)[-_](?:device|serial|udid|id)(?:[-_]\d+)?|(?:device|serial|udid)[-_](?:id|name|number|\d+))$/i;

function isIPLiteral(value){
  const bare=value.startsWith('[')&&value.endsWith(']')?value.slice(1,-1):value;
  return ipaddr.isValid(bare);
}

export function createAssignmentDetector(names,minimum,kind='device') {
  const policy={
    matchers:assignmentMatchers(names,new RegExp(names,'i')),
    classify:name=>kind==='device'?'device':name.replace(/["']/g,'').split('.').at(-1).toLowerCase()==='computername'?'computer':'hostname',
    accept:(value,role)=>{
      value=value.trim();
      const minLength=role==='device'?minimum:Math.max(2,minimum);
      if(value.length<minLength||placeholder(value))return false;
      if(role==='device'){
        if(genericDeviceWord.test(value))return false;
        return deviceShape.test(value)||encodedDeviceShape.test(value);
      }
      if(isIPLiteral(value)||reservedHost.test(value)||genericHostWord.test(value))return false;
      return (role==='computer'?computerShape:hostShape).test(value);
    },
    allowDynamic:false,
  };
  return (text,key='',budget,syntax)=>assignmentReason(text,key,policy,budget,syntax);
}
