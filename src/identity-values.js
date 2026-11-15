import {placeholder} from './value-syntax.js';
import {assignmentMatchers,assignmentReason} from './assignment-values.js';
const deviceShape=/^[\p{L}\p{N}][\p{L}\p{N}_.:-]*$/u;
const encodedDeviceShape=/^[A-Za-z0-9+/_-]+={0,2}$/;
const hostShape=/^[\p{L}\p{N}_](?:[\p{L}\p{N}_.-]*[\p{L}\p{N}_-])?\.?$/u;
const computerShape=/^[\p{L}\p{N}\p{So}][\p{L}\p{M}\p{N}\p{So}\p{Sk}\u200d ._'’()-]*$/u;
export function createAssignmentDetector(names,minimum,kind='device') {
  const policy={
    matchers:assignmentMatchers(names,new RegExp(names,'i')),
    classify:name=>kind==='device'?'device':name.replace(/["']/g,'').split('.').at(-1).toLowerCase()==='computername'?'computer':'hostname',
    accept:(value,role)=>{
      value=value.trim();
      return value.length>=minimum&&!placeholder(value)&&
        (role==='device'?deviceShape.test(value)||encodedDeviceShape.test(value):(role==='computer'?computerShape:hostShape).test(value));
    },
    allowDynamic:false,
  };
  return (text,key='',budget)=>assignmentReason(text,key,policy,budget);
}
