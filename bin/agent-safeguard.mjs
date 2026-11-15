#!/usr/bin/env node
import {spawnSync} from 'node:child_process';import {existsSync,readFileSync} from 'node:fs';import {fileURLToPath} from 'node:url';import {compile,defaults} from '../dist/core.js';
const root=fileURLToPath(new URL('..',import.meta.url)),args=process.argv.slice(2);
if(args.some(a=>/^--(?:bare|safe-mode|resume|continue|fork-session|settings|plugin-dir|plugin-url)(?:=|$)/.test(a)||['-c','-r'].includes(a))){console.error('SAFEGUARD: this launcher supports new sessions only; conflicting configuration flags refused.');process.exit(2);}
try{compile(existsSync(root+'/local/rules.json')?JSON.parse(readFileSync(root+'/local/rules.json','utf8')):defaults);}catch{console.error('SAFEGUARD: invalid configuration');process.exit(2);}
console.error('Agent Safeguard 0.1.22: experimental content guard; use /agent-safeguard-status to inspect loading.');
const result=spawnSync('claude',['--plugin-dir',root,...args],{stdio:'inherit'});if(result.error)console.error('SAFEGUARD: Claude could not start');process.exit(result.status??1);
