import {readFile,writeFile,mkdir} from 'node:fs/promises';
import Ajv from 'ajv/dist/2020.js';
import standalone from 'ajv/dist/standalone/index.js';
import {build} from 'esbuild';
await mkdir('dist',{recursive:true});
const ajv=new Ajv({code:{source:true,esm:true},strict:false});
const validate=ajv.compile(JSON.parse(await readFile('schemas/rules.schema.json','utf8')));
await writeFile('dist/validate.js',standalone(ajv,validate));
await build({entryPoints:['src/core.js'],outfile:'dist/core.js',bundle:true,format:'esm',platform:'browser',target:'es2022'});
