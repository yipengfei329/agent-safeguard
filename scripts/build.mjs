import {readFile,writeFile,mkdir} from 'node:fs/promises';
import Ajv from 'ajv/dist/2020.js';
import standalone from 'ajv/dist/standalone/index.js';
import {build} from 'esbuild';
await mkdir('dist',{recursive:true});
const ajv=new Ajv({code:{source:true,esm:true},strict:false});
const validate=ajv.compile(JSON.parse(await readFile('schemas/rules.schema.json','utf8')));
await writeFile('dist/validate.js',standalone(ajv,validate));
await build({entryPoints:['src/core.js'],outfile:'dist/core.js',bundle:true,format:'esm',platform:'browser',target:'es2022'});
// Same engine, embedded by the desktop validator; no separate validation implementation.
await build({entryPoints:['src/core.js'],outfile:'dist/core.desktop.js',bundle:true,format:'iife',globalName:'SafeguardCore',platform:'browser',target:'es2022'});

// Mods rejects modules over 1 MiB; keep the offline snapshot within that limit.
if ((await readFile('dist/core.js')).length>1048576) throw Error('MODS_MODULE_LIMIT');
