"""Real-host Write input fault recovery with synthetic Swift and a local model.
The timeout case supplies an expired deadline for one scan in a TEMPORARY
plugin only. It tests the actual deadline path, not machine-dependent slowness.
No user project, rules or conversation is used as a fixture.
"""
import http.server,json,os,pathlib,queue,shutil,subprocess,tempfile,threading,time
from importlib.util import spec_from_file_location,module_from_spec
ROOT=pathlib.Path(__file__).resolve().parent.parent
spec=spec_from_file_location('recovery_helpers',ROOT/'scripts/e2e-recovery.py');helpers=module_from_spec(spec);spec.loader.exec_module(helpers)
CLAUDE=shutil.which('claude')
SOURCE='import SwiftUI\n'+''.join(f'struct FixtureRow{i}: View {{ var body: some View {{ Text("Fixture row {i}") }} }}\n' for i in range(800))
CASES=['clean','timeout','timeout-rejected-input','timeout-snapshot','timeout-probe-fails','text-limit','exception']
def run_case(name):
 with tempfile.TemporaryDirectory(prefix='safeguard-write-recovery-') as tmp:
  base=pathlib.Path(tmp);home=base/'home';home.mkdir();plugin=base/'plugin';plugin.mkdir();target=base/'Fixture.swift'
  baseline=os.environ.get('SAFEGUARD_BASELINE_PLUGIN');source_root=pathlib.Path(baseline) if baseline else ROOT
  for directory in ['hooks','dist','.claude-plugin']:shutil.copytree(source_root/directory,plugin/directory)
  cfg=json.loads((ROOT/'config/tool-results.json').read_text());cfg['schemaVersion']=2;cfg['policy']['recovery']='next-safe-user-prompt'
  if name=='text-limit':cfg['limits']['maxTextBytes']=4096
  (plugin/'local').mkdir();(plugin/'local/rules.json').write_text(json.dumps(cfg))
  if name.startswith('timeout') or name=='exception':
   core=plugin/'dist/core.js';core.rename(plugin/'dist/core.real.js')
   # Inject one actual deadline expiry. These test-only files are never installed.
   core.write_text("""export * from './core.real.js';
import {compile as actual} from './core.real.js';
export function compile(...args){const e=actual(...args),scan=e.scan;let faulted=false;
 e.scan=(value,source,tool,...rest)=>{
  if(!faulted&&source==='tool.input'&&tool==='Write'){
   faulted=true;
   if(EXCEPTION)return {blocked:true,rule:'inspection.failed',reason:'inspection.exception'};
   return scan(value,source,tool,Date.now()-1);
  }
  if(PROBE_FAIL&&value==='SAFEGUARD_HEALTH_PROBE')return {blocked:true,rule:'inspection.failed',reason:'inspection.timeout'};
  return scan(value,source,tool,...rest);
 };return e;}
""".replace('EXCEPTION','true' if name=='exception' else 'false').replace('PROBE_FAIL','true' if name=='timeout-probe-fails' else 'false'))
  requests=[]
  class Handler(http.server.BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_POST(self):
    d=json.loads(self.rfile.read(int(self.headers['Content-Length'])));requests.append(d)
    follow='FOLLOWUP_SAFE' in json.dumps(d.get('messages',[]))
    has_result=any(isinstance(m.get('content'),list) and any(b.get('type')=='tool_result' for b in m['content'] if isinstance(b,dict)) for m in d.get('messages',[]))
    if follow or has_result:blocks=[{'type':'text','text':'SAFE_FOLLOWUP_OK' if follow else 'WRITE_OK'}]
    else:blocks=[{'type':'tool_use','id':'write_fixture','name':'Write','input':{'file_path':str(target),'content':SOURCE}}]
    msg={'id':'msg_fixture','type':'message','role':'assistant','model':d['model'],'content':blocks,'stop_reason':'end_turn' if blocks[0]['type']=='text' else 'tool_use','stop_sequence':None,'usage':{'input_tokens':10,'output_tokens':10}}
    body=helpers.events(msg);self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
  env={'PATH':os.environ['PATH'],'HOME':str(home),'CLAUDE_CONFIG_DIR':str(home/'config'),'ANTHROPIC_API_KEY':'synthetic-local-only','ANTHROPIC_BASE_URL':f'http://127.0.0.1:{server.server_port}','DISABLE_TELEMETRY':'1','DISABLE_ERROR_REPORTING':'1','CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1'}
  args=[CLAUDE,'-p','--input-format','stream-json','--output-format','stream-json','--verbose','--plugin-dir',str(plugin),'--setting-sources','','--dangerously-skip-permissions','--tools','Write','--model','claude-sonnet-4-6']
  proc=subprocess.Popen(args,cwd=base,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);q=queue.Queue();output=[]
  def reader():
   for line in proc.stdout:
    try:v=json.loads(line);output.append(v);q.put(v)
    except ValueError:pass
   q.put({'type':'eof'})
  threading.Thread(target=reader,daemon=True).start();threading.Thread(target=lambda:list(proc.stderr),daemon=True).start()
  def send(text):proc.stdin.write(json.dumps({'type':'user','message':{'role':'user','content':text}})+'\n');proc.stdin.flush()
  def result():
   deadline=time.monotonic()+30
   while time.monotonic()<deadline:
    v=q.get(timeout=max(.1,deadline-time.monotonic()))
    if v.get('type')=='eof':raise AssertionError('unexpected host exit')
    if v.get('type')=='result':return v
   raise TimeoutError('host result timeout')
  def status():
   send('/agent-safeguard-status');v=result().get('result','');return json.loads(v[v.index('{'):v.rindex('}')+1])
  try:
   send('Write the synthetic fixture once.');result();initial=len(requests)
   assert initial==(2 if name=='clean' else 1),(name,'initial request count',initial)
   assert target.exists()==(name=='clean'),(name,'Write execution mismatch')
   before=status();assert before['recovery']['state']==('active' if name=='clean' else 'faulted')
   if name=='timeout-snapshot':(plugin/'local/rules.json').write_text('{invalid')
   if name in ['timeout-rejected-input','timeout-snapshot']:
    send('password=SYNTHETIC_RETRY_SECRET');result();assert len(requests)==initial;assert status()['recovery']['state']=='faulted'
   send('FOLLOWUP_SAFE: skip the failed operation and answer without tools.');follow=result()
   if baseline:
    assert name=='timeout';assert len(requests)==initial;assert 'recovery.health-required' in json.dumps(follow)
    proc.stdin.close();proc.wait(timeout=10)
    history='\n'.join(p.read_text() for p in (home/'config/projects').rglob('*.jsonl'))
    assert 'Nothing refused it' in history;assert not target.exists()
    return {'case':'baseline-timeout','passed':True,'pluginVersion':before['pluginVersion'],'safeFollowupBlocked':True,'misleadingCancellation':True,'heldWriteReplayed':False}
   automatic=name in ['clean','timeout','timeout-rejected-input','timeout-snapshot']
   assert len(requests)==initial+(1 if automatic else 0),(name,'automatic request count',len(requests),before.get('lastRule'),before.get('lastReason'))
   if automatic:assert 'SAFE_FOLLOWUP_OK' in json.dumps(follow)
   else:
    rendered=json.dumps(follow);assert 'agent-safeguard-check' in rendered,(name,'missing health instructions')
    send('/agent-safeguard-check');check=result()
    if name=='timeout-probe-fails':assert 'SAFEGUARD_CHECK_FAILED' in json.dumps(check)
    else:
     assert 'SAFEGUARD_HEALTH_OK' in json.dumps(check)
     send('FOLLOWUP_SAFE: continue without tools.');assert 'SAFE_FOLLOWUP_OK' in json.dumps(result());assert len(requests)==initial+1
   after=status()
   assert 'SYNTHETIC_RETRY_SECRET' not in json.dumps(requests),(name,'rejected input reached a model request')
   if name=='timeout-probe-fails':assert after['recovery']['state']=='faulted'
   else:assert after['recovery']['state']=='active'
   assert target.exists()==(name=='clean'),(name,'held operation replayed')
   proc.stdin.close();proc.wait(timeout=10)
   history='\n'.join(p.read_text() for p in (home/'config/projects').rglob('*.jsonl'))
   if name!='clean':
    assert 'Tool not executed.' in history and 'SAFEGUARD_BLOCKED' in history,(name,'missing refusal')
    assert 'Nothing refused it' not in history,(name,'refusal lost to cancellation')
   return {'case':name,'passed':True,'inputBytes':len(SOURCE.encode()),'initialRequests':initial,'automaticallyRecovered':automatic,'finalState':after['recovery']['state'],'heldWriteReplayed':False,'refusalPreserved':name!='clean'}
  finally:
   if proc.poll() is None:proc.kill();proc.wait()
   server.shutdown()
if __name__=='__main__':
 if not CLAUDE:raise SystemExit('Claude Code is required for real-host tests')
 rows=[]
 for name in CASES:
  if os.environ.get('SAFEGUARD_CASE') and name!=os.environ['SAFEGUARD_CASE']:continue
  try:row=run_case(name)
  except Exception as e:row={'case':name,'passed':False,'error':str(e)}
  rows.append(row);print(json.dumps(row),flush=True)
 (ROOT/'benchmarks/results').mkdir(exist_ok=True)
 (ROOT/'benchmarks/results/write-recovery-e2e.json').write_text(json.dumps(rows,indent=2)+'\n')
 assert rows and all(r['passed'] for r in rows),'Write recovery cases failed or no case selected'
