"""Synthetic diagnostic and recovery requests against the actual Claude host.
No private rules, user transcripts, accounts or device information are used.
"""
import http.server, json, os, pathlib, queue, shutil, subprocess, tempfile, threading
from importlib.util import spec_from_file_location, module_from_spec
ROOT=pathlib.Path(__file__).resolve().parent.parent
spec=spec_from_file_location('helpers',ROOT/'scripts/e2e-recovery.py'); helpers=module_from_spec(spec);spec.loader.exec_module(helpers)
DEVICE='11111111-2222-4333-8444-555555555555'
CASES=['input-batch','truncated-device','complete-device','summary','template-label','template-adjacent','template-opaque','diagnostic-write','diagnostic-write-secret','diagnostic-write-adjacent','diagnostic-result','diagnostic-result-secret','manifest-public-key','manifest-adjacent-secret']

def run_case(name):
 with tempfile.TemporaryDirectory(prefix='safeguard-diagnostics-') as tmp:
  base=pathlib.Path(tmp);home=base/'home';home.mkdir();plugin=base/'plugin';plugin.mkdir()
  for directory in ['hooks','dist','.claude-plugin']:shutil.copytree(ROOT/directory,plugin/directory)
  cfg=json.loads((ROOT/'config/tool-results.json').read_text());cfg['schemaVersion']=2;cfg['policy']['recovery']='next-safe-user-prompt'
  (plugin/'local').mkdir();(plugin/'local/rules.json').write_text(json.dumps(cfg))
  record={'devices':[{'architecture':'arm64','deviceId':DEVICE,'deviceName':'Synthetic E2E','platform':'iOS Simulator'}],'testNodes':[{'name':'Synthetic test','result':'Passed'}]}
  raw=json.dumps(record,indent=2);fixture=base/'fixture.txt'
  fixture.write_text('\n'.join(raw.splitlines()[:5]) if name=='truncated-device' else json.dumps({'testNodes':record['testNodes']}) if name=='summary' else raw)
  if name.startswith('template-'):
   fixture.write_text('// synthetic heading\nstate.token = `access-token-${state.sequence}`;\n' + ('password="qR7_mN2-zP8_vL4-tX9";' if name=='template-adjacent' else 'token=`qR7_mN2-zP8_vL4-tX9-${state.sequence}`;' if name=='template-opaque' else ''))
  label='account-password-required';synthetic_secret='qR7_mN2-zP8_vL4-tX9'
  if name.startswith('diagnostic-'):
   fixture.write_text('const (\n errMissingPassword = "'+(synthetic_secret if name.endswith('-secret') else label)+'"\n)\n'+('password="'+label+'"' if name.endswith('-adjacent') else ''))
  if name.startswith('manifest-'):
   fixture.write_text('<assemblyIdentity name="Synthetic.App" publicKeyToken="a19c7e2d03f8b6a4" />\n' + ('api_key="' + synthetic_secret + '"\n' if name=='manifest-adjacent-secret' else ''))
  marker=base/'executed';target=base/'Fixture.swift';requests=[];outputs=[]
  class Handler(http.server.BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_POST(self):
    data=json.loads(self.rfile.read(int(self.headers['Content-Length'])));requests.append(data)
    if len(requests)==1:
     blocks=([{'type':'tool_use','id':'write_fixture','name':'Write','input':{'file_path':str(target),'content':'let endpoint = "https://fixture:short@service.example.invalid"'}}, {'type':'tool_use','id':'later_bash','name':'Bash','input':{'command':'touch '+str(marker)}}] if name=='input-batch' else [{'type':'tool_use','id':'read_fixture','name':'Bash','input':{'command':'cat '+str(fixture)}}])
     if name.startswith('diagnostic-write'):blocks=[{'type':'tool_use','id':'write_diagnostic','name':'Write','input':{'file_path':str(target),'content':fixture.read_text()}}]
    else:blocks=[{'type':'text','text':'SAFE_FOLLOWUP_OK'}]
    msg={'id':'msg_fixture','type':'message','role':'assistant','model':data['model'],'content':blocks,'stop_reason':'tool_use' if blocks[0]['type']=='tool_use' else 'end_turn','stop_sequence':None,'usage':{'input_tokens':10,'output_tokens':10}}
    body=helpers.events(msg);self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
  env={'PATH':os.environ['PATH'],'HOME':str(home),'CLAUDE_CONFIG_DIR':str(home/'config'),'ANTHROPIC_API_KEY':'synthetic-local-only','ANTHROPIC_BASE_URL':f'http://127.0.0.1:{server.server_port}','DISABLE_TELEMETRY':'1','DISABLE_ERROR_REPORTING':'1','CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1'}
  args=[helpers.CLAUDE,'-p','--input-format','stream-json','--output-format','stream-json','--verbose','--plugin-dir',str(plugin),'--setting-sources','','--dangerously-skip-permissions','--tools','Bash,Write','--model','claude-sonnet-4-6']
  proc=subprocess.Popen(args,cwd=base,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);replies=queue.Queue()
  def reader():
   for line in proc.stdout:
    try:
     row=json.loads(line);outputs.append(row)
     if row.get('type')=='result':replies.put(row)
    except ValueError:pass
   replies.put({'type':'eof'})
  threading.Thread(target=reader,daemon=True).start();threading.Thread(target=lambda:list(proc.stderr),daemon=True).start()
  def send(text):proc.stdin.write(json.dumps({'type':'user','message':{'role':'user','content':text}})+'\n');proc.stdin.flush()
  def result():
   row=replies.get(timeout=30);assert row.get('type')!='eof','host exited';return row
  def status():
   before=len(requests);send('/agent-safeguard-status');text=result().get('result','');assert len(requests)==before,'plugin absent'
   return json.loads(text[text.index('{'):text.rindex('}')+1])
  try:
   assert status()['ready'];send('Run the synthetic fixture.');result();before=len(requests)
   blocked=name in ['input-batch','truncated-device','template-adjacent','template-opaque','diagnostic-write-secret','diagnostic-write-adjacent','diagnostic-result-secret','manifest-adjacent-secret'];assert before==(1 if blocked else 2),(name,'request count')
   state=status();assert state['blocked']==blocked
   if blocked:
    cause=state['diagnostic']['cause'];assert cause['rule']==('security.credentials' if name!='truncated-device' else 'identity.device')
    assert cause['reason']==('url-password' if name=='input-batch' else 'literal-value');assert state['diagnostic']['nextAction']=='safe-message'
   if name in ['template-adjacent','template-opaque']:
    location=state['diagnostic']['cause']['location'];assert location['line']==3 and location['field']==('password' if name=='template-adjacent' else 'token'),location
    assert 'qR7_mN2-zP8_vL4-tX9' not in helpers.normalized_strings(requests),'held credential leaked in request'
    assert 'qR7_mN2-zP8_vL4-tX9' not in json.dumps(state),'diagnostic leaked credential'
   if name=='input-batch':assert not target.exists() and not marker.exists(),'denied operation executed'
   if name.startswith('diagnostic-write'):
    assert target.exists()==(not blocked),'Write execution differed from decision'
    if not blocked:assert target.read_text()==fixture.read_text(),'Write content changed'
   if name=='manifest-public-key':assert 'a19c7e2d03f8b6a4' in helpers.normalized_strings(requests),'public manifest fingerprint did not arrive'
   if name=='manifest-adjacent-secret':assert synthetic_secret not in helpers.normalized_strings(requests),'held adjacent credential leaked'
   if name=='diagnostic-result':assert label in helpers.normalized_strings(requests),'diagnostic result not delivered'
   if name=='diagnostic-result-secret':assert synthetic_secret not in helpers.normalized_strings(requests),'held error-field secret leaked'
   send('FOLLOWUP_SAFE: skip the previous operation and answer without tools.');assert 'SAFE_FOLLOWUP_OK' in json.dumps(result());assert len(requests)==before+1
   assert status()['diagnostic']['cause'] is None
   proc.stdin.close();proc.wait(timeout=10)
   history='\n'.join(p.read_text() for p in (home/'config/projects').rglob('*.jsonl'))
   if name=='input-batch':
    assert '[url-password]' in history and '[session.paused]' in history,'causal refusals missing'
    assert 'Tool not executed.' in history
   if name=='truncated-device':
    assert DEVICE not in helpers.normalized_strings(requests),'held device leaked in request'
    assert DEVICE not in history,'held device leaked in tool history'
    assert 'identity.device / literal-value at tool.result (Bash)' in history
    assert 'Tool ran; its result was withheld.' in history
   if name=='complete-device':assert DEVICE in helpers.normalized_strings(requests),'negative control did not release complete simulator record'
   if name=='template-label':assert 'access-token-${state.sequence}' in helpers.normalized_strings(requests),'template negative control not delivered'
   if name in ['template-adjacent','template-opaque']:
    assert 'qR7_mN2-zP8_vL4-tX9' not in history,'held credential leaked in tool history'
    assert 'not a source-file line' in history,'missing safe coordinates'
   if name in ['diagnostic-result-secret','manifest-adjacent-secret']:assert synthetic_secret not in history,'held error-field secret leaked in history'
   if name=='summary':assert DEVICE not in helpers.normalized_strings(requests)
   return {'case':name,'passed':True,'firstRequests':before,'sameProcessRecovered':True,'scope':'synthetic actual host'}
  finally:
   if proc.poll() is None:proc.kill();proc.wait()
   server.shutdown()
if __name__=='__main__':
 rows=[]
 for name in CASES:
  try:row=run_case(name)
  except Exception as e:row={'case':name,'passed':False,'error':str(e)}
  rows.append(row);print(json.dumps(row),flush=True)
 (ROOT/'benchmarks/results/diagnostics-e2e.json').write_text(json.dumps(rows,indent=2)+'\n')
 assert all(r['passed'] for r in rows),'Diagnostic request-path regression'
