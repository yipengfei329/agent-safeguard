"""Synthetic diagnostic and recovery requests against the actual Claude host.
No private rules, user transcripts, accounts or device information are used.
"""
import http.server, json, os, pathlib, queue, shlex, shutil, subprocess, tempfile, threading
from importlib.util import spec_from_file_location, module_from_spec
ROOT=pathlib.Path(__file__).resolve().parent.parent
spec=spec_from_file_location('helpers',ROOT/'scripts/e2e-recovery.py'); helpers=module_from_spec(spec);spec.loader.exec_module(helpers)
DEVICE='11111111-2222-4333-8444-555555555555'
COMPACT_SECRET='sY9!nT4_hE7#tI2-cK8'
CASES=['input-batch','truncated-device','complete-device','summary','template-label','template-adjacent','template-opaque','diagnostic-write','diagnostic-write-secret','diagnostic-write-adjacent','diagnostic-result','diagnostic-result-secret','manifest-public-key','manifest-adjacent-secret','go-key-placeholder','go-key-adjacent-secret','polyglot-clean','provider-aws-token','placeholder-writeback','compaction-retry']

def check_compaction(send,result,status,requests,outputs,set_phase):
 assert status()['ready']
 set_phase('block')
 send('Read the synthetic fixture.');result()
 assert len(requests)==1 and status()['blocked'],'the synthetic tool result was not held'
 output_start=len(outputs)
 send('/compact');result()
 assert len(requests)==1 and 'SAFEGUARD_BLOCKED' in helpers.normalized_strings(outputs[output_start:]),'a held result was followed by a compaction request'

 set_phase('history');before=len(requests)
 for i in range(4):
  send(f'Synthetic compaction history {i}. Reply with the fixture marker.');result()
 assert len(requests)==before+4 and status()['recovery']['resumes']==1,'synthetic history did not recover'

 set_phase('fail');before=len(requests);output_start=len(outputs)
 send('/compact');result()
 assert len(requests)>before,'first compaction did not reach the local model'
 replies=helpers.normalized_strings(outputs[output_start:])
 assert 'SAFEGUARD_COMPACT_FAILED' in replies,'downstream failure was not reported separately'
 assert 'SYNTHETIC_PRIVATE_COMPACT_EXCEPTION' not in replies,'plugin exposed the exception detail'
 state=status()
 assert state['ready'] and not state['blocked'] and state['diagnostic']['cause'] is None,'compaction fault locked the session'

 set_phase('retry');before=len(requests);output_start=len(outputs)
 send('/compact');result()
 assert len(requests)>before,'second compaction was not dispatched'
 assert any(r.get('subtype')=='compact_boundary' for r in outputs[output_start:]),'host did not install the compacted history'

 set_phase('followup');before=len(requests)
 send('After compaction, reply with the fixture marker.');result()
 assert len(requests)==before+1 and 'SYNTHETIC_COMPACT_SUMMARY' in helpers.normalized_strings(requests[-1]),'the same session did not continue from its summary'
 assert COMPACT_SECRET not in helpers.normalized_strings(requests),'the held result reached a later request'
 return {'case':'compaction-retry','passed':True,'sameProcessRecovered':True,'scope':'synthetic actual host'}

def run_case(name):
 with tempfile.TemporaryDirectory(prefix='safeguard-diagnostics-') as tmp:
  base=pathlib.Path(tmp);home=base/'home';home.mkdir();plugin=base/'plugin';plugin.mkdir()
  for directory in ['hooks','dist','.claude-plugin']:shutil.copytree(ROOT/directory,plugin/directory)
  cfg=json.loads((ROOT/('config/redact-results.json' if name=='placeholder-writeback' else 'config/tool-results.json')).read_text());cfg['schemaVersion']=2;cfg['policy']['recovery']='next-safe-user-prompt'
  (plugin/'local').mkdir();(plugin/'local/rules.json').write_text(json.dumps(cfg))
  record={'devices':[{'architecture':'arm64','deviceId':DEVICE,'deviceName':'Synthetic E2E','platform':'iOS Simulator'}],'testNodes':[{'name':'Synthetic test','result':'Passed'}]}
  raw=json.dumps(record,indent=2);fixture=base/'fixture.txt'
  fixture.write_text('\n'.join(raw.splitlines()[:5]) if name=='truncated-device' else json.dumps({'testNodes':record['testNodes']}) if name=='summary' else raw)
  if name=='polyglot-clean':
   fixture.write_text('const DEFAULT_TOKEN = "USER_PROFILE";\nconst h = { token: "id-verification", secret: "User_Profile" };\n{"hostname":"localhost","bind":{"hostname":"127.0.0.1"},"device_id":"device-1","password":"Your password expired 3 days ago!"}\nether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff\n')
  if name=='provider-aws-token':
   fixture.write_text('AWS_ACCESS_KEY_ID=AKIA9X7K2M4P8Q3R6V5N\n')
  if name=='placeholder-writeback':
   fixture.write_text('2026/01/15 12:00:00 dial tcp 1.0.1.7:443: i/o timeout\n    testing.tRunner(0x1, {0x2})\n')
  if name=='compaction-retry':fixture.write_text('password='+COMPACT_SECRET)
  if name.startswith('template-'):
   fixture.write_text('// synthetic heading\nstate.token = `access-token-${state.sequence}`;\n' + ('password="qR7_mN2-zP8_vL4-tX9";' if name=='template-adjacent' else 'token=`qR7_mN2-zP8_vL4-tX9-${state.sequence}`;' if name=='template-opaque' else ''))
  label='account-password-required';synthetic_secret='qR7_mN2-zP8_vL4-tX9'
  if name.startswith('diagnostic-'):
   fixture.write_text('const (\n errMissingPassword = "'+(synthetic_secret if name.endswith('-secret') else label)+'"\n)\n'+('password="'+synthetic_secret+'"' if name.endswith('-adjacent') else ''))
  if name.startswith('manifest-'):
   fixture.write_text('<assemblyIdentity name="Synthetic.App" publicKeyToken="a19c7e2d03f8b6a4" />\n' + ('api_key="' + synthetic_secret + '"\n' if name=='manifest-adjacent-secret' else ''))
  bash_command='cat '+shlex.quote(str(fixture))
  if name.startswith('go-key-'):
   fixture=base/'fixture_test.go'
   adjacent=f'  "APP_PASSWORD": "{synthetic_secret}",\n' if name=='go-key-adjacent-secret' else ''
   fixture.write_text(
    'package fixture\n\nfunc fixture() map[string]string {\n return map[string]string{\n'
    '  "APP_API_TOKEN": "sk-dummy-secret-value",\n'+adjacent+' }\n}\n')
   quoted_fixture=shlex.quote(str(fixture))
   bash_command=f"sed -n '1,140p' {quoted_fixture}; grep -n '^func ' {quoted_fixture}"
  marker=base/'executed';target=base/'Fixture.swift';requests=[];outputs=[];compaction_phase='history'
  def set_phase(phase):
   nonlocal compaction_phase
   compaction_phase=phase
  class Handler(http.server.BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_POST(self):
    data=json.loads(self.rfile.read(int(self.headers['Content-Length'])));requests.append(data)
    if name=='compaction-retry':
     if compaction_phase=='fail':
      body=json.dumps({'type':'error','error':{'type':'invalid_request_error','message':'prompt is too long: SYNTHETIC_PRIVATE_COMPACT_EXCEPTION'}}).encode()
      self.send_response(400);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);return
     if compaction_phase=='block':
      blocks=[{'type':'tool_use','id':'compact_fixture','name':'Bash','input':{'command':bash_command}}]
     else:
      reply='<summary>SYNTHETIC_COMPACT_SUMMARY</summary>' if compaction_phase=='retry' else 'SAFE_FOLLOWUP_OK'
      blocks=[{'type':'text','text':reply}]
    elif len(requests)==1:
     blocks=([{'type':'tool_use','id':'write_fixture','name':'Write','input':{'file_path':str(target),'content':'let endpoint = "https://fixture:short@service.example.invalid"'}}, {'type':'tool_use','id':'later_bash','name':'Bash','input':{'command':'touch '+str(marker)}}] if name=='input-batch' else [{'type':'tool_use','id':'read_fixture','name':'Bash','input':{'command':bash_command}}])
     if name.startswith('diagnostic-write'):blocks=[{'type':'tool_use','id':'write_diagnostic','name':'Write','input':{'file_path':str(target),'content':fixture.read_text()}}]
    elif name=='placeholder-writeback' and len(requests)==2:
     blocks=[{'type':'tool_use','id':'write_redacted_ip','name':'Write','input':{'file_path':str(target),'content':'endpoint: http://[IP_1]:443\n'}}]
    else:blocks=[{'type':'text','text':'SAFE_FOLLOWUP_OK'}]
    msg={'id':f'msg_fixture_{len(requests)}','type':'message','role':'assistant','model':data['model'],'content':blocks,'stop_reason':'tool_use' if blocks[0]['type']=='tool_use' else 'end_turn','stop_sequence':None,'usage':{'input_tokens':10,'output_tokens':10}}
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
   if name=='compaction-retry':return check_compaction(send,result,status,requests,outputs,set_phase)
   assert status()['ready'];send('Run the synthetic fixture.');result();before=len(requests)
   blocked=name in ['input-batch','truncated-device','template-adjacent','template-opaque','diagnostic-write-secret','diagnostic-write-adjacent','diagnostic-result-secret','manifest-adjacent-secret','go-key-adjacent-secret','provider-aws-token','placeholder-writeback']
   expected_requests=2 if name=='placeholder-writeback' else (1 if blocked else 2)
   assert before==expected_requests,(name,'request count',before)
   state=status();assert state['blocked']==blocked
   if blocked:
    cause=state['diagnostic']['cause']
    expected_rule='network.address' if name=='placeholder-writeback' else ('identity.device' if name=='truncated-device' else 'security.credentials')
    expected_reason='redaction.placeholder-input' if name=='placeholder-writeback' else ('url-password' if name=='input-batch' else 'token-format' if name=='provider-aws-token' else 'literal-value')
    assert cause['rule']==expected_rule,cause
    assert cause['reason']==expected_reason,cause
    assert state['diagnostic']['nextAction']=='safe-message'
   if name=='polyglot-clean':
    sent=helpers.normalized_strings(requests)
    assert 'USER_PROFILE' in sent and 'id-verification' in sent and 'Your password expired 3 days ago!' in sent,'polyglot result not delivered'
   if name=='provider-aws-token':
    assert 'AKIA9X7K2M4P8Q3R6V5N' not in helpers.normalized_strings(requests),'AWS key leaked in request'
   if name=='placeholder-writeback':
    sent=helpers.normalized_strings(requests)
    assert '1.0.1.7' not in sent and '[IP_1]:443' in sent,'IP was not redacted before reaching model'
    assert not target.exists(),'placeholder writeback executed'
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
   if name=='go-key-placeholder':
    sent=helpers.normalized_strings(requests)
    assert 'sk-dummy-secret-value' in sent and '3:func fixture() map[string]string {' in sent,'combined Bash result did not arrive'
   if name=='go-key-adjacent-secret':
    assert synthetic_secret not in helpers.normalized_strings(requests),'held adjacent credential leaked'
    assert cause['location']['line']==6 and cause['location']['field']=='password',cause['location']
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
   if name in ['diagnostic-result-secret','manifest-adjacent-secret','go-key-adjacent-secret']:assert synthetic_secret not in history,'held credential leaked in history'
   if name=='provider-aws-token':assert 'AKIA9X7K2M4P8Q3R6V5N' not in history,'AWS key leaked in history'
   if name=='placeholder-writeback':
    assert '1.0.1.7' not in history,'raw IP leaked in history'
    assert '[redaction.placeholder-input]' in history and 'Tool not executed.' in history,'missing placeholder writeback refusal'
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
