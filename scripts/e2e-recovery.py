"""Synthetic real-host multi-turn recorder. All values originate in local fixtures,
not the model's tool arguments. No real credentials or user configuration.
"""
import http.server,json,os,pathlib,queue,re,shlex,shutil,subprocess,tempfile,threading,time
ROOT=pathlib.Path(__file__).resolve().parent.parent
CLAUDE=os.environ.get('SAFEGUARD_CLAUDE_BIN') or shutil.which('claude')
IP='203.0.113.17'; SECRET='SYNTHETIC_RECOVERY_SECRET'
TEST_ADDRESS_LINE='    time=2026-01-15T12:00:00.123Z level=INFO msg="IPv6 endpoint listening" addr=[2001:db8::7]:8080\n'
TEST_LOG=TEST_ADDRESS_LINE+(
 '--- FAIL: TestSynthetic (0.10s)\n'
 '    fixture_test.go:12: failed {detail:\n'
 '    end}\n'
 '    testing.tRunner(0x1, {0x2})\n'
)
TEST_TAIL=TEST_ADDRESS_LINE+'FAIL\texample.invalid/test/e2e\t0.118s\nFAIL\n'
CASES=[
 ('clean','BUILD_OK',False,'pass'),
 ('ip','peer='+IP,False,'redact'),
 ('ip-repeat','local='+IP+' remote='+IP,False,'redact'),
 ('ipv6','peer=[2001:db8::7]:8080',False,'redact'),
 ('mapped','peer=::ffff:'+IP,False,'redact'),
 ('escaped','peer=203.0.\\u0031\\u00313.17',False,'redact'),
 ('ansi','peer=203.0.\x1b[31m113.17',False,'redact'),
 ('json',json.dumps({'peer':IP,'status':'ok'}),False,'redact'),
 ('stderr','connection failed peer='+IP,True,'redact'),
 ('numbered-test-log',TEST_LOG,False,'redact'),
 ('numbered-test-stderr',TEST_LOG,True,'redact'),
 ('numbered-test-credential',TEST_LOG+'    password='+SECRET+'\n',False,'block'),
 ('numbered-test-source',TEST_LOG+'    func synthetic() {\n',False,'block'),
 ('mixed-test-log',TEST_TAIL,False,'redact'),
 ('mixed-test-source-ip',TEST_TAIL,False,'block'),
 ('credential','password='+SECRET,False,'block'),
 ('stderr-credential','password='+SECRET,True,'block'),
 ('stderr-code','const peer="'+IP+'";',True,'block'),
 ('json-array',json.dumps({'peers':[IP,IP]}),False,'redact'),
 ('nested-json',json.dumps({'data':json.dumps({'peer':IP})}),False,'redact'),
 ('unicode','连接成功 😀 peer='+IP,False,'redact'),
 ('isolated-control','peer='+IP,False,'absent'),
 ('disabled-safe-mode','peer='+IP,False,'disabled'),
 ('mixed','peer='+IP+' password='+SECRET,False,'block'),
 ('code','const peer="'+IP+'";',False,'block'),
 ('ambiguous',IP,False,'block'),
 ('duplicate-json','{"peer":"'+IP+'","peer":"clean"}',False,'block'),
 ('key-json','{"'+IP+'":"value"}',False,'block'),
 ('input-rejection','BUILD_OK',False,'input'),
 ('legacy-lock','peer='+IP,False,'legacy'),
 ('overlap','peer='+IP,False,'overlap'),
 ('unsupported-read','peer='+IP,False,'read'),
]
def normalized_strings(value):
 if isinstance(value,dict):return '\n'.join(normalized_strings(x) for pair in value.items() for x in pair)
 if isinstance(value,list):return '\n'.join(map(normalized_strings,value))
 if not isinstance(value,str):return ''
 value=re.sub(r'\\u([0-9a-fA-F]{4})',lambda m:chr(int(m[1],16)),value)
 return re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',value)
def events(message):
 out=[('message_start',{'type':'message_start','message':{**message,'content':[],'stop_reason':None}})]
 for i,c in enumerate(message['content']):
  start={**c};start.update({'text':''} if c['type']=='text' else {'input':{}})
  delta={'type':'text_delta','text':c['text']} if c['type']=='text' else {'type':'input_json_delta','partial_json':json.dumps(c['input'])}
  out.extend([('content_block_start',{'type':'content_block_start','index':i,'content_block':start}),('content_block_delta',{'type':'content_block_delta','index':i,'delta':delta}),('content_block_stop',{'type':'content_block_stop','index':i})])
 out.extend([('message_delta',{'type':'message_delta','delta':{'stop_reason':message['stop_reason'],'stop_sequence':None},'usage':{'output_tokens':10}}),('message_stop',{'type':'message_stop'})])
 return ''.join('event: '+k+'\ndata: '+json.dumps(v)+'\n\n' for k,v in out).encode()
def run_case(case):
 name,value,error,action=case
 with tempfile.TemporaryDirectory(prefix='safeguard-recovery-') as tmp:
  b=pathlib.Path(tmp);home=b/'home';home.mkdir();plugin=b/'plugin';plugin.mkdir()
  for directory in ['hooks','dist','.claude-plugin']:shutil.copytree(ROOT/directory,plugin/directory)
  (plugin/'local').mkdir();cfg=json.loads((ROOT/'config/tool-results.json').read_text())
  cfg['schemaVersion']=2;cfg['policy']['recovery']='next-safe-user-prompt'
  network=cfg['rules'][0];network['detector']={'kind':'ip','mode':'any','excludeCidrs':['127.0.0.0/8']}
  cfg['rules'].append({**network,'id':'network.address.output','sources':['tool.result'],'action':'redact'})
  network['sources']=['user.prompt']
  if action in ['legacy','overlap']:
   if action=='legacy':cfg['rules'].pop()
   network['sources'].append('tool.result')
   if action=='legacy':cfg['schemaVersion']=1;cfg['policy'].pop('recovery')
  (plugin/'local/rules.json').write_text(json.dumps(cfg));fixture=b/'fixture.txt';fixture.write_text(value)
  quoted_fixture=shlex.quote(str(fixture))
  command=(f"grep -n -B1 -A4 -- '^--- FAIL:' {quoted_fixture} | cut -c1-260"
           if name.startswith('numbered-test-') else 'cat '+quoted_fixture)
  if name.startswith('mixed-test-'):
   source=(f'var field, action, peer = "message", "send", "{IP}"' if name=='mixed-test-source-ip'
           else 'var fields = []string{"message", "send"}')
   (b/'fixture.go').write_text('package fixture\n\n'+source+'\n')
   source_pattern=shlex.quote('"message", "send"')
   command=f'git grep -n --no-index -- {source_pattern} fixture.go | head -3; tail -30 {quoted_fixture}'
  if error:command='{ '+command+'; } >&2; exit 7'
  requests=[]
  class H(http.server.BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_POST(self):
    d=json.loads(self.rfile.read(int(self.headers['Content-Length'])));requests.append(d)
    follow='FOLLOWUP_SAFE' in json.dumps(d.get('messages',[]))
    has_result=any(isinstance(m.get('content'),list) and any(c.get('type')=='tool_result' for c in m['content'] if isinstance(c,dict)) for m in d.get('messages',[]))
    if follow or has_result:blocks=[{'type':'text','text':'SAFE_FOLLOWUP_OK' if follow else 'RESULT_OK'}]
    elif action=='read':blocks=[{'type':'tool_use','id':'fixture_call','name':'Read','input':{'file_path':str(fixture)}}]
    else:blocks=[{'type':'tool_use','id':'fixture_call','name':'Bash','input':{'command':command}}]
    msg={'id':'msg_fixture','type':'message','role':'assistant','model':d['model'],'content':blocks,'stop_reason':'end_turn' if blocks[0]['type']=='text' else 'tool_use','stop_sequence':None,'usage':{'input_tokens':10,'output_tokens':10}}
    body=events(msg);self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  server=http.server.ThreadingHTTPServer(('127.0.0.1',0),H);threading.Thread(target=server.serve_forever,daemon=True).start()
  env={'PATH':os.environ['PATH'],'HOME':str(home),'CLAUDE_CONFIG_DIR':str(home/'config'),'ANTHROPIC_API_KEY':'synthetic-local-only','ANTHROPIC_BASE_URL':f'http://127.0.0.1:{server.server_port}','DISABLE_TELEMETRY':'1','DISABLE_ERROR_REPORTING':'1','CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1'}
  args=[CLAUDE,'-p','--input-format','stream-json','--output-format','stream-json','--verbose','--plugin-dir',str(plugin),'--setting-sources','','--dangerously-skip-permissions','--tools','Bash,Read','--model','claude-sonnet-4-6']
  if action=='absent':
   i=args.index('--plugin-dir');del args[i:i+2]
  if action=='disabled':args+=['--safe-mode']
  proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env,cwd=b);q=queue.Queue();outputs=[];stderr=[]
  def reader():
   for line in proc.stdout:
    try:d=json.loads(line);outputs.append(d);q.put(d)
    except ValueError:pass
   q.put({'type':'eof'})
  threading.Thread(target=reader,daemon=True).start();threading.Thread(target=lambda:stderr.extend(proc.stderr),daemon=True).start()
  def send(text):proc.stdin.write(json.dumps({'type':'user','message':{'role':'user','content':text}})+'\n');proc.stdin.flush()
  def result():
   deadline=time.monotonic()+30
   while time.monotonic()<deadline:
    d=q.get(timeout=max(.1,deadline-time.monotonic()))
    if d.get('type') in ['result','eof']:return d
   raise TimeoutError('result timeout')
  try:
   send('password='+SECRET if action=='input' else 'Run the local fixture once.');first=result();first_count=len(requests)
   assert first['type']=='result',(name,'no first result')
   expected=0 if action=='input' else 2 if action in ['pass','redact','absent','disabled'] else 1
   assert first_count==expected,(name,'first requests',first_count,expected)
   send('FOLLOWUP_SAFE: skip the previous operation and reply without tools.');second=result()
   assert len(requests)==first_count+(0 if action=='legacy' else 1),(name,'recovery request count',len(requests),second.get('subtype'))
   if action!='legacy':assert 'SAFE_FOLLOWUP_OK' in json.dumps(second),(name,'recovery answer missing')
   proc.stdin.close();proc.wait(timeout=10)
   raw=normalized_strings(requests);history='\n'.join(normalized_strings(json.loads(line)) for f in (home/'config/projects').rglob('*.jsonl') for line in f.read_text().splitlines() if line.strip())
   # User-input denial may be saved locally by the host; never permitted in requests.
   if action in ['absent','disabled']:
    assert IP in raw and IP in history,(name,'negative control did not expose fixture')
    return {'case':name,'passed':True,'firstRequests':first_count,'rawInRequests':True,'rawInToolHistory':True,'scope':'negative-control-'+action}
   for token in [IP,'2001:db8::7',SECRET]:assert token not in raw,(name,'raw in request')
   if action!='input':
    for token in [IP,'2001:db8::7',SECRET]:assert token not in history,(name,'raw in history')
   if action=='redact':assert '[IP_' in raw,(name,'missing label', [c for d in requests for m in d.get('messages',[]) if isinstance(m.get('content'),list) for c in m['content'] if c.get('type')=='tool_result'])
   if name.startswith('numbered-test-') and action=='redact':
    assert 'addr=[[IP_1]]:8080' in raw and 'testing.tRunner(0x1, {0x2})' in raw,(name,'diagnostic content lost')
   if name=='mixed-test-log':
    assert 'fixture.go:3:var fields = []string{"message", "send"}' in raw,(name,'source content changed')
    assert 'addr=[[IP_1]]:8080' in raw and 'example.invalid/test/e2e' in raw,(name,'test output changed')
   if error and action=='redact':
    results=[c for d in requests for m in d.get('messages',[]) if isinstance(m.get('content'),list) for c in m['content'] if c.get('type')=='tool_result']
    assert any(c.get('is_error') for c in results),(name,'error status lost')
   # Real persisted resume and fork, using the same local recorder.
   sid=first.get('session_id');assert sid,(name,'missing session id')
   resumed=[]
   for fork in [False,True]:
    cmd=[CLAUDE,'-p','FOLLOWUP_SAFE: no tools.','--resume',sid,'--plugin-dir',str(plugin),'--setting-sources','','--dangerously-skip-permissions','--model','claude-sonnet-4-6']+(['--fork-session'] if fork else [])
    before=len(requests);r=subprocess.run(cmd,cwd=b,env=env,capture_output=True,text=True,timeout=30)
    assert r.returncode==0 and len(requests)>before and 'SAFE_FOLLOWUP_OK' in r.stdout,(name,'resume failed',fork,r.stderr[-150:])
    for token in [IP,'2001:db8::7',SECRET]:assert token not in normalized_strings(requests[before:]),(name,'resume leaked',fork)
    resumed.append('fork' if fork else 'resume')
   return {'case':name,'firstRequests':first_count,'sameProcessRecovered':action!='legacy','redacted':action=='redact','resume':resumed,'rawInRequests':False,'rawInToolHistory':False if action!='input' else 'input-history-out-of-scope','passed':True}
  finally:
   if proc.poll() is None:proc.kill();proc.wait()
   server.shutdown()
if __name__=='__main__':
 report=[]
 for case in CASES:
  if os.environ.get('SAFEGUARD_CASE') and case[0]!=os.environ['SAFEGUARD_CASE']:continue
  try:row=run_case(case)
  except Exception as e:row={'case':case[0],'passed':False,'error':str(e)}
  report.append(row);print(json.dumps(row),flush=True)
 (ROOT/'benchmarks/results').mkdir(exist_ok=True)
 (ROOT/'benchmarks/results/recovery-e2e.json').write_text(json.dumps(report,indent=2)+'\n')
 assert all(r['passed'] for r in report),'Some recovery cases failed'
