#!/usr/bin/env python3
"""Actual installed Claude + desktop backend, synthetic local model, isolated HOME.
No real account, user plugin installation or private rules are read or changed.
"""
import base64,hashlib,http.server,json,os,pathlib,shutil,subprocess,tempfile,threading,time
ROOT=pathlib.Path(__file__).resolve().parents[2]
EXE=ROOT/'desktop/target/release/agent-safeguard-desktop'
CLAUDE=shutil.which('claude')
assert CLAUDE
reports=[]
with tempfile.TemporaryDirectory(prefix='safeguard-desktop-flow-') as tmp:
 base=pathlib.Path(tmp);home=base/'home';home.mkdir();work=base/'work';work.mkdir();data=base/'data'
 env={'PATH':os.environ['PATH'],'HOME':str(home),'CLAUDE_CONFIG_DIR':str(home/'config'),'ANTHROPIC_API_KEY':'synthetic-local-only','DISABLE_TELEMETRY':'1','DISABLE_ERROR_REPORTING':'1','CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1'}
 def backend(action,text=None,extra=()):
  p=subprocess.run([str(EXE),'--data-dir',str(data),'--backend',action,*extra],env=env,cwd=work,input=text,capture_output=True,text=True,timeout=80)
  result=json.loads(p.stdout);assert p.returncode==0 and result['ok'],(action,result);return result.get('data')
 backend('install');rules=data/'marketplace/plugins/agent-safeguard/local/rules.json'
 original=json.loads(rules.read_text());assert all(not r['id'].startswith('personal.synthetic-') for r in original['rules'])
 def run_case(name,output,blocked,hold=False):
  requests=[];entered=threading.Event();release=threading.Event()
  class Handler(http.server.BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_POST(self):
    req=json.loads(self.rfile.read(int(self.headers['Content-Length'])));requests.append(req);entered.set()
    if hold and len(requests)==1:release.wait(25)
    has_result=any(isinstance(m.get('content'),list) and any(b.get('type')=='tool_result' for b in m['content']) for m in req.get('messages',[]))
    blocks=[{'type':'text','text':'done'}] if has_result else [{'type':'tool_use','id':'tool_synthetic','name':'Bash','input':{'command':'printf %s '+base64.b64encode(output.encode()).decode()+' | base64 --decode','description':'Synthetic fixture'}}]
    msg={'id':'msg_fixture','type':'message','role':'assistant','model':req.get('model','test'),'content':blocks,'stop_reason':'end_turn' if has_result else 'tool_use','stop_sequence':None,'usage':{'input_tokens':10,'output_tokens':10}}
    events=[('message_start',{'type':'message_start','message':{**msg,'content':[],'stop_reason':None}})]
    for i,b in enumerate(blocks):
     initial={**b};initial['text']='' if b['type']=='text' else ''
     if b['type']=='tool_use':initial.pop('text',None);initial['input']={}
     events.append(('content_block_start',{'type':'content_block_start','index':i,'content_block':initial}))
     delta={'type':'text_delta','text':b['text']} if b['type']=='text' else {'type':'input_json_delta','partial_json':json.dumps(b['input'])}
     events.extend([('content_block_delta',{'type':'content_block_delta','index':i,'delta':delta}),('content_block_stop',{'type':'content_block_stop','index':i})])
    events.extend([('message_delta',{'type':'message_delta','delta':{'stop_reason':msg['stop_reason'],'stop_sequence':None},'usage':{'output_tokens':10}}),('message_stop',{'type':'message_stop'})])
    body=''.join('event: '+e+'\ndata: '+json.dumps(v)+'\n\n' for e,v in events).encode()
    self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
  ids={s['session'] for s in backend('sessions')['sessions']}
  proc=subprocess.Popen([CLAUDE,'-p','Run the synthetic fixture command.','--no-session-persistence','--setting-sources','user','--dangerously-skip-permissions','--tools','Bash','--model','claude-sonnet-4-6','--max-turns','3'],cwd=work,env={**env,'ANTHROPIC_BASE_URL':f'http://127.0.0.1:{server.server_port}'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  try:
   assert entered.wait(20),'model did not receive initial request'
   if hold:
    deadline=time.monotonic()+8;live=[]
    while time.monotonic()<deadline:
     live=[s for s in backend('sessions')['sessions'] if s['session'] not in ids]
     if live and live[0]['ready']:break
     time.sleep(.15)
    if not (live and live[0]['ready'] and not live[0]['ended']):
     release.set();out,err=proc.communicate(timeout=35)
     print('status diagnostics',json.dumps({'rows':live,'files':[str(p.relative_to(base)) for p in base.rglob('desktop.json')],'session_files':[str(p.relative_to(base)) for p in base.rglob('sessions/*.json')],'stderr':err[-3000:],'stdout':out[-1000:]}))
     raise AssertionError('no automatic live report')
    first=live[0]['updatedAt'];time.sleep(16)
    heartbeat=[s for s in backend('sessions')['sessions'] if s['session'] not in ids]
    assert heartbeat[0]['updatedAt']>first,'heartbeat did not advance'
   release.set();stdout,stderr=proc.communicate(timeout=35);assert proc.returncode==0,(name,'host failed')
   # Reports on session.end are best effort; allow asynchronous host write to finish.
   deadline=time.monotonic()+4;new=[]
   while time.monotonic()<deadline:
    new=[s for s in backend('sessions')['sessions'] if s['session'] not in ids]
    if new and (not blocked or new[0]['lastRule']=='custom.rule'):break
    time.sleep(.1)
   assert new,(name,'missing status')
   row=new[0];assert row['identity']['hostSessionId'];assert pathlib.Path(row['identity']['project']).resolve()==work.resolve(), 'project attribution mismatch'
   if blocked:
    assert row['interception'], {k:row[k] for k in ('schema','pluginVersion','lastRule','lastEvent','blocked','ended','interception')}
    assert row['interception']['ruleId']=='custom.flow'
    assert row['interception']['event']=='tool.result'
    assert list((data/'sessions/interceptions').glob('*.json')),'missing persisted interception'
   assert row['ruleVersion']==json.loads(rules.read_text())['ruleSetVersion']
   assert len(requests)==(1 if blocked else 2),(name,'request count',len(requests))
   if blocked:
    assert row['lastRule']=='custom.rule',(name,'missing block evidence')
    assert output not in json.dumps([m for req in requests for m in req.get('messages',[]) if m['role']=='user'])
   assert output not in json.dumps(new),(name,'raw output in status')
   reports.append({'case':name,'model_requests':len(requests),'auto_status':True,'heartbeat_verified':hold,'new_rules_loaded':row['ruleVersion']!=original['ruleSetVersion'],'blocked':blocked})
  finally:
   release.set()
   if proc.poll() is None:proc.kill();proc.communicate()
   server.shutdown()
 run_case('installed-clean','SYNTHETIC_DESKTOP_VALUE',False,True)
 cfg=json.loads(rules.read_text());cfg['rules'].append({'id':'custom.flow','enabled':True,'sources':['tool.input','tool.result','user.prompt'],'action':'block','detector':{'kind':'exact','values':['SYNTHETIC_DESKTOP_VALUE'],'caseSensitive':True}})
 saved=backend('apply',json.dumps(cfg),('--expected-digest',hashlib.sha256(rules.read_bytes()).hexdigest()))
 assert saved['version']!=original['ruleSetVersion']
 run_case('new-session-after-save','SYNTHETIC_DESKTOP_VALUE',True)
 assert len(backend('sessions')['sessions'])>=2
 backend('disable');backend('enable');backend('update');assert json.loads(rules.read_text())['ruleSetVersion']==saved['version']
 backend('uninstall');assert rules.exists()
print(json.dumps(reports,indent=2))
(ROOT/'desktop/artifacts').mkdir(exist_ok=True)
(ROOT/'desktop/artifacts/flow-results.json').write_text(json.dumps(reports,indent=2)+'\n')
