const test=require('node:test'),assert=require('node:assert/strict');
const {resolveConfig}=require('../assets/miniapp-network/runtime-config');
const {createClient}=require('../assets/miniapp-network/api-client');
const settings={mode:'experience',apiBase:'https://api.acme.cn'};
test('experience requires an explicit public HTTPS origin',()=>{
  for(const apiBase of ['', 'http://api.acme.cn','https://localhost','https://192.168.1.1','https://10.1.2.3','https://127.0.0.2','https://api.example.com','https://user:pass@api.acme.cn','https://api.acme.cn/#secret'])assert.throws(()=>resolveConfig({...settings,apiBase}));
  assert.equal(resolveConfig(settings).apiBase,settings.apiBase);
  assert.equal(resolveConfig({mode:'development',apiBase:'http://127.0.0.1:8000/'}).apiBase,'http://127.0.0.1:8000');
});
test('no fallback to LAN or unknown mode and no override of immutable resolved config',()=>{
  assert.throws(()=>resolveConfig({mode:'demo',apiBase:'https://api.acme.cn'}));
  const r=resolveConfig(settings);assert.equal(Object.isFrozen(r),true);
});
function setup(reply){const calls=[],unauthorized=[];const wx={request:r=>{calls.push(r);reply(r);}};return {calls,unauthorized,client:createClient({wx,config:settings,getSessionToken:()=> 'session-test',onUnauthorized:e=>unauthorized.push(e)})};}
test('correct endpoint and session per request, no administrator header',async()=>{
  const s=setup(r=>r.success({statusCode:200,data:{ok:true},header:{}}));
  assert.deepEqual(await s.client.get('/api/me'),{ok:true});assert.equal(s.calls[0].header.Authorization,'Bearer session-test');assert.equal(s.calls[0].url,'https://api.acme.cn/api/me');
  assert.deepEqual(Object.keys(s.calls[0].header).sort(),['Authorization','content-type']);
});
test('lost mutation response is uncertain and never retried automatically',async()=>{
  const s=setup(r=>r.fail({errMsg:'timeout'}));await assert.rejects(s.client.post('/api/orders',{amount:100}),e=>e.code==='RESULT_UNKNOWN'&&e.uncertain===true);assert.equal(s.calls.length,1);
});
test('read failure does not claim committed business action',async()=>{
  const s=setup(r=>r.fail({errMsg:'timeout'}));await assert.rejects(s.client.get('/api/me'),e=>e.code==='NETWORK_ERROR'&&e.uncertain===false);
});
test('401 invalidates once; 409 retains explicit conflict without replay',async()=>{
  for(const status of [401,409]){const s=setup(r=>r.success({statusCode:status,data:{code:'FAIL',error:'rejected'}}));await assert.rejects(s.client.post('/api/orders',{}),e=>e.status===status);assert.equal(s.calls.length,1);assert.equal(s.unauthorized.length,status===401?1:0);}
});
test('paths cannot exfiltrate session tokens to alternate origins',async()=>{
  const s=setup(r=>r.success({statusCode:200,data:{}}));
  for(const path of ['https://other.cn','//other.cn/api','/../admin','/api/./x','/api/\\evil'])await assert.rejects(s.client.get(path));assert.equal(s.calls.length,0);
});
test('encoded paths and unknown config rejected before sending',async()=>{
  assert.throws(()=>resolveConfig({...settings,adminKey:'test'}));
  const s=setup(r=>r.success({statusCode:200,data:{}}));
  for(const p of ['/%2e%2e/admin','/%252e%252e/admin','/%2fother.cn','/api/%5cevil','/api/%00'])await assert.rejects(s.client.get(p));
  assert.equal(s.calls.length,0);
});
test('fresh token and empty session do not use privileged fallbacks',async()=>{
  let token='',headers=[];
  const client=createClient({wx:{request:r=>{headers.push(r.header);r.success({statusCode:200,data:{}});}},config:settings,getSessionToken:()=>token});
  await client.get('/api/public');token='new-session';await client.get('/api/me');
  assert.equal(headers[0].Authorization,undefined);assert.equal(headers[1].Authorization,'Bearer new-session');
});
test('mutation server failure is uncertain with safe error text',async()=>{
  const s=setup(r=>r.success({statusCode:503,data:{error:'private diagnostic'}}));
  await assert.rejects(s.client.post('/api/jobs',{}),e=>e.uncertain&&e.status===503&&!e.message.includes('private'));
  assert.equal(s.calls.length,1);
});
