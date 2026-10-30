const {test}=require('node:test'),assert=require('node:assert/strict');
const core=require('../dashboard/static/js/workspace.js');
test('graph labels fit narrow nodes without splitting unicode characters',()=>{
 assert.equal(core.fitGraphLabel('127.0.0.1',156,18),'127.0.0.1');
 const name='ftp_data_theft FTP 下载敏感诱饵文件并返回虚拟响应';
 const short=core.fitGraphLabel(name,236,18);
 assert.ok(short.endsWith('…'));assert.ok(short.length<name.length);
 const units=s=>Array.from(s).reduce((n,c)=>n+(/[^\x00-\x7f]/.test(c)?1:.65),0);
 assert.ok(units(short)*18<=236);
 assert.ok(core.fitGraphLabel('🛡️'.repeat(30),100,18).endsWith('…'));
});
test('section belongs to its parent and invalid tabs recover to default',()=>{assert.equal(core.sectionFor('sessions','graph'),'graph');assert.equal(core.sectionFor('settings','calls'),'calls');assert.equal(core.sectionFor('sessions','effects'),'timeline')});
test('graph preserves capture boundaries and bounded grouped facts',()=>{const rows=[{id:'a',src_ip:'192.0.2.1',session_id:'A',excerpt:'GET /news query=x headers={}',channel:'web'},{id:'b',src_ip:'192.0.2.1',session_id:'B',excerpt:'GET /news query=y headers={}',channel:'web'},{id:'c',src_ip:'192.0.2.1',session_id:'A',excerpt:'GET /news query=z headers={}',channel:'web'}];const g=core.projectGraph(rows);assert.equal(g.groups.length,2);assert.equal(g.groups.find(r=>r.session==='A').records.length,2);assert.equal(g.total,3);assert.equal(core.projectGraph([]).groups.length,0)});

test('virtual replies stay readable and never imply a real host compromise',()=>{assert.equal(core.virtualReply('{\"status\":\"signed_in\"}'),'模拟业务已登录');assert.equal(core.virtualReply('{\"status\":\"queued\"}'),'虚拟任务排队中');assert.equal(core.virtualReply('{\"items\":[1,2]}'),'返回2条模拟目录记录');assert.ok(core.virtualReply('x'.repeat(1000)).length<=180)});
