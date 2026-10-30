// Exercise the real UI modules, including zoom anchor invariants and update
// coalescing; actual canvas hit-testing/dragging is covered by browser evidence.
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const root=path.resolve(__dirname,'../dashboard/static/js');
const context={window:{},document:{hidden:false},console};vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(root,'world_map.js'),'utf8'),context);
const proto=context.window.CachedWorldMap.prototype;
const map=Object.create(proto);Object.assign(map,{width:3066,height:1646,base:.8,zoom:1.1,pan:[70,-30],tip:{hidden:false},emit(){},schedule(){},point:[1,2]});
const p=map.screen([120,30]);map.scaleBy(1.5,p);const q=map.screen([120,30]);assert(Math.hypot(p[0]-q[0],p[1]-q[1])<1e-7,'zoom must preserve coordinate beneath anchor');
map.scaleBy(100);assert.equal(map.zoom,10);map.scaleBy(.0001);assert.equal(map.zoom,1.1);map.reset();assert.deepEqual(map.pan,[0,0]);
const calls=[];const callbacks=[],elements=new Map(['topList','suspiciousScroll','sessionScroll','pieChart'].map(id=>[id,{dataset:{},childElementCount:1}]));
const c={window:{updateTopList:v=>calls.push(v),updateSuspiciousRequests(){},updateSessionAnalysis(){},updatePieChart(){}},document:{hidden:false,getElementById:id=>elements.get(id),addEventListener(){}},_mapGestureActive:false,geoLocationCacheByIp:{},getDashboardWindowHours:()=>24,isDemoMode:false,setTimeout:fn=>(callbacks.push(fn),1),console};vm.createContext(c);vm.runInContext(fs.readFileSync(path.join(root,'panel_updates.js'),'utf8'),c);
c.window.updateTopList([{src_ip:'192.0.2.1',count:1}]);c.window.updateTopList([{src_ip:'192.0.2.1',count:1}]);assert.equal(calls.length,1,'unchanged panel must remain intact');
c._mapGestureActive=true;c.window.updateTopList([{src_ip:'192.0.2.1',count:2}]);c.window.updateTopList([{src_ip:'192.0.2.1',count:3}]);assert.equal(calls.length,1,'no heavy panel update during drag');c._mapGestureActive=false;callbacks.shift()();assert.equal(calls.length,2);assert.equal(calls[1][0].count,3,'only latest pending data applied');
console.log(JSON.stringify({status:'passed',checks:['zoom_anchor','zoom_max','zoom_min','reset','unchanged_panel','deferred_panel','coalesced_latest']}));
