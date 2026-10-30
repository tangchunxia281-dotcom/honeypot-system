'use strict';
// Run the shipped browser script against a small DOM and controlled HTTP replies.
// Only browser I/O is substituted; the page handlers and asynchronous work are real.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {test}=require('node:test');
const source=fs.readFileSync(path.join(__dirname,'../dashboard/static/js/workspace.js'),'utf8');
const flush=()=>new Promise(resolve=>setImmediate(resolve));

class Element {
    constructor(tag='div'){this.tagName=tag;this.children=[];this.value='';this._text='';this.disabled=false;this.hidden=false;}
    set textContent(value){this._text=String(value);this.children=[];}
    get textContent(){return this._text+this.children.map(child=>child.textContent).join(' ');}
    append(...children){this.children.push(...children);}
    replaceChildren(...children){this._text='';this.children=children;}
    get firstChild(){return this.children[0]||null;}
    setAttribute(){}
    showModal(){}
    close(){}
}
function evidence(id='event-a',ip='192.0.2.1'){
    return {id,timestamp:'2026-10-29 12:00:13',channel:'web',src_ip:ip,session_id:'capture-a',table:'raw_request',record_id:1,kind:'request',rule_level:'low',excerpt:id,
        rule:{level:'low',score:0,signals:[]},ai:null,review:null};
}
function harness({view='events',search='?ws=1',prior=null,deferDetail=false,deferReview=false,deferCase=false}={}){
    const ids=['notice','back','refresh','closeRaw','rawDialog','rawText','cancelCase','newCaseDialog','caseCreateForm','caseTitle','confirmCase',
        'scopeForm','scopeText','scopeIp','scopeSession','scopeTerm','scopeStart','scopeEnd','toggleScope','clearScope','sync',
        'eventList','eventDetail','eventCount','pageNumber','previous','next'];
    if(view==='overview')ids.push('summary','recent','recentCases','indexHealth','openEvents');
    if(view==='investigate')ids.push('caseList','caseDetail','newCase');
    if(view==='settings'){
        for(const id of ['scopeForm','scopeText'])ids.splice(ids.indexOf(id),1);
        ids.push('environment','installedModels','catalogModels','modelDescription','setupTask','cancelSetup','downloadModel','testInstalled','saveModel','disableModel','checkEnvironment','ruleEvaluation','effectMetrics','evaluations');
    }
    const elements=new Map(ids.map(id=>[id,new Element()]));
    const nav=['overview','events','sessions','investigate','settings'].map(view=>({pathname:'/workspace/'+view,href:'/workspace/'+view}));
    const location={search,href:'/workspace/'+view+search,assign(value){this.href=value;}};
    const stored=new Map(prior?[['honeypot:workspace:'+view,JSON.stringify(prior)]]:[]);
    let localCase={id:'case-a',title:'调查A',query:{ip:'192.0.2.1'},status:'open',note:'',revision:0,created:1793246400,updated:1793246400,evidence:[evidence()],job_ids:[]};
    const pending=[];const calls=[];const jobs=new Map();let requestNumber=0;
    const response=value=>({status:200,ok:true,json:async()=>value});
    const fetch=async (request,options)=>{
        calls.push({request,options});
        const url=new URL(request,'http://localhost');
        if(url.pathname==='/api/workspace/overview')return response({total:0,channels:{},recent:[],cases:[],index:{error:''}});
        if(url.pathname==='/api/workspace/cases')return response({records:[{...localCase}]});
        if(url.pathname==='/api/workspace/cases/case-a/ask'){
            const payload=JSON.parse(options.body);
            if(!jobs.has(payload.request_id))jobs.set(payload.request_id,{id:'job-'+jobs.size,question:payload.question,status:'fallback',reason:'disabled',result:{},steps:[]});
            const job=jobs.get(payload.request_id);if(!localCase.job_ids.includes(job.id))localCase.job_ids.unshift(job.id);
            return response(job);
        }
        if(url.pathname.startsWith('/api/local/jobs/'))return response([...jobs.values()].find(j=>j.id===url.pathname.split('/').pop()));
        if(url.pathname==='/api/workspace/cases/case-a'){
            if(options.method==='POST')localCase={...localCase,...JSON.parse(options.body),revision:localCase.revision+1};
            if(deferCase)return new Promise(resolve=>pending.push({kind:'case',resolve:value=>resolve(response(value||{...localCase}))}));
            return response({...localCase});
        }
        if(url.pathname==='/api/setup/environment')return response({service_reachable:false,installed:[],catalog:[],hardware:{},current:{enabled:false,model:''}});
        if(url.pathname==='/api/setup/tasks/current')return response({status:'idle'});
        if(url.pathname==='/api/local/effects')return response({calls:{total:0,valid:0},human_acceptance:{reviewed:0,accepted:0}});
        if(url.pathname==='/api/workbench/evaluations')return response([]);
        if(url.pathname.endsWith('/review')){
            if(deferReview)return new Promise(resolve=>pending.push({kind:'review',resolve:value=>resolve(response(value))}));
            return response({revision:1,label:'uncertain',note:''});
        }
        if(url.pathname.startsWith('/api/workspace/events/')){
            if(deferDetail)return new Promise(resolve=>pending.push({kind:'detail',resolve:value=>resolve(response(value))}));
            return response(evidence(url.pathname.split('/').pop()));
        }
        assert.equal(url.pathname,'/api/workspace/events');
        const secondPage=!!url.searchParams.get('cursor');
        const records=url.searchParams.get('ip')==='198.51.100.2'?[]:[evidence(secondPage?'event-page-two':'event-a')];
        return response({records,total:31,next:secondPage?'':'page2-cursor'});
    };
    function dynamic(id){function walk(e){if(e.id===id)return e;for(const child of e.children){const found=walk(child);if(found)return found;}return null;}for(const e of elements.values()){const found=walk(e);if(found)return found;}return null;}
    const context={document:{body:{dataset:{workspace:view}},getElementById:id=>elements.get(id)||dynamic(id),createElement:tag=>new Element(tag),
        querySelector:()=>({content:'test-csrf'}),querySelectorAll:()=>nav},location,
        history:{length:2,back(){},replaceState(_state,_title,url){location.href=url;location.search=new URL(url,'http://localhost').search;}},
        sessionStorage:{getItem:key=>stored.get(key)||null,setItem:(key,value)=>stored.set(key,value),removeItem:key=>stored.delete(key)},
        crypto:{randomUUID:()=>String(++requestNumber)},
        fetch,URLSearchParams,AbortController,setTimeout,clearTimeout,scrollY:0,scrollTo(){},window:{addEventListener(){}}};
    vm.createContext(context);vm.runInContext(source,context,{filename:'workspace.js'});
    const get=id=>elements.get(id)||dynamic(id)||undefined;
    function findButton(root,text){for(const child of root.children){if(child.tagName==='button'&&child.textContent===text)return child;const nested=findButton(child,text);if(nested)return nested;}return null;}
    return {get,location,calls,nav,flush,
        click(root,text){const button=findButton(get(root),text);assert.ok(button,'missing button '+text);return button.onclick();},
        filter(ip){get('scopeIp').value=ip;get('scopeForm').onsubmit({preventDefault(){}});},
        release(kind,value){const index=pending.findIndex(item=>item.kind===kind);assert.notEqual(index,-1,'missing pending '+kind);pending.splice(index,1)[0].resolve(value);},
        dispose(){for(const item of pending.splice(0))item.resolve(item.kind==='detail'?evidence():{});}
    };
}

test('a pending event cannot restore itself after the source filter changes',async t=>{
    const page=harness({deferDetail:true});t.after(()=>page.dispose());await page.flush();
    const detail=page.click('eventList','查看记录');
    page.filter('198.51.100.2');await page.flush();
    page.release('detail',evidence());await detail;
    const url=new URL(page.location.href,'http://localhost');
    assert.equal(url.searchParams.get('ip'),'198.51.100.2');
    assert.equal(url.searchParams.has('event'),false,'stale detail restored its event URL');
    assert.equal(page.get('eventDetail').textContent.includes('event-a'),false);
});

test('a completed event and its actions are cleared when the filter changes',async()=>{
    const page=harness();await page.flush();await page.click('eventList','查看记录');
    assert.match(page.get('eventDetail').textContent,/event-a/);
    page.filter('198.51.100.2');await page.flush();
    assert.doesNotMatch(page.get('eventDetail').textContent,/event-a|加入新调查|保存复核意见/);
});

test('clearing the scope also discards a pending event response',async t=>{
    const page=harness({search:'?ws=1&ip=192.0.2.1',deferDetail:true});t.after(()=>page.dispose());await page.flush();
    const detail=page.click('eventList','查看记录');
    page.get('clearScope').onclick();await page.flush();page.release('detail',evidence());await detail;
    assert.equal(new URL(page.location.href,'http://localhost').searchParams.has('event'),false);
    assert.doesNotMatch(page.get('eventDetail').textContent,/event-a/);
});

test('moving to the next page discards a pending detail from the previous page',async t=>{
    const page=harness({deferDetail:true});t.after(()=>page.dispose());await page.flush();
    const detail=page.click('eventList','查看记录');
    page.get('next').onclick();await page.flush();page.release('detail',evidence());await detail;
    assert.equal(new URL(page.location.href,'http://localhost').searchParams.get('cursor'),'page2-cursor');
    assert.doesNotMatch(page.get('eventDetail').textContent,/event-a/);
});

test('an in-flight review saves its target but cannot reselect it after filtering',async t=>{
    const page=harness({deferReview:true});t.after(()=>page.dispose());await page.flush();await page.click('eventList','查看记录');
    const review=page.click('eventDetail','保存复核意见');
    page.filter('198.51.100.2');await page.flush();
    page.release('review',{revision:1,label:'uncertain',note:''});await review;
    assert.equal(new URL(page.location.href,'http://localhost').searchParams.has('event'),false);
    assert.doesNotMatch(page.get('eventDetail').textContent,/event-a/);
});

test('reload or Back restores matching cursor pagination and the previous-page action',async()=>{
    const prior={scope:{},cursor:'page2-cursor',page:2,stack:[''],params:'ws=1&cursor=page2-cursor'};
    const page=harness({search:'?ws=1&cursor=page2-cursor',prior});await page.flush();
    assert.equal(page.get('pageNumber').textContent,'第 2 页');
    assert.equal(page.get('previous').disabled,false);
    assert.match(page.get('eventList').textContent,/event-page-two/);
    page.get('previous').onclick();await page.flush();
    assert.equal(page.get('pageNumber').textContent,'第 1 页');
    assert.equal(page.get('previous').disabled,true);
    assert.match(page.get('eventList').textContent,/event-a/);
});

test('saved pagination never overrides a URL with a different explicit scope',async()=>{
    const prior={scope:{ip:'192.0.2.1'},cursor:'page2-cursor',page:2,stack:[''],params:'ws=1&ip=192.0.2.1&cursor=page2-cursor'};
    const page=harness({search:'?ws=1&ip=198.51.100.2',prior});await page.flush();
    assert.equal(page.get('scopeIp').value,'198.51.100.2');
    assert.equal(page.get('pageNumber').textContent,'第 1 页');
    assert.equal(page.get('previous').disabled,true);
    assert.equal(page.get('eventList').textContent.includes('event-page-two'),false);
});

test('matching saved pagination does not replace the explicit selected event',async()=>{
    const prior={scope:{},cursor:'page2-cursor',page:2,stack:[''],params:'ws=1&cursor=page2-cursor&event=event-a'};
    const page=harness({search:'?ws=1&cursor=page2-cursor&event=event-b',prior});await page.flush();
    assert.match(page.get('eventDetail').textContent,/event-b/);
    assert.doesNotMatch(page.get('eventDetail').textContent,/event-a/);
});

test('saving case status refreshes the left list while retaining the review tab',async()=>{
    const page=harness({view:'investigate',search:'?ws=1&case=case-a'});await page.flush();
    assert.match(page.get('caseList').textContent,/待调查/);
    await page.click('caseDetail','人工处理与导出');
    const select=page.get('caseDetail').children.at(-1).children.find(child=>child.tagName==='select');
    assert.ok(select);select.value='reviewing';await page.click('caseDetail','保存处理状态');
    assert.match(page.get('caseList').textContent,/调查A \/ 复核中/);
    assert.doesNotMatch(page.get('caseList').textContent,/待调查/);
    assert.match(page.get('caseDetail').textContent,/保存处理状态/,'review tab should remain open');
});

test('settings sidebar preserves the incoming evidence scope without filter inputs',async()=>{
    const page=harness({view:'settings',search:'?ws=1&ip=192.0.2.1&session=capture-a&term=run-A'});await page.flush();
    assert.equal(page.get('scopeText'),undefined);
    for(const item of page.nav){
        const query=new URL(item.href,'http://localhost').searchParams;
        assert.equal(query.get('ip'),'192.0.2.1');
        assert.equal(query.get('session'),'capture-a');
        assert.equal(query.get('term'),'run-A');
    }
});

test('a pending case cannot restore its old scope after the filter changes',async t=>{
    const page=harness({view:'investigate',search:'?ws=1&case=case-a',deferCase:true});t.after(()=>page.dispose());await page.flush();
    page.filter('198.51.100.2');await page.flush();page.release('case');await page.flush();
    const query=new URL(page.location.href,'http://localhost').searchParams;
    assert.equal(query.get('ip'),'198.51.100.2');
    assert.equal(query.has('case'),false);
    assert.doesNotMatch(page.get('caseDetail').textContent,/调查A/);
});

test('changing scope clears the selected case and its previous review actions',async()=>{
    const page=harness({view:'investigate',search:'?ws=1&case=case-a'});await page.flush();await page.click('caseDetail','人工处理与导出');
    assert.match(page.get('caseDetail').textContent,/调查A/);
    page.filter('198.51.100.2');await page.flush();
    assert.doesNotMatch(page.get('caseDetail').textContent,/调查A|保存处理状态/);
});

test('overview open-events link carries the active scope instead of restoring an older event filter',async()=>{const page=harness({view:'overview',search:'?ws=1&ip=192.0.2.1&term=run-A'});await page.flush();const query=new URL(page.get('openEvents').href,'http://localhost').searchParams;assert.equal(query.get('ip'),'192.0.2.1');assert.equal(query.get('term'),'run-A');assert.equal(query.get('ws'),'1')});

test('unsaved case note survives switching away and back to review',async()=>{
    const page=harness({view:'investigate',search:'?ws=1&case=case-a'});await page.flush();
    await page.click('caseDetail','人工处理与导出');
    const content=()=>page.get('caseDetail').children.at(-1);
    content().children.find(e=>e.tagName==='textarea').value='尚未保存的重要复核笔记';
    await page.click('caseDetail','证据快照');await page.click('caseDetail','人工处理与导出');
    assert.equal(content().children.find(e=>e.tagName==='textarea').value,'尚未保存的重要复核笔记');
    await page.click('caseDetail','保存处理状态');
    assert.match(page.get('caseDraftStatus').textContent,/已保存/);
    assert.doesNotMatch(page.get('caseDraftStatus').textContent,/未保存/);
});

test('question draft survives switching tabs and failed submit can create a new task',async()=>{
    const page=harness({view:'investigate',search:'?ws=1&case=case-a'});await page.flush();
    await page.click('caseDetail','提问与补查');page.get('caseQuestion').value='请解释这些合成记录';
    await page.click('caseDetail','证据快照');await page.click('caseDetail','提问与补查');
    assert.equal(page.get('caseQuestion').value,'请解释这些合成记录');
    await page.click('caseDetail','开始提问与补查');
    await page.click('activeJob','重新执行此问题');
    const submits=page.calls.filter(c=>c.request.endsWith('/ask')).map(c=>JSON.parse(c.options.body));
    assert.equal(submits.length,2);assert.notEqual(submits[0].request_id,submits[1].request_id);
    assert.equal(submits[0].question,submits[1].question);
});
