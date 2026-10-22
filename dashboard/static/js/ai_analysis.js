(() => {
  'use strict';
  const $=id=>document.getElementById(id),risks={critical:'极高危',high:'高危',medium:'中风险',low:'低风险',unknown:'证据不足'};
  const states={queued:'排队中',running:'分析中',completed:'已完成',fallback:'未完成，可重试',cancelled:'已取消'};
  const reasons={capacity_limit:'等待模型容量',priority_wait:'等待交互',circuit_open:'等待服务恢复',waiting_recovery:'升级后等待恢复',invalid_model_output:'回答校验未通过',model_output_truncated:'回答被截断',deadline_exceeded:'等待超时',model_unavailable:'模型连接失败',disabled:'AI 已关闭',manual_retry:'手动重新分析',worker_interrupted:'处理进程中断',gateway_auth_failed:'共享服务令牌无效',gateway_queue_full:'共享队列已满',gateway_client_pending:'本成员待处理任务已满',gateway_client_budget:'本成员调用额度已满',gateway_timeout:'共享服务等待超时',gateway_worker_interrupted:'共享服务处理进程中断',gateway_cancelled:'共享任务已取消'};
  let busy=false,selected='',detailVersion='',discussion='',before='',nextBefore='',page=1,paused=false,task='',chatBusy=false;
  let caseContext='',evidenceContext='';const cards=new Map();let conversation=sessionStorage.getItem('aiAnalystConversation')||crypto.randomUUID().replaceAll('-','');
  sessionStorage.setItem('aiAnalystConversation',conversation);
  async function api(url,data,timeout=12000){const c=new AbortController(),timer=setTimeout(()=>c.abort(),timeout);try{
    const response=await fetch(url,{method:data?'POST':'GET',credentials:'same-origin',signal:c.signal,
      headers:data?{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name="csrf-token"]').content}:{},body:data?JSON.stringify(data):undefined});
    const body=await response.json();if(!response.ok||body.code!==0)throw new Error(body.msg||'请求未完成');return body.data;
  }finally{clearTimeout(timer);}}
  function add(tag,text,parent,cls=''){const e=document.createElement(tag);e.textContent=text;if(cls)e.className=cls;parent?.append(e);return e;}
  function badge(risk,parent,status='completed'){return add('span',status==='completed'?(risks[risk]||'证据不足'):(states[status]||status),parent,'risk '+(status==='completed'?'risk-'+(risk||'unknown'):'state-'+status));}
  const date=value=>new Date(value*1000).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false});
  function evidence(items,records,parent){const m=new Map((records||[]).map(r=>[r.id,r]));for(const item of items||[]){const r=m.get(item.id);if(!r)continue;
    const box=add('div','',parent,'evidence-item');add('small',`${r.timestamp} · ${r.src_ip} · ${r.locator}`,box);badge(r.rule_level,box);add('small','原规则分级，与 AI 判断分开',box);add('blockquote',item.quote,box);}}
  async function detail(id,force=false){try{selected=id;const row=await api('/api/ai/analysis/'+id);if(selected!==id)return;const version=id+'|'+row.updated_at+'|'+(row.reviews||[]).length;
    if(!force&&detailVersion===version)return;detailVersion=version;$('reportDetail').hidden=false;$('reviewPanel').hidden=row.status!=='completed';
    const r=row.result,records=row.context.records||[];$('title').textContent=r.title||states[row.status];$('riskBadge').replaceChildren();badge(r.risk,$('riskBadge'),row.status);
    $('createCase').disabled=row.status!=='completed';$('exportReport').hidden=row.status!=='completed';$('exportReport').href='/api/ai/analysis/'+id+'/export';$('retryReport').disabled=['queued','running'].includes(row.status);
    $('scope').textContent=`${row.context.scope||'证据快照'} · 本批 ${records.length} 条记录 · 来源 ${[...new Set(records.map(v=>v.src_ip))].join('、')} · ${date(row.created_at)} · 调用 ${row.call_id||'尚无'}`;
    for(const [target,value] of [['summary',r.summary||reasons[row.reason]||states[row.status]],['intent',r.intent||'尚无有效 AI 结论'],['riskReason',r.risk_reason||'尚无有效 AI 结论'],['limitations',r.limitations||'本任务未完成；规则分级不会代替 AI 判断。']])$(target).textContent=value;
    if(r.coverage)$('scope').textContent+=` · 模型实际 ${r.coverage.selected}/${r.coverage.batch_records} 条代表片段 · 未覆盖线索 ${(r.coverage.omitted_hints||[]).join('、')||'无'}`;
    $('timeline').replaceChildren();for(const v of r.timeline||[])add('li',v.description,$('timeline'));
    $('recommendations').replaceChildren();for(const v of r.recommendations||[])add('li',v,$('recommendations'));
    $('evidence').replaceChildren();evidence(r.evidence,records,$('evidence'));
    $('records').textContent=records.map(v=>`${v.locator} · ${v.timestamp} · ${v.src_ip}\n${v.excerpt}`).join('\n\n');
    $('reviews').replaceChildren();for(const v of row.reviews||[])add('div',`${date(v.created_at)} · ${({agree:'认可',false_positive:'可能误报',missed:'可能漏报',needs_review:'待复核'})[v.verdict]} · 人工 ${risks[v.human_risk]}\n${v.note}`,$('reviews'),'review-entry');
  }catch(e){$('notice').textContent=e.message;}}
  function renderCards(rows){const seen=new Set();for(const [index,row] of rows.entries()){seen.add(row.id);const signature=row.updated_at+'|'+row.status;
    let entry=cards.get(row.id);if(!entry){const button=add('button','',null,'report-card');button.addEventListener('click',async()=>{await detail(row.id);$('reportDetail').scrollIntoView({behavior:'smooth',block:'start'});});entry={button,signature:''};cards.set(row.id,entry);}
    if(entry.signature!==signature){entry.signature=signature;entry.button.replaceChildren();badge(row.result.risk,entry.button,row.status);add('strong',row.result.title||states[row.status],entry.button);add('p',row.result.summary||reasons[row.reason]||states[row.status],entry.button);add('small',`${date(row.created_at)} · ${row.record_count??row.context.selected} 条 · ${row.src_ip||''}`,entry.button);}
    const current=$('reports').children[index];if(current!==entry.button)$('reports').insertBefore(entry.button,current||null);
  }for(const [id,entry] of cards)if(!seen.has(id)){entry.button.remove();cards.delete(id);}
  if(!rows.length){if(!$('reports').querySelector('.empty-list'))add('p','暂无符合筛选的报告。',$('reports'),'empty-list');}else $('reports').querySelector('.empty-list')?.remove();}
  async function refresh(){if(busy)return;busy=true;try{const params=new URLSearchParams({limit:'12',risk:$('riskFilter').value,state:$('stateFilter').value,before});const data=await api('/api/ai/analysis?'+params);
    $('indexed').textContent=data.indexed;$('coverage').textContent=`已分配 ${data.assigned} · 待分配 ${data.unassigned} · 待索引 ${data.scan.lag||0}`;
    $('high').textContent=`${data.risks.critical||0} / ${data.risks.high||0}`;$('medium').textContent=`${data.risks.medium||0} / ${data.risks.low||0}`;$('waiting').textContent=(data.states.queued||0)+(data.states.running||0);$('unknown').textContent=`证据不足 ${data.risks.unknown||0} · 未完成 ${data.states.fallback||0}`;
    paused=data.background_paused_until>Date.now()/1000;$('mode').textContent=paused?'恢复后台分析':'交互演示模式';const cool=data.model_state?.circuit_open_until>Date.now()/1000;
    $('notice').textContent=cool?`模型连接故障，队列保留；约 ${Math.ceil(data.model_state.circuit_open_until-Date.now()/1000)} 秒后尝试，或点击“检查模型并恢复”。`:paused?'后台 AI 暂缓；规则、索引和问答继续。':!data.enabled?'AI 已关闭，历史结果保留。':data.scan.scan_error?'部分来源读取失败，请查看进度。':`自动分析已开启 · 当前模型任务 ${data.model_state?.active||0} · 引用原文由程序附上。`;
    renderCards(data.reports);nextBefore=data.next_before||'';$('older').disabled=!nextBefore;$('pageInfo').textContent=`第 ${page} 页 · 每页最多12份`;
    $('scanState').textContent=(data.scan.sources||[]).map(s=>s.error?`${s.name||s.source}：读取失败`:`${s.name} · 剩余请求 ${s.remaining.raw_request}／事件 ${s.remaining.event_log}`).join('\n')||'等待扫描';
    if(selected){const row=data.reports.find(v=>v.id===selected);if(row&&(!detailVersion.startsWith(selected+'|'+row.updated_at+'|')))await detail(selected);}
  }catch(e){$('notice').textContent=e.name==='AbortError'?'读取超时，稍后自动重试。':e.message;}finally{busy=false;}}
  function message(text,kind){return add('div',text,$('messages'),'message message-'+kind);}
  function answer(row,box){box.replaceChildren();if(row.status==='completed'){add('div',row.result.answer,box);add('small',row.task==='general_chat'?'普通本地聊天 · 没有读取日志':`提供 ${row.context.selected||row.context.records?.length||0} 条检索片段 · 调用 ${row.call_id}`,box);evidence(row.result.evidence,row.context.records,box);add('small',row.result.limitations,box);if(row.result.coverage)add('small',`实际模型片段 ${row.result.coverage.selected}/${row.result.coverage.batch_records} · 未覆盖线索 ${(row.result.coverage.omitted_hints||[]).join('、')||'无'}`,box);}else{box.textContent=(row.status==='cancelled'?'已取消接收答案。':'未完成：')+(reasons[row.reason]||row.reason||'');box.classList.add('message-error');}}
  async function poll(id,box){chatBusy=true;task=id;$('send').disabled=true;$('cancelChat').hidden=false;sessionStorage.setItem('aiAnalystPending',id);const started=Date.now();
    try{for(let i=0;i<150&&task===id;i++){const row=await api('/api/ai/chat/'+id);if(['completed','fallback','cancelled'].includes(row.status)){answer(row,box);$('chatStatus').textContent=row.status==='completed'?'回答已完成。':'任务未完成，可检查原因或重试。';return;}
      $('chatStatus').textContent=`${states[row.status]} · 已等待 ${Math.floor((Date.now()-started)/1000)} 秒 · 任务保留，无需重复发送。`;await new Promise(r=>setTimeout(r,2000));}
      box.textContent='任务仍在后台保留。刷新页面可继续查看；没有把超时等待当成已完成。';
    }catch(e){box.textContent=e.message;}finally{chatBusy=false;task='';$('send').disabled=false;$('cancelChat').hidden=true;sessionStorage.removeItem('aiAnalystPending');}}
  async function restore(){try{const rows=await api('/api/ai/chat/history?conversation='+conversation);if(rows.length)$('messages').replaceChildren();let pending=null;
    for(const row of rows){message(row.question,'user');const box=message('等待模型…','ai');if(['completed','fallback','cancelled'].includes(row.status))answer(row,box);else pending={row,box};}
    if(pending)poll(pending.row.id,pending.box);
  }catch(e){$('chatStatus').textContent='历史暂不可用：'+e.message;}}
  $('chatForm').addEventListener('submit',async e=>{e.preventDefault();if(chatBusy)return;const question=$('question').value.trim();if(!question)return;chatBusy=true;$('send').disabled=true;document.querySelector('.chat-empty')?.remove();message(question,'user');const box=message('正在提交…','ai');
    try{const job=await api('/api/ai/chat',{question,conversation,mode:$('chatMode').value,report_id:$('chatMode').value==='logs'?discussion:'',case_id:$('chatMode').value==='logs'?caseContext:'',evidence_id:$('chatMode').value==='logs'?evidenceContext:'',src_ip:$('chatIp').value.trim(),term:$('chatTerm').value.trim()});$('question').value='';await poll(job.id,box);}catch(error){box.textContent=error.message;chatBusy=false;$('send').disabled=false;}});
  $('cancelChat').addEventListener('click',async()=>{if(!task)return;try{await api('/api/ai/chat/'+task+'/cancel',{});$('chatStatus').textContent='已取消接收；正在进行的模型推理会自然结束。';}catch(e){$('chatStatus').textContent=e.message;}});
  $('newChat').addEventListener('click',()=>{if(chatBusy){$('chatStatus').textContent='请先取消或等待当前问题。';return;}conversation=crypto.randomUUID().replaceAll('-','');sessionStorage.setItem('aiAnalystConversation',conversation);$('messages').replaceChildren();});
  $('discuss').addEventListener('click',()=>{evidenceContext='';caseContext='';discussion=selected;$('chatMode').value='logs';$('chatIp').disabled=true;$('chatTerm').disabled=true;$('discussion').textContent='当前讨论已选择的报告及其证据。';$('clearDiscussion').hidden=false;$('chatSection').scrollIntoView({behavior:'smooth'});$('question').focus({preventScroll:true});});
  $('clearDiscussion').addEventListener('click',()=>{discussion='';caseContext='';evidenceContext='';$('chatIp').disabled=$('chatMode').value==='general';$('chatTerm').disabled=$('chatMode').value==='general';$('discussion').textContent='当前使用 IP／关键词检索。';$('clearDiscussion').hidden=true;});
  $('chatMode').addEventListener('change',()=>{sessionStorage.setItem('aiAnalystMode',$('chatMode').value);$('discussion').textContent=$('chatMode').value==='general'?'普通聊天不使用报告上下文。':evidenceContext?'当前讨论关联图证据。':caseContext?'当前讨论调查证据快照。':discussion?'当前讨论已选报告。':'当前使用 IP／关键词检索。';$('clearDiscussion').hidden=$('chatMode').value==='general'||!(discussion||caseContext||evidenceContext);$('chatIp').disabled=$('chatMode').value==='general'||!!(discussion||caseContext||evidenceContext);$('chatTerm').disabled=$('chatMode').value==='general'||!!(discussion||caseContext||evidenceContext);$('chatStatus').textContent=$('chatMode').value==='general'?'普通本地聊天，不读取蜜罐日志、不联网。':'日志模式只针对检索到的证据分析。';});
  document.querySelectorAll('[data-question]').forEach(b=>b.addEventListener('click',()=>{$('question').value=b.dataset.question;$('question').focus();}));
  $('scan').addEventListener('click',async()=>{$('scan').disabled=true;try{await api('/api/ai/analysis/scan',{});await refresh();}catch(e){$('notice').textContent=e.message;}finally{$('scan').disabled=false;}});
  $('mode').addEventListener('click',async()=>{try{const r=await api('/api/ai/analysis/mode',{mode:paused?'automatic':'interactive'});paused=r.pause_until>Date.now()/1000;$('mode').textContent=paused?'恢复后台分析':'交互演示模式';await refresh();}catch(e){$('notice').textContent=e.message;}});
  $('recover').addEventListener('click',async()=>{$('recover').disabled=true;$('notice').textContent='正在进行真实连接验收；成功后才清除连接故障冷却。';try{const r=await api('/api/ai/recover',{},40000);$('notice').textContent=r.status==='success'?'模型实际回答成功，已恢复。':'恢复未成功：'+(reasons[r.reason]||r.reason);}catch(e){$('notice').textContent=e.message;}finally{$('recover').disabled=false;}});
  $('retryReport').addEventListener('click',async()=>{try{await api('/api/ai/analysis/'+selected+'/retry',{});detailVersion='';await detail(selected,true);refresh();}catch(e){$('notice').textContent=e.message;}});
  $('createCase').addEventListener('click',()=>{if(selected)location.href='/ai/investigations?report='+selected;});
  $('closeDetail').addEventListener('click',()=>{selected='';$('reportDetail').hidden=true;$('reviewPanel').hidden=true;});
  $('saveReview').addEventListener('click',async()=>{try{await api('/api/ai/analysis/'+selected+'/review',{verdict:$('reviewVerdict').value,risk:$('reviewRisk').value,note:$('reviewNote').value});await detail(selected,true);}catch(e){$('notice').textContent=e.message;}});
  $('archives').addEventListener('click',async()=>{try{const rows=await api('/api/ai/archives');$('archiveList').replaceChildren();for(const r of rows){const link=add('a',r.name+' · '+Math.round(r.bytes/1024)+' KB',$('archiveList'));link.href='/api/ai/archives/'+encodeURIComponent(r.name);link.style.display='block';}if(!rows.length)add('p','尚无历史分析档案。',$('archiveList'));}catch(e){$('notice').textContent=e.message;}});
  function resetPage(){before='';page=1;refresh();}
  $('latest').addEventListener('click',resetPage);$('older').addEventListener('click',()=>{if(nextBefore){before=nextBefore;page++;refresh();}});$('riskFilter').addEventListener('change',resetPage);$('stateFilter').addEventListener('change',resetPage);
  const storedMode=sessionStorage.getItem('aiAnalystMode');if(storedMode==='general'){$('chatMode').value='general';$('chatIp').disabled=true;$('chatTerm').disabled=true;$('discussion').textContent='普通聊天不使用报告上下文。';}setInterval(()=>{if(!document.hidden)refresh();},6000);refresh();restore();const params=new URLSearchParams(location.search),id=params.get('report'),caseId=params.get('case'),ip=params.get('ip'),evidenceId=params.get('evidence');
  if(ip)$('chatIp').value=ip;
  if(evidenceId&&/^[a-f0-9]{24}$/.test(evidenceId)){api('/api/team/evidence/'+evidenceId).then(row=>{evidenceContext=evidenceId;caseContext='';discussion='';$('chatMode').value='logs';$('chatIp').disabled=true;$('chatTerm').disabled=true;$('discussion').textContent='当前讨论关联图证据：'+row.locator+' · '+row.timestamp;$('clearDiscussion').hidden=false;}).catch(e=>$('chatStatus').textContent=e.message);}
  else if(caseId&&/^[a-f0-9]{24}$/.test(caseId)){api('/api/ai/investigations/'+caseId).then(row=>{caseContext=caseId;discussion='';$('chatMode').value='logs';$('chatIp').disabled=true;$('chatTerm').disabled=true;$('discussion').textContent='当前讨论调查：'+row.title+' · 使用服务器保存的证据快照。';$('clearDiscussion').hidden=false;$('chatStatus').textContent='调查模式从快照选择最多24条记录，模型使用最多6条代表证据。';}).catch(e=>$('chatStatus').textContent=e.message);}
  else if(id&&/^[a-f0-9]{24}$/.test(id))detail(id,true).then(()=>$('reportDetail').scrollIntoView());
})();
