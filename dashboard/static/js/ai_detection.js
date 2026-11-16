(() => {
  'use strict';
  const $=id=>document.getElementById(id);
  const types={xss:'XSS',sqli:'SQL 注入',path_traversal:'目录穿越',command_injection:'命令注入',ssrf:'SSRF',ssti:'模板注入',xxe:'XXE',scanner:'扫描工具特征',other:'其他可疑行为'};
  const verdicts={suspicious:'疑似攻击',no_clear_attack:'可见片段未发现明确攻击',uncertain:'不确定'};
  const states={queued:'等待分析',running:'正在分析',completed:'已完成',fallback:'分析未完成',skipped:'未进入分析'};
  const reasons={queue_full:'队列已满',source_budget:'来源额度已满',session_budget:'模型调用预算已满',capacity_limit:'模型忙',
    model_unavailable:'模型服务不可用',deadline_exceeded:'模型超时',invalid_model_output:'输出格式或证据无效',
    circuit_open:'连续故障，暂时回退',worker_interrupted:'工作任务中断',disabled:'AI 已关闭',configuration_invalid:'配置无效'};
  const date=v=>new Date(v*1000).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false});
  let busy=false,selected='';
  async function api(path,post=false){
    const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),8000);
    try{
      const response=await fetch(path,{method:post?'POST':'GET',credentials:'same-origin',signal:controller.signal,
        headers:post?{'X-CSRF-Token':document.querySelector('meta[name="csrf-token"]').content}:{}});
      const body=await response.json();if(!response.ok||body.code!==0)throw new Error(body.msg||'请求失败');return body.data;
    }finally{clearTimeout(timer);}
  }
  function cell(row,text,detail=''){
    const td=document.createElement('td');td.textContent=text;
    if(detail){const small=document.createElement('small');small.textContent=detail;td.appendChild(small);}row.appendChild(td);return td;
  }
  async function detail(id){
    try{
      const row=await api('/api/ai/detections/'+id);selected=id;$('detail').hidden=false;
      $('detailMeta').textContent=`来源 ${row.src_ip} · 会话 ${row.session_id} · 原请求 raw_request:${row.raw_request_id} · ${row.status==='queued'||row.status==='running'?'上次已结束调用':'调用'} ${row.call_id||'尚无'}${row.rule_ai_disagreement?' · 规则与 AI 意见不同':''}`;
      $('summary').textContent=row.result.summary||reasons[row.reason]||states[row.status];
      $('evidence').replaceChildren();
      for(const item of row.result.evidence||[]){const li=document.createElement('li');li.textContent=`字段 ${item.field}：${item.quote}`;$('evidence').appendChild(li);}
      $('requestFields').textContent=JSON.stringify(row.snapshot,null,2);
      $('retry').disabled=row.status==='queued'||row.status==='running';
    }catch(error){$('notice').textContent='读取详情失败：'+error.message;}
  }
  async function refresh(){
    if(busy)return;busy=true;
    try{
      const data=await api('/api/ai/detections?limit=50&src_ip='+encodeURIComponent($('sourceIp').value.trim()));
      const p=data.policy;
      $('policy').textContent=`研判${p.enabled&&p.detection_enabled?'已开启':'已关闭'} · 有参数／请求体及规则可疑请求自动提交；其他约 1/${p.normal_sample_every} 按记录摘要抽样 · 每来源每小时额度 ${p.detection_per_ip_hour} · 队列上限 ${p.detection_queue_max}`;
      $('counts').textContent=`保留历史：已完成 ${data.counts.completed||0}，等待 ${data.counts.queued||0}，处理中 ${data.counts.running||0}，未完成 ${data.counts.fallback||0}，未进入 ${data.counts.skipped||0}。`;
      $('rows').replaceChildren();
      for(const row of data.records){
        const tr=document.createElement('tr');cell(tr,date(row.created_at),row.src_ip);
        cell(tr,row.snapshot.fields.method+' '+row.snapshot.fields.path,'raw_request:'+row.raw_request_id);
        const level=cell(tr,({critical:'规则极高危',high:'规则高危',medium:'规则中风险',low:'规则低风险'})[row.rule_level]||'规则分级未知','分数 '+row.snapshot.rule_score);
        level.className='risk-'+(row.rule_level||'unknown');
        const description=row.status==='completed'?(verdicts[row.verdict]+' '+(row.result.attack_types||[]).map(t=>types[t]||t).join('、')):states[row.status];
        cell(tr,description,row.rule_ai_disagreement?'规则与 AI 意见不同':reasons[row.reason]||row.reason);
        const button=document.createElement('button');button.type='button';button.textContent='证据详情';button.addEventListener('click',()=>detail(row.id));
        const td=cell(tr,'');td.appendChild(button);$('rows').appendChild(tr);
      }
      if(!data.records.length){const tr=document.createElement('tr');cell(tr,'暂无研判记录。产生测试请求，或提交最近已保存请求。').colSpan=5;$('rows').appendChild(tr);}
      $('notice').textContent='对照记录已更新；AI 结果未用于自动封禁或更改原规则分数。';
      if(selected)await detail(selected);
    }catch(error){$('notice').textContent='读取失败：'+(error.name==='AbortError'?'请求超时':error.message);}
    finally{busy=false;}
  }
  $('refresh').addEventListener('click',refresh);
  $('sourceIp').addEventListener('change',refresh);
  $('recent').addEventListener('click',async()=>{
    $('recent').disabled=true;
    try{const data=await api('/api/ai/analyze-recent',true);$('notice').textContent=`已检查最近 ${data.outcomes.length} 条原请求，任务按额度处理。`;await refresh();}
    catch(error){$('notice').textContent=error.message;}finally{$('recent').disabled=false;}
  });
  $('retry').addEventListener('click',async()=>{
    if(!selected)return;$('retry').disabled=true;
    try{await api('/api/ai/detections/'+selected+'/retry',true);await refresh();}
    catch(error){$('notice').textContent=error.message;$('retry').disabled=false;}
  });
  setInterval(()=>{if(!document.hidden)refresh();},5000);refresh();
})();
