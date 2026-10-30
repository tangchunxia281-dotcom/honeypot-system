/* Optional capabilities reuse the five-entry workspace and its scoped evidence. */
window.MijiIntegrations=function(ctx){
 'use strict';
 const {api,node,button,link,info,run,url,getScope,getSection}=ctx,$=id=>document.getElementById(id);
 let ticket=0,targetRevision=0;
 const levels={low:'低风险',medium:'中风险',high:'高风险',critical:'极高风险'},states={watching:'持续关注',reviewing:'复核中',handled:'已处理'};
 const valid=t=>t===ticket;
 async function openTarget(row={}){
  if(row.ip&&!row.revision){const existing=await api('/api/integrations/targets?q='+encodeURIComponent(row.ip));row=existing.records.find(r=>r.ip===row.ip)||row;}
  targetRevision=row.revision||0;$('targetIp').value=row.ip||'';$('targetIp').readOnly=!!row.revision;
  $('targetLevel').value=row.level||'medium';$('targetStatus').value=row.status||'watching';
  $('targetTags').value=(row.tags||[]).join('，');$('targetNote').value=row.note||'';$('targetDialog').showModal();
 }
 function field(label,type,value){const l=node('label',label),input=node('input');input.type=type;if(type==='checkbox')input.checked=value;else input.value=value;l.append(input);return {label:l,input};}
 async function targets(t){
  const r=await api('/api/integrations/targets?q='+encodeURIComponent($('targetSearch').value));if(!valid(t))return;
  const box=$('targetList');box.replaceChildren();
  for(const row of r.records){
   const e=node('article',undefined,'target-row'),head=node('div',undefined,'section-title');
   head.append(node('h3',row.ip),node('span',levels[row.level]+' / '+states[row.status],'status-pill'));e.append(head);
   e.append(node('p',row.tags.join(' · ')||'尚无标签','muted'),node('p',row.note||'尚无核对备注'));
   const actions=node('div',undefined,'actions');actions.append(button('编辑档案',()=>openTarget(row),'quiet'),link('查看来源事件',url('events',{ip:row.ip},{tab:'records'})),link('查看来源会话',url('sessions',{ip:row.ip},{tab:'timeline'})),button('删除目标',async()=>{
    if(!confirm('删除 '+row.ip+' 的标签和备注？原始证据仍保留。'))return;
    await api('/api/integrations/targets/delete',{ip:row.ip,revision:row.revision});await render('targets');info('目标标签已删除，原始证据保留。');
   },'quiet'));e.append(actions);box.append(e);
  }
  if(!r.records.length)box.append(node('p','尚无匹配目标。可手动新增，或从当前范围的证据提取候选。','empty'));
 }
 async function services(t){
  const r=await api('/api/integrations/protocols');if(!valid(t))return;
  const box=$('servicesList');box.replaceChildren();
  for(const s of r.services){
   const e=node('div',undefined,'service-config');e.dataset.protocol=s.protocol;
   const head=node('div');head.append(node('h3',s.protocol.toUpperCase()),node('p',s.listening?'端口有监听':'端口未监听','muted'));
   const enabled=field('启用服务','checkbox',s.enabled);enabled.input.className='service-enabled';enabled.label.classList.add('check-row');
   const port=field('本机端口','number',s.port);port.input.min=1024;port.input.max=65535;port.input.className='service-port';
   e.append(head,enabled.label,port.label,node('span','127.0.0.1','muted'));box.append(e);
  }
 }
 async function classifier(t){
  const r=await api('/api/integrations/classifier');if(!valid(t))return;
  $('classifierUrl').value=r.url;$('classifierTimeout').value=r.timeout;$('classifierEnabled').checked=r.enabled;
  $('classifierState').replaceChildren(node('p',r.enabled?'分类已启用；未完成结果不当作正常输入。':'分类未启用；基础规则和大模型调查可独立使用。','status-line'),node('p',`已完成 ${r.counts.completed||0} / 失败 ${r.counts.failed||0} / 排队处理中 ${r.pending} / 容量或冷却跳过 ${r.skipped}`,'muted'));
  if(r.last_error)$('classifierState').append(node('p','最近异常：'+r.last_error+'；冷却剩余 '+r.cooldown_seconds+' 秒','muted'));
 }
 async function cloud(t){
  const r=await api('/api/integrations/cloud');if(!valid(t))return;const s=r.saved,isCloud=['deepseek','openai'].includes(s.provider);
  $('cloudProvider').value=isCloud?s.provider:'deepseek';$('cloudUrl').value=isCloud?s.base_url:'https://api.deepseek.com';$('cloudModel').value=isCloud?s.model:'deepseek-chat';$('cloudKey').value='';$('cloudConsent').checked=false;
  $('cloudState').replaceChildren(node('p',`当前运行：${r.running.provider} / ${r.running.model||'尚未指定模型'} / ${r.running.enabled?'AI启用':'AI关闭'}`,'status-line'),node('p',`已保存：${s.provider} / ${s.model||'尚未指定'}；云端密钥${s.key_configured?'已设置（不回显）':'未设置'}。保存与当前运行分别展示。`,'muted'));
 }
 async function render(tab){const t=++ticket;if(tab==='targets')await targets(t);else if(tab==='services')await services(t);else if(tab==='classifier')await classifier(t);else if(tab==='cloud')await cloud(t);if(valid(t)&&getSection()===tab)info(({targets:'来源复核档案已读取；候选按当前证据范围提取。',services:'服务设置已读取；端口监听与协议验收分别检查。',classifier:'分类设置与实际任务统计已读取。',cloud:'云端配置已读取；已保存配置与当前运行分别展示。'})[tab]);}
 function classification(box,r,score){
  if(!r)return;const e=node('section',undefined,'classification-result');e.append(node('h3','分类模型复核'));
  if(r.status==='completed'){
   const d=r.result;e.append(node('p',d.attack_type+' / '+(d.is_attack?'模型判断可疑':'模型未判为攻击')),
    node('p',`模型概率 ${Math.round(d.attack_prob*100)}% · 有效加分 ${d.effective_points} · 建议融合分 ${d.suggested_score}`,'muted'));
   if(d.reasons.length)e.append(node('p',d.reasons.join('；')));
   e.append(node('small','建议分仅用于人工复核；原规则分保留，不自动封禁。模型概率不等于实测准确率。'));
  }else e.append(node('p',r.status==='queued'?'等待分类结果':'分类未完成：'+r.reason));
  box.append(e);
 }
 if($('targetAdd'))$('targetAdd').onclick=()=>openTarget();
 if($('targetFind'))$('targetFind').onclick=()=>run(()=>render('targets'));
 if($('targetCancel'))$('targetCancel').onclick=()=>$('targetDialog').close();
 if($('targetForm'))$('targetForm').onsubmit=e=>{e.preventDefault();run(async()=>{
  await api('/api/integrations/targets',{ip:$('targetIp').value.trim(),level:$('targetLevel').value,status:$('targetStatus').value,note:$('targetNote').value,tags:$('targetTags').value.split(/[,，]/).map(t=>t.trim()).filter(Boolean),revision:targetRevision});
  $('targetDialog').close();if(getSection()==='targets')await render('targets');info('来源复核档案已保存。');
 })};
 if($('targetSuggest'))$('targetSuggest').onclick=()=>run(async()=>{
  const r=await api('/api/integrations/targets/suggest?'+new URLSearchParams(getScope()));if(getSection()!=='targets')return;
  const box=$('targetCandidates');box.replaceChildren(node('p',`当前范围最近 ${r.sampled} / ${r.total} 条证据中的候选；点击后确认并保存。`,'muted'));
  for(const row of r.records)box.append(button(`${row.ip} / ${row.count}条可疑线索 / ${row.channels.join('、')}`,()=>openTarget({ip:row.ip,note:'从当前范围证据提取，待人工核对。'}),'quiet'));
  if(!r.records.length)box.append(node('p','当前样本没有中风险及以上的来源候选。'));
 });
 if($('servicesRefresh'))$('servicesRefresh').onclick=()=>run(()=>render('services'));
 if($('servicesSave'))$('servicesSave').onclick=()=>run(async()=>{
  const services=[...$('servicesList').children].map(e=>({protocol:e.dataset.protocol,enabled:e.querySelector('.service-enabled').checked,host:'127.0.0.1',port:Number(e.querySelector('.service-port').value)}));
  await api('/api/integrations/protocols',{services});info('服务设置已保存。请在启动窗口停止并重启全部服务后生效。');
 });
 if($('classifierSave'))$('classifierSave').onclick=()=>run(async()=>{
  await api('/api/integrations/classifier',{enabled:$('classifierEnabled').checked,url:$('classifierUrl').value.trim(),timeout:Number($('classifierTimeout').value)});
  await render('classifier');info('分类设置已保存；仅后续新请求参与复核，排队任务沿用提交时配置。');
 });
 async function saveCloud(enabled){
  await api('/api/integrations/cloud',{provider:$('cloudProvider').value,base_url:$('cloudUrl').value.trim(),model:$('cloudModel').value.trim(),api_key:$('cloudKey').value,enabled,consent:$('cloudConsent').checked});
  $('cloudKey').value='';await render('cloud');info('云端配置已保存。请重启全部服务，当前运行模型尚未切换。');
 }
 if($('cloudSave'))$('cloudSave').onclick=()=>run(()=>saveCloud(true));
 if($('cloudDisable'))$('cloudDisable').onclick=()=>run(()=>saveCloud(false));
 if($('cloudProbe'))$('cloudProbe').onclick=()=>run(async()=>{
  if(!confirm('向当前运行模型发送一次固定连接测试？不附带蜜罐证据；云端服务可能收取调用费用。'))return;
  $('cloudProbe').disabled=true;try{
   $('cloudProbeResult').textContent='正在实际调用当前运行模型…';
   const r=await api('/api/integrations/cloud/probe',{confirm:true},45000);
   $('cloudProbeResult').replaceChildren(node('p',`${r.provider} / ${r.model} / ${r.status==='success'?'实际调用成功':'未取得有效回答'} / ${r.latency_ms} ms`),node('p',r.status==='success'?r.reply:r.reason,'muted'));
  }finally{$('cloudProbe').disabled=false;}
 });
 return {render,classification};
};
