(() => {
  'use strict';
  const $=id=>document.getElementById(id);
  const sources={model:'AI 选择',program:'预设逻辑',fallback:'备用处理',pending:'等待决策'};
  const strategies={virtual_command:'虚拟命令',not_found:'命令未安装',unavailable:'组件不可用',permission_denied:'权限拒绝',profile_summary:'虚拟主机概览',preview_pending:'预览任务',format_error:'格式错误',service_busy:'服务繁忙',job_lookup:'任务查询'};
  const reasons={deadline_exceeded:'模型等待超时',model_unavailable:'模型服务不可用',invalid_model_output:'策略格式无效',rate_limit:'调用过于频繁',session_budget:'会话预算用完',source_budget:'来源预算用完',capacity_limit:'模型额度已满',circuit_open:'模型故障冷却',disabled:'模型已关闭',policy_restricted:'输入超出策略范围',audit_storage_unavailable:'审计保存失败',worker_interrupted:'交互任务中断'};
  let busy=false;
  function cell(row,text,detail='') {
    const td=document.createElement('td');td.textContent=text;
    if(detail){const small=document.createElement('small');small.textContent=detail;td.append(small);}row.append(td);return td;
  }
  async function refresh() {
    if(busy)return;busy=true;
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),8000);
    try {
      const sid=$('sessionId').value.trim(),channel=$('channel').value;
      if(sid&&!/^[a-f0-9]{32}$/.test(sid))throw new Error('请输入正确的 32 位会话编号');
      const response=await fetch('/api/ai/interactions?'+new URLSearchParams({limit:sid?'100':'50',session_id:sid,channel}),{credentials:'same-origin',signal:controller.signal});
      const body=await response.json();if(!response.ok||body.code!==0)throw new Error(body.msg||'读取失败');
      const data=body.data;
      $('modelCount').textContent=data.counts.model||0;$('programCount').textContent=data.counts.program||0;$('fallbackCount').textContent=data.counts.fallback||0;
      $('turns').replaceChildren();
      const records=sid?[...data.records].sort((a,b)=>a.step-b.step):data.records;
      for(const item of records) {
        const tr=document.createElement('tr');
        cell(tr,new Date(item.created_at*1000).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}),item.session_id);
        cell(tr,item.channel.toUpperCase()+' · #'+item.step,item.status==='running'?'等待完成':item.src_ip);
        cell(tr,sources[item.source]||item.source,(strategies[item.strategy]||item.strategy)+' '+(reasons[item.reason]||item.reason));
        cell(tr,item.input_preview+'\n→ '+(item.output_preview||(item.status==='running'?'等待回应…':'（无文本输出，操作已完成）')));
        const state=[];
        if(item.state.cwd)state.push('虚拟目录：'+item.state.cwd);
        if(item.state.job_id)state.push('任务编号：'+item.state.job_id);
        if(item.state.job_status)state.push('任务状态：'+({queued:'排队中',ready:'已就绪'}[item.state.job_status]||item.state.job_status));
        cell(tr,state.join('\n')||'无状态变化',item.call_id?'调用 '+item.call_id:'未调用模型');
        const button=document.createElement('button');button.textContent='回放此会话';button.addEventListener('click',()=>{$('sessionId').value=item.session_id;refresh();});cell(tr,'').append(button);
        $('turns').append(tr);
      }
      if(!records.length){const tr=document.createElement('tr');cell(tr,'暂无交互记录。通过 SSH 或 Web 预览诱饵进行测试。').colSpan=6;$('turns').append(tr);}
      $('notice').textContent=(sid?'正在回放单个会话。':'已读取最近真实交互。')+'统计范围随当前筛选变化；AI 标记仅代表实际成功调用。';
    } catch(error){$('notice').textContent=error.name==='AbortError'?'读取超时，请刷新。':error.message;}
    finally{clearTimeout(timer);busy=false;}
  }
  for(const id of ['refresh','filter'])$(id).addEventListener('click',refresh);
  $('clear').addEventListener('click',()=>{$('sessionId').value='';$('channel').value='';refresh();});
  setInterval(()=>{if(!document.hidden)refresh();},5000);refresh();
})();
