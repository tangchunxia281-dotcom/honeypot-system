(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const reasons = {disabled:'AI 已关闭',configuration_invalid:'模型地址或名称无效',model_unavailable:'模型服务不可用',
    model_http_error:'模型服务返回错误',invalid_model_output:'回复格式或证据无效',model_output_truncated:'模型输出被截断',priority_wait:'后台分析等待交互',deadline_exceeded:'等待超时',
    circuit_open:'连续故障，暂时回退',capacity_limit:'模型处理额度已满',session_budget:'会话调用预算已用完',
    rate_limit:'调用过于频繁',audit_storage_unavailable:'调用记录存储不可用',worker_unavailable:'模型任务启动失败',
    worker_interrupted:'任务中断',model_not_installed:'配置模型不在本机列表中',ready_for_call:'可发送调用'};
  const date = value => value ? new Date(value * 1000).toLocaleString('zh-CN', {timeZone:'Asia/Shanghai',hour12:false}) : '尚无记录';
  let refreshing = false;
  function readable(item) {
    try {
      const value=JSON.parse(item.response_preview);
      if(value.strategy)return 'AI 选择策略：'+({preview_pending:'创建模拟预览任务',format_error:'回应格式错误',service_busy:'模拟服务繁忙',profile_summary:'显示虚拟主机概览',not_found:'命令未安装',unavailable:'组件不可用',permission_denied:'权限拒绝'}[value.strategy]||value.strategy);
      if(value.summary)return value.summary;
      if(value.answer)return value.answer;
    }catch(error){if(['log_report','log_chat','web_detect','web_reply','ssh_reply'].includes(item.task))return '结构化预览已限长，请在分析／研判／交互页面查看完整结果。';}
    return item.response_preview||'—';
  }
  async function api(path, options = {}, timeout = 7000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(path, {...options,credentials:'same-origin',signal:controller.signal,headers:{...options.headers}});
      const body = await response.json();
      if (!response.ok || body.code !== 0) throw new Error(body.msg || '请求未完成');
      return body.data;
    } finally { clearTimeout(timer); }
  }
  function cell(row, text, detail = '') {
    const td = document.createElement('td'); td.textContent = text;
    if (detail) { const small = document.createElement('small'); small.textContent = detail; td.appendChild(small); }
    row.appendChild(td); return td;
  }
  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      const data = await api('/api/ai/status');
      $('model').textContent = data.model || '未配置';
      $('config').textContent = `配置${data.enabled?'已开启':'已关闭'} · 超时 ${data.timeout} 秒 · 模型并发上限 ${data.concurrency}`;
      $('health').textContent = data.health.service_reachable ? (data.health.model_available ? '服务可连接，模型已安装' : '服务可连接，模型名称不匹配') : '服务暂不可用';
      $('loaded').textContent = `模型${data.health.model_loaded?'已加载':'尚未加载或已卸载'} · 检查时间 ${date(data.health.checked_at)}`;
      $('success').textContent = String(data.counts.success || 0);
      $('lastSuccess').textContent = '最近成功：' + date(data.last_success_at);
      $('fallback').textContent = String(data.counts.fallback || 0);
      $('active').textContent = `正在处理 ${data.active} 个任务${data.circuit_open_until > Date.now()/1000?' · 故障冷却中':''}`;
      $('notice').textContent = data.storage_available ? '运行状态已更新。服务连通与实际生成结果分别展示。' : '调用记录存储不可用；请检查数据目录。';
      $('calls').replaceChildren();
      for (const item of data.recent) {
        const row = document.createElement('tr');
        cell(row,date(item.created_at),item.id);
        cell(row,({probe:'连接验收',ssh_reply:'SSH 诱饵策略',web_detect:'HTTP 请求研判',web_reply:'Web 诱饵策略',log_report:'多条日志分析',log_chat:'日志证据问答',general_chat:'普通本地聊天'})[item.task] || item.task,item.session_id);
        const diagnostics={evidence_quote_mismatch:'引用未匹配证据原文',unsupported_success_claim:'包含无证据的成功利用声明',analyst_field_length_or_type:'回答字段超长或类型错误',schema_or_evidence_invalid:'字段格式或证据校验失败'};
        const status = cell(row,{success:'成功生成',fallback:'备用处理',running:'处理中'}[item.status] || item.status,(reasons[item.reason] || item.reason)+(item.validation_detail?' · '+(diagnostics[item.validation_detail]||item.validation_detail):''));
        status.className = item.status;
        cell(row,item.status==='running'?'等待中':item.latency_ms+' ms');
        const preview=cell(row,readable(item));
        if(item.response_preview){const details=document.createElement('details');const title=document.createElement('summary');title.textContent='技术数据';const pre=document.createElement('pre');pre.textContent=item.response_preview;details.append(title,pre);preview.append(details);}
        if(item.task==='log_report'){const link=document.createElement('a');link.textContent='查看分析报告';link.href='/ai/analysis?report='+encodeURIComponent(item.session_id);preview.append(link);}
        $('calls').appendChild(row);
      }
      if (!data.recent.length) { const row=document.createElement('tr'); const td=cell(row,'尚无实际调用。可发送连接验收，或测试未知 SSH 命令。');td.colSpan=5;$('calls').appendChild(row); }
    } catch (error) { $('notice').textContent = '读取状态失败：' + (error.name==='AbortError'?'请求超时':error.message); }
    finally { refreshing=false; }
  }
  $('refresh').addEventListener('click',refresh);
  $('probe').addEventListener('click',async () => {
    $('probe').disabled=true; $('probeMeta').textContent='正在进行一次真实模型调用；首次加载可能触发超时回退…';
    try {
      const data=await api('/api/ai/probe',{method:'POST',headers:{'X-CSRF-Token':document.querySelector('meta[name="csrf-token"]').content}},40000);
      $('probeMeta').textContent=`${data.status==='success'?'模型成功回答':'已使用备用处理'} · ${data.latency_ms} ms · 编号 ${data.call_id}`;
      $('probeReply').textContent=data.reply || reasons[data.reason] || data.reason || '未获得有效回复；蜜罐保留原有处理流程。';
      await refresh();
    } catch (error) { $('probeMeta').textContent='验收请求未完成：'+(error.name==='AbortError'?'页面等待超时，请查看调用记录':error.message); }
    finally { $('probe').disabled=false; }
  });
  setInterval(() => { if (!document.hidden) refresh(); },5000);
  refresh();
})();
