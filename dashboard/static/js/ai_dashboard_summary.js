(() => {
  'use strict';const box=document.getElementById('aiRiskSummary');if(!box)return;let busy=false;
  async function refresh(){if(busy)return;busy=true;const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),7000);
    try{const response=await fetch('/api/ai/analysis',{credentials:'same-origin',signal:controller.signal});const body=await response.json();if(!response.ok||body.code!==0)throw new Error();
      box.replaceChildren();for(const [key,label,color] of [['critical','极高危','#ff858c'],['high','高危','#ffb27c'],['medium','中风险','#f0d580'],['low','低风险','#81ddbc']]){
        const span=document.createElement('span');span.textContent=label+' '+(body.data.risks[key]||0)+'  ';span.style.color=color;box.append(span);
      }const small=document.createElement('div');small.textContent=`AI 报告分布 · 已索引 ${body.data.indexed} 条证据 · 不等于成功入侵次数`;small.style.marginTop='6px';box.append(small);
    }catch(error){box.textContent='AI 分析暂不可用；原规则继续处理。';}finally{clearTimeout(timer);busy=false;}}
  refresh();setInterval(()=>{if(!document.hidden)refresh();},10000);
})();
