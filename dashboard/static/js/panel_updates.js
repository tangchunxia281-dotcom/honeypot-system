/* Stable panel updates, coalesced while the atlas is being dragged. */
(() => {
  'use strict';const pending=new Map(),signatures=new Map();let timer=0;
  function flush(){timer=0;if(document.hidden)return;if(_mapGestureActive){timer=setTimeout(flush,80);return;}const jobs=[...pending.values()];pending.clear();for(const job of jobs)job();}
  const targets=[['topList','updateTopList'],['suspiciousScroll','updateSuspiciousRequests'],['sessionScroll','updateSessionAnalysis'],['pieChart','updatePieChart']];
  for(const [id,name] of targets){const original=window[name];if(typeof original!=='function')continue;
    window[name]=function(value){const run=()=>{const rows=Array.isArray(value)?value:(value?.items||value?.data||[]);const locations=rows.map(r=>geoLocationCacheByIp[r.src_ip]||'');const signature=JSON.stringify([getDashboardWindowHours(),isDemoMode,value,locations]);const el=document.getElementById(id);if(signatures.get(id)===signature&&el?.childElementCount)return;original(value);signatures.set(id,signature);if(el)el.dataset.renderCount=String(Number(el.dataset.renderCount||0)+1);};
      if(_mapGestureActive||document.hidden){pending.set(id,run);if(!timer)timer=setTimeout(flush,80);}else run();};
  }
  document.addEventListener('visibilitychange',()=>{if(!document.hidden)flush();});
})();
