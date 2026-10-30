/* Cached atlas renderer. Country geometry is baked once, never per drag frame.
 * The small ECharts-compatible bridge keeps existing source/log focus behavior.
 */
(() => {
  'use strict';
  const W=2400, north=-Math.log(Math.tan(Math.PI/4+85*Math.PI/360)),
    south=-Math.log(Math.tan(Math.PI/4-60*Math.PI/360)), H=(south-north)*W/(2*Math.PI);
  const project=([lon,lat])=>[(Number(lon)+180)*W/360,(-Math.log(Math.tan(Math.PI/4+Math.max(-85,Math.min(85,Number(lat)))*Math.PI/360))-north)*W/(2*Math.PI)];
  class CachedWorldMap {
    constructor(container,geojson,names={}) {
      this.el=container;this.names=names;this.zoom=1.1;this.pan=[0,0];this.series=[];this.events=new Map();this.zrEvents=new Map();
      this.stats={frames:0,geometryPaints:0,lastFrameMs:0,maxFrameMs:0};this.drag=null;this.hover=null;this.point=null;this.effect=false;
      this.canvas=document.createElement('canvas');this.canvas.className='atlas-canvas';this.canvas.tabIndex=0;this.canvas.setAttribute('aria-label','世界地图，可拖动；方向键移动，加减键缩放，Home 重置');
      this.tip=document.createElement('div');this.tip.className='atlas-tooltip';this.tip.hidden=true;this.tip.setAttribute('role','tooltip');
      container.replaceChildren(this.canvas,this.tip);this.ctx=this.canvas.getContext('2d');
      this.countries=[];this.vertexCount=0;
      for(const f of geojson.features||[]) {
        const p=new Path2D(),bounds=[Infinity,Infinity,-Infinity,-Infinity];
        const polys=f.geometry?.type==='Polygon'?[f.geometry.coordinates]:f.geometry?.type==='MultiPolygon'?f.geometry.coordinates:[];
        for(const polygon of polys)for(const ring of polygon){let last=null;for(const ll of ring){const v=project(ll);this.vertexCount++;bounds[0]=Math.min(bounds[0],v[0]);bounds[1]=Math.min(bounds[1],v[1]);bounds[2]=Math.max(bounds[2],v[0]);bounds[3]=Math.max(bounds[3],v[1]);if(!last||Math.abs(v[0]-last[0])>W/2)p.moveTo(...v);else p.lineTo(...v);last=v;}p.closePath();}
        this.countries.push({name:f.properties?.name||f.name||'未知',path:p,bounds});
      }
      this.cache=document.createElement('canvas');this.cache.width=W;this.cache.height=Math.ceil(H);const c=this.cache.getContext('2d');
      c.fillStyle='#142e4f';c.strokeStyle='#389ee8';c.lineWidth=2.2;
      for(const country of this.countries){c.fill(country.path,'evenodd');c.stroke(country.path);}this.stats.geometryPaints++;
      this.bind();this.observer=new ResizeObserver(()=>this.resize());this.observer.observe(container);this.resize();
      document.addEventListener('visibilitychange',()=>{if(document.hidden){clearTimeout(this.pulseTimer);cancelAnimationFrame(this.raf);this.raf=0;}else this.schedule();});
      container.dataset.renderer='cached-canvas';container.dataset.countries=String(this.countries.length);container.dataset.vertices=String(this.vertexCount);
    }
    emit(name,event,zr=false){for(const fn of (zr?this.zrEvents:this.events).get(name)||[])fn(event);}
    bind(){const c=this.canvas;
      c.addEventListener('pointerdown',e=>{if(e.button!==0)return;c.setPointerCapture(e.pointerId);this.drag={id:e.pointerId,x:e.clientX,y:e.clientY};this.tip.hidden=true;this.hover=null;c.classList.add('dragging');this.emit('mousedown',e,true);});
      c.addEventListener('pointermove',e=>{const r=c.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;if(this.drag){this.pan[0]+=e.clientX-this.drag.x;this.pan[1]+=e.clientY-this.drag.y;this.drag.x=e.clientX;this.drag.y=e.clientY;this.emit('georoam',{zoom:this.zoom});}else{this.point=[x,y];}this.schedule();});
      const end=e=>{if(!this.drag)return;this.drag=null;c.classList.remove('dragging');this.emit('mouseup',e,true);this.schedule();};
      c.addEventListener('pointerup',end);c.addEventListener('pointercancel',end);c.addEventListener('lostpointercapture',end);
      c.addEventListener('pointerleave',()=>{if(!this.drag){this.point=null;this.hover=null;this.tip.hidden=true;this.emit('globalout',{},true);this.schedule();}});
      c.addEventListener('wheel',e=>{e.preventDefault();const r=c.getBoundingClientRect();this.scaleBy(Math.exp(-Math.max(-100,Math.min(100,e.deltaY))*.002),[e.clientX-r.left,e.clientY-r.top]);},{passive:false});
      c.addEventListener('keydown',e=>{const keys={ArrowLeft:[35,0],ArrowRight:[-35,0],ArrowUp:[0,35],ArrowDown:[0,-35]};if(keys[e.key]){e.preventDefault();this.pan=this.pan.map((v,i)=>v+keys[e.key][i]);this.emit('georoam',{});this.schedule();}else if(['+','=','-','Home'].includes(e.key)){e.preventDefault();if(e.key==='Home')this.reset();else this.scaleBy(e.key==='-'?.8:1.25);}});
    }
    scaleBy(factor,anchor=[this.width/2,this.height/2]){const z=Math.max(1.1,Math.min(10,this.zoom*factor)),ratio=z/this.zoom,center=[this.width/2,this.height/2];this.pan=this.pan.map((v,i)=>ratio*v+(anchor[i]-center[i])*(1-ratio));this.zoom=z;this.point=null;this.tip.hidden=true;this.emit('georoam',{zoom:z});this.schedule();}
    reset(){this.zoom=1.1;this.pan=[0,0];this.point=null;this.tip.hidden=true;this.emit('georoam',{zoom:this.zoom});this.schedule();}
    origin(){const s=this.base*this.zoom;return [(this.width-W*s)/2+this.pan[0],(this.height-H*s)/2+this.pan[1]];}
    screen(ll){const q=project(ll),o=this.origin(),s=this.base*this.zoom;return [o[0]+q[0]*s,o[1]+q[1]*s];}
    resize(){const r=this.el.getBoundingClientRect();this.width=Math.max(1,r.width);this.height=Math.max(1,r.height);this.dpr=Math.min(window.devicePixelRatio||1,1.5);this.canvas.width=Math.round(this.width*this.dpr);this.canvas.height=Math.round(this.height*this.dpr);this.base=Math.max(.001,Math.min((this.width-32)/W,(this.height-32)/H));this.schedule();}
    schedule(){if(!this.raf&&!document.hidden)this.raf=requestAnimationFrame(t=>{this.raf=0;this.draw(t);});}
    draw(t){const started=performance.now(),c=this.ctx,o=this.origin(),s=this.base*this.zoom;c.setTransform(this.dpr,0,0,this.dpr,0,0);c.clearRect(0,0,this.width,this.height);c.drawImage(this.cache,o[0],o[1],W*s,H*s);
      if(!this.drag&&this.point){const q=[(this.point[0]-o[0])/s,(this.point[1]-o[1])/s];this.hover=null;for(const country of this.countries){const b=country.bounds;if(q[0]>=b[0]&&q[0]<=b[2]&&q[1]>=b[1]&&q[1]<=b[3]&&this.cache.getContext('2d').isPointInPath(country.path,q[0],q[1],'evenodd')){this.hover=country;break;}}
        if(this.hover){c.save();c.translate(...o);c.scale(s,s);c.fillStyle='rgba(70,160,218,.24)';c.fill(this.hover.path,'evenodd');c.restore();}
      }
      let pointTip='';for(const series of this.series){if(series.id==='map_focus_points')continue;const line=series.type==='lines';for(const datum of series.data||[]){const color=datum.riskColor||({high:'#ff647c',medium:'#ffd06b',low:'#61d9b1'})[datum.riskLevel]||'#b6ecff';c.strokeStyle=color;c.fillStyle=color;c.lineWidth=1.25;
          if(line){const a=this.screen(datum.coords[0]),b=this.screen(datum.coords[1]);if(Math.hypot(a[0]-b[0],a[1]-b[1])<2)continue;const dx=b[0]-a[0],dy=b[1]-a[1];c.globalAlpha=series.id==='map_hover_line'?1:.4;c.beginPath();c.moveTo(...a);c.quadraticCurveTo((a[0]+b[0])/2-dy*.16,(a[1]+b[1])/2+dx*.16,...b);c.stroke();c.globalAlpha=1;continue;}
          const xy=this.screen(datum.value),server=series.id==='map_server',focus=series.id==='map_hover_point',radius=server?5:focus?7:Math.min(8,3+Math.log2(1+(datum.value[2]||0))*.7);c.fillStyle=server?'#fff1b4':color;c.beginPath();c.arc(...xy,radius,0,Math.PI*2);c.fill();
          if(server||focus){c.strokeStyle=server?'#ffd16d':color;c.globalAlpha=.55;c.beginPath();c.arc(...xy,radius+6+(this.effect&&!this.drag?(t/150)%10:0),0,Math.PI*2);c.stroke();c.globalAlpha=1;}
          if(server){c.font='12px Microsoft YaHei';c.fillText('本机',xy[0]+10,xy[1]+4);}
          if(!this.drag&&this.point&&Math.hypot(xy[0]-this.point[0],xy[1]-this.point[1])<radius+5)pointTip=server?`本机位置\n${datum.location||'未知'}`:`来源 ${datum.ip}\n${datum.location||'未知'} · ${datum.value[2]} 次\n次数颜色只表示相对活跃度；调查页查看风险`;
      }}
      if(!this.drag&&this.point&&(pointTip||this.hover)){this.tip.textContent=pointTip||(this.names[this.hover.name]||this.hover.name);this.tip.hidden=false;this.tip.style.left=Math.max(6,Math.min(this.width-210,this.point[0]+14))+'px';this.tip.style.top=Math.max(6,Math.min(this.height-80,this.point[1]+14))+'px';}else this.tip.hidden=true;
      this.stats.frames++;this.stats.lastFrameMs=performance.now()-started;this.stats.maxFrameMs=Math.max(this.stats.maxFrameMs,this.stats.lastFrameMs);this.el.dataset.mapZoom=String(this.zoom);this.el.dataset.geometryPaints=String(this.stats.geometryPaints);this.el.dataset.mapFrames=String(this.stats.frames);this.el.dataset.mapFrameMs=this.stats.lastFrameMs.toFixed(3);this.el.dataset.mapMaxFrameMs=this.stats.maxFrameMs.toFixed(3);
      if(this.effect&&!this.drag&&!matchMedia('(prefers-reduced-motion: reduce)').matches&&!document.hidden){clearTimeout(this.pulseTimer);this.pulseTimer=setTimeout(()=>this.schedule(),50);}
    }
    // Explicit bridge for existing source series; no deep options/geometry clone.
    setOption(option){if(option.geo){this.zoom=Number(option.geo.zoom||this.zoom);if(option.geo.center)this.pan=[0,0];}if(option.series)for(const patch of option.series){let current=this.series.find(s=>s.id===patch.id);if(!current){current={id:patch.id,type:patch.id.includes('line')?'lines':'scatter',data:[]};this.series.push(current);}Object.assign(current,patch);}this.schedule();}
    getOption(){return {geo:[{zoom:this.zoom}],series:this.series};}
    on(name,fn){this.events.set(name,[...(this.events.get(name)||[]),fn]);}off(name){this.events.delete(name);}
    getZr(){return {on:(name,fn)=>this.zrEvents.set(name,[...(this.zrEvents.get(name)||[]),fn])};}
    dispatchAction(action){if(action.type==='hideTip'&&!this.point)this.tip.hidden=true;}
  }
  window.CachedWorldMap=CachedWorldMap;
})();
