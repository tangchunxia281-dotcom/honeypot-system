(() => {'use strict';const side=document.getElementById('aiSidebar'),toggle=document.getElementById('navToggle');
  toggle?.addEventListener('click',()=>{const open=side.classList.toggle('open');toggle.setAttribute('aria-expanded',String(open));});
  side?.querySelectorAll('a').forEach(a=>a.addEventListener('click',()=>{side.classList.remove('open');toggle?.setAttribute('aria-expanded','false');}));
  document.addEventListener('keydown',e=>{if(e.key==='Escape'){side?.classList.remove('open');toggle?.setAttribute('aria-expanded','false');}});
  document.getElementById('backTop')?.addEventListener('click',()=>window.scrollTo({top:0,behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'}));
  const links=[...document.querySelectorAll('[data-section]')];if('IntersectionObserver' in window){const observer=new IntersectionObserver(entries=>{for(const e of entries)if(e.isIntersecting)links.forEach(a=>a.classList.toggle('active',a.dataset.section===e.target.id));},{rootMargin:'-10% 0px -60% 0px'});links.forEach(a=>{const section=document.getElementById(a.dataset.section);if(section)observer.observe(section);});}
})();
