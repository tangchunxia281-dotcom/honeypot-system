(() => {'use strict';const side=document.getElementById('aiSidebar'),toggle=document.getElementById('navToggle');
  const narrow=matchMedia('(max-width: 760px)');
  function navigation(open=false,returnFocus=false){
    if(!side)return;
    side.classList.toggle('open',narrow.matches&&open);
    const hidden=narrow.matches&&!open;
    // A translated-offscreen link must not remain in keyboard navigation.
    if(hidden&&side.contains(document.activeElement))toggle?.focus();
    side.inert=hidden;side.setAttribute('aria-hidden',String(hidden));
    toggle?.setAttribute('aria-expanded',String(narrow.matches&&open));
    if(returnFocus)toggle?.focus();
  }
  navigation();narrow.addEventListener('change',()=>navigation());
  toggle?.addEventListener('click',()=>navigation(!side.classList.contains('open')));
  side?.querySelectorAll('a').forEach(a=>a.addEventListener('click',()=>navigation()));
  document.addEventListener('keydown',e=>{if(e.key==='Escape'&&side?.classList.contains('open'))navigation(false,true);});
  document.getElementById('backTop')?.addEventListener('click',()=>window.scrollTo({top:0,behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'}));
  const links=[...document.querySelectorAll('[data-section]')];if('IntersectionObserver' in window){const observer=new IntersectionObserver(entries=>{for(const e of entries)if(e.isIntersecting)links.forEach(a=>a.classList.toggle('active',a.dataset.section===e.target.id));},{rootMargin:'-10% 0px -60% 0px'});links.forEach(a=>{const section=document.getElementById(a.dataset.section);if(section)observer.observe(section);});}
})();
