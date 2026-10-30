const {test}=require('node:test'),assert=require('node:assert/strict');
const vm=require('node:vm'),fs=require('node:fs'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../dashboard/static/js/ai_shell.js'),'utf8');

function shell(){
 const classes=new Set(),listeners={},changes=[];
 const toggle={attrs:{},addEventListener:(name,fn)=>listeners['toggle:'+name]=fn,setAttribute(name,value){this.attrs[name]=value;},focus(){document.activeElement=this;}};
 const link={focus(){document.activeElement=this;},addEventListener(){}};
 const side={inert:false,attrs:{},classList:{contains:k=>classes.has(k),remove:k=>classes.delete(k),toggle(k,force){const on=force===undefined?!classes.has(k):force;on?classes.add(k):classes.delete(k);return on;}},
   setAttribute(name,value){this.attrs[name]=value;},querySelectorAll:()=>[link],querySelector:()=>link,contains:e=>e===link};
 const media={matches:true,addEventListener:(name,fn)=>changes.push(fn)};
 const document={activeElement:toggle,getElementById:id=>({aiSidebar:side,navToggle:toggle}[id]),querySelectorAll:()=>[],addEventListener:(name,fn)=>listeners[name]=fn};
 vm.runInNewContext(source,{document,window:{scrollTo(){}},matchMedia:()=>media});
 return {side,toggle,link,document,click:()=>listeners['toggle:click'](),escape:()=>listeners.keydown({key:'Escape'}),resize(wide){media.matches=!wide;changes.forEach(fn=>fn());}};
}

test('closed narrow-screen navigation cannot receive keyboard focus',()=>{
 const s=shell();assert.equal(s.side.inert,true);assert.equal(s.side.attrs['aria-hidden'],'true');
 s.click();assert.equal(s.side.inert,false);assert.equal(s.toggle.attrs['aria-expanded'],'true');
 s.document.activeElement=s.link;s.escape();assert.equal(s.side.inert,true);assert.equal(s.document.activeElement,s.toggle);
 s.resize(true);assert.equal(s.side.inert,false);assert.equal(s.side.attrs['aria-hidden'],'false');
});
