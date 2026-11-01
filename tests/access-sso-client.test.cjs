const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync('web/static/js/auth.js','utf8');
function harness(fetch){
 const elements=new Map();
 for(const id of ['login-form','organization-sso-link'])elements.set(id,{style:{},hidden:false,focus(){}});
 const subtitle={textContent:'Local sign-in',removeAttribute(){this.translatable=false}};
 const context=vm.createContext({fetch,console,Headers,Date,Set,Promise,setTimeout:()=>{},window:{},localStorage:{getItem:()=>null,removeItem(){},setItem(){}},document:{addEventListener(){},getElementById:id=>elements.get(id),querySelector:()=>subtitle}});
 vm.runInContext(source+'\nvar shown=[];var bootCount=0;showLoginOverlay=(message="")=>shown.push(message);hideLoginOverlay=()=>{};setupLoginUI=()=>{};applyRBACToUI=()=>{};renderUserMenuProfile=()=>{};bootstrapApp=async()=>{bootCount++};',context);
 return {context,elements,subtitle,run:()=>vm.runInContext('initializeApp()',context),read:expr=>vm.runInContext(expr,context)};
}
const json=data=>({ok:true,json:async()=>data});
test('hosted Access rebinding finishes before startup callers can show a password overlay',async()=>{
 let release;const exchange=new Promise(r=>release=r);
 const h=harness(async url=>url.endsWith('/methods')?json({access_sso:true,sso_only:true}):exchange);
 const start=h.run();
 const waiting=h.read('ensureAuthenticated()');
 await new Promise(setImmediate);assert.equal(h.read('shown.length'),0);
 release(json({token:'native',expires_at:new Date(Date.now()+3600000).toISOString(),user:{username:'viewer'},roles:['viewer'],permissions:[]}));
 await Promise.all([start,waiting]);assert.equal(h.read('bootCount'),1);assert.equal(h.read('shown.length'),0);assert.equal(h.elements.get('login-form').hidden,true);assert.equal(h.subtitle.translatable,false);
});
for(const scenario of ['network','missing-token','unassigned'])test('SSO-only '+scenario+' leaves an actionable visible failure',async()=>{
 const h=harness(async url=>{if(url.endsWith('/methods'))return json({access_sso:true,sso_only:true});if(scenario==='network')throw new Error('offline');if(scenario==='unassigned')return {ok:false,json:async()=>({error:'Access not assigned'})};return json({})});
 await h.run();assert.equal(h.read('bootCount'),0);assert.ok(h.read('shown.at(-1)').length);assert.equal(h.elements.get('organization-sso-link').style.display,'flex');
});
test('local instance never attempts Pentforge SSO when the method is disabled',async()=>{
 const calls=[];const h=harness(async url=>{calls.push(url);return json({access_sso:false,sso_only:false})});await h.run();assert.deepEqual(calls,['/api/auth/methods']);assert.equal(h.elements.get('organization-sso-link').style.display,'none');assert.equal(h.elements.get('login-form').hidden,false);
});
