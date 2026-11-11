// PocketRSI audit arms (Kehai, 2026-11-10). Usage, from this folder:
//   node run_arm.js shipped ladder 30        (the jar as delivered, default rung cycle)
//   node run_arm.js shipped weights 30       (Rung 1 only: keep training)
//   node run_arm.js core_blind.js blind 30   (no curated optimizer ladder, unguided recipe)
//   node run_arm.js core_ouroboros_genuine.js ouro_real 30   (@scorer genuinely mutated)
//   node run_arm.js shipped ouro_shipped 10  (the delivered, scripted Ouroboros)
// Scores: 'exam' = examiner combined (0.7 ID + 0.3 OOD) on the examiner's seeds;
// 'freshAcc' = mean token accuracy on 24 fresh 0b11 seeds neither file ever used.
const fs=require('fs'),vm=require('vm');
const [,,consPath,mode,NS]=process.argv;const N=+NS;
const sb={TextEncoder,TextDecoder,Buffer,Float32Array,Int32Array,Uint32Array,Uint8Array,Int8Array,DataView,ArrayBuffer,Math,Date,JSON,Object,Array,Map,Set,Error,Number,String,Boolean,RegExp,parseInt,parseFloat,isNaN,isFinite,console,globalThis:{}};
sb.self=sb;sb.window=sb;vm.createContext(sb);
// consPath 'shipped' = the jar's own #rsi-constitution; otherwise a patched core file in this folder
const jarHtml=fs.readFileSync(require('path').join(__dirname,'..','pocketrsi.html'),'utf8');
const coreSrc=consPath==='shipped'?jarHtml.match(/<script[^>]*id=["']rsi-constitution["'][^>]*>([\s\S]*?)<\/script>/)[1]:fs.readFileSync(require('path').resolve(__dirname,consPath),'utf8');
vm.runInContext(coreSrc,sb);const C=sb.PocketRSICore;
const P=C.parseDescendantHTML(jarHtml);
const st=C.createInitialState(P.constitutionHash);
const mk=(k)=>[...Array(12).keys()].map(s=>((C.mixHashU32(`KEHAI_FRESH_${k}:${s}`)&0x3fffffff)|0xc0000000)>>>0);
const FID=mk('id'),FOOD=mk('ood');
function ev(gt,w){const g=C.parseGenome(gt);const m=new C.RWKV7({...g.arch,ternaryMix:g.recipe.ternaryMix,quantThresh:g.recipe.quantThresh,groupSize:g.recipe.groupSize},new C.DetRNG(C.GEN0_INIT_SEED));m.loadFlatWeights(w);
 const ei=C.evaluateModelOnSeeds(m,g,C.EXAMINER_ID_SEEDS,false,true),eo=C.evaluateModelOnSeeds(m,g,C.EXAMINER_OOD_SEEDS,true,true);
 const fi=C.evaluateModelOnSeeds(m,g,FID,false,true),fo=C.evaluateModelOnSeeds(m,g,FOOD,true,true);
 return {exam:+(0.7*ei.score+0.3*eo.score).toFixed(4),freshAcc:+((fi.acc+fo.acc)/2).toFixed(4)};}
const out=[];let acc=0;
for(let i=1;i<=N;i++){const opts=mode==='weights'?{rung:'weights'}:(mode.startsWith('ouro')?{ouroboros:true}:{});C.evolveOneGeneration(st,opts);const rec=st.lineage[st.lineage.length-1];if(rec.accepted!==false)acc++;
 if(i%5===0||i===N){out.push({gen:i,selfDev:JSON.stringify(rec.dev_scores).slice(0,160),...ev(st.activeGenomeText,st.activeWeights)});}}
const upd=C.parseDSLProgram(C.parseGenome(st.activeGenomeText).dsl);
console.log(JSON.stringify({mode,cons:consPath.split('/').pop(),N,accepted:acc,curve:out,finalUpdate:C.serializeDSLAst(upd.update),finalScorer:C.serializeDSLAst(upd.scorer),recKeys:Object.keys(st.lineage[1]).join(',')}));
