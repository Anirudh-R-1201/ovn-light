/* SPDX-License-Identifier: Apache-2.0 */
'use strict';
function issueValue(value){
 if(Array.isArray(value))return value.map(issueValue);
 if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,issueValue(value[k])]));
 return value;
}
function issueEndpoint(e){return [e?.node,e?.network,e?.nad,e?.namespace,e?.pod,e?.uid,e?.ip,e?.port,e?.role,e?.policyKind]}

// Several reconstructed paths can end at one drop counter. Group only matching
// endpoint and policy identities; keep each path available without adding counts.
function groupFindings(findings){
 const groups=new Map();
 for(const [index,f] of findings.entries()){
  const causes=(f.causes||[]).map(c=>JSON.stringify(issueValue(c))).sort();
  const key=JSON.stringify([f.node,f.counterID||f.id||index,issueEndpoint(f.source),issueEndpoint(f.destination),f.protocol,f.verdict,f.confidence,!!f.canRecommend,causes]);
  if(!groups.has(key))groups.set(key,{finding:f,paths:[],seen:new Set()});
  const group=groups.get(key);
  // Finding IDs identify the ordered flow IDs. Conditional branches can reach
  // the same path twice; retain separate warnings and candidate evidence.
  const pathKey=JSON.stringify([f.id||index,issueValue(f.sourceContext),[...new Set(f.warnings||[])].sort()]);
  if(!group.seen.has(pathKey)){group.paths.push(f);group.seen.add(pathKey)}
 }
 return [...groups.values()];
}
