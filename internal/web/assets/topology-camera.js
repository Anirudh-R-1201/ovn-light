/* SPDX-License-Identifier: Apache-2.0 */
'use strict';
function applyTopologyCamera(){
 const c=topologyState.camera,root=$('topology-graph').querySelector('.topology-canvas');
 if(root&&root.parentElement.clientWidth>=620)root.style.transform=`translate(${c.x}px,${c.y}px) scale(${c.k})`;
 $('topology-zoom').textContent=Math.round(c.k*100)+'%';
 $('topology-graph').classList.toggle('show-labels',$('topology-labels').checked);
}
function resetTopologyCamera(){topologyState.camera={x:0,y:0,k:1};topologyState.layoutKey='';topologyState.positions.clear();applyTopologyCamera();}
function zoomTopology(factor,x,y){
 const viewport=$('topology-graph').querySelector('.topology-viewport');if(!viewport)return;
 const c=topologyState.camera,k=Math.max(.15,Math.min(3,c.k*factor));x??=viewport.clientWidth/2;y??=viewport.clientHeight/2;
 c.x=x-(x-c.x)*k/c.k;c.y=y-(y-c.y)*k/c.k;c.k=k;applyTopologyCamera();
}
function setupTopologyCamera(viewport,root){
 applyTopologyCamera();
 viewport.addEventListener('wheel',e=>{e.preventDefault();const b=viewport.getBoundingClientRect();zoomTopology(Math.exp(-e.deltaY*.0015),e.clientX-b.left,e.clientY-b.top);},{passive:false});
 let drag;
 viewport.onpointerdown=e=>{if(e.button!==0||e.target.closest('button,.topology-hit'))return;drag={x:e.clientX,y:e.clientY,c:{...topologyState.camera}};viewport.setPointerCapture(e.pointerId);};
 viewport.onpointermove=e=>{if(!drag)return;topologyState.camera.x=drag.c.x+e.clientX-drag.x;topologyState.camera.y=drag.c.y+e.clientY-drag.y;applyTopologyCamera();};
 viewport.onpointerup=viewport.onpointercancel=()=>{drag=null;};
 viewport.onkeydown=e=>{if(e.target!==viewport)return;const c=topologyState.camera;if(e.key==='+')zoomTopology(1.2);else if(e.key==='-')zoomTopology(1/1.2);else if(e.key==='ArrowLeft')c.x+=40;else if(e.key==='ArrowRight')c.x-=40;else if(e.key==='ArrowUp')c.y+=40;else if(e.key==='ArrowDown')c.y-=40;else return;e.preventDefault();applyTopologyCamera();};
}
$('topology-zoom-in').onclick=()=>zoomTopology(1.25);
$('topology-zoom-out').onclick=()=>zoomTopology(.8);
$('topology-reset').onclick=resetTopologyCamera;
$('topology-labels').onchange=applyTopologyCamera;
$('topology-fit').onclick=()=>{const root=$('topology-graph').querySelector('.topology-canvas');if(!root)return;const v=root.parentElement,k=Math.min(1,v.clientWidth/root.offsetWidth,v.clientHeight/root.offsetHeight);topologyState.camera={k,x:(v.clientWidth-root.offsetWidth*k)/2,y:0};applyTopologyCamera();};
