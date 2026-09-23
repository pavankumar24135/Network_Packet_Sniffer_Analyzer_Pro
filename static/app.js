let packetData=[];

function fmtBytes(n){if(n<1024)return n+" B";if(n<1024*1024)return(n/1024).toFixed(2)+" KB";return(n/1024/1024).toFixed(2)+" MB"}

async function refresh(){
 const s=await fetch("/api/stats").then(r=>r.json());
 document.getElementById("totalPackets").textContent=s.total_packets;
 document.getElementById("totalBytes").textContent=fmtBytes(s.total_bytes);
 for(const p of ["tcp","udp","dns","arp"])document.getElementById(p).textContent=s.protocols[p.toUpperCase()]||0;
 const status=document.querySelector(".status");
 status.className="status"+(s.running?" running":"");
 document.getElementById("statusText").textContent=s.running?"Capturing":"Stopped";
 const entries=Object.entries(s.protocols);
 const max=Math.max(1,...entries.map(x=>x[1]));
 document.getElementById("bars").innerHTML=entries.map(([p,c])=>`<div class="barbox"><div class="bar" style="height:${Math.max(4,c/max*110)}px"></div><b>${c}</b><small>${p}</small></div>`).join("");
 packetData=await fetch("/api/packets?limit=300").then(r=>r.json());
 renderPackets();
}

function renderPackets(){
 const q=document.getElementById("filter").value.toLowerCase();
 const pf=document.getElementById("protocolFilter").value;
 const rows=packetData.filter(p=>(!pf||p.protocol===pf)&&Object.values(p).join(" ").toLowerCase().includes(q));
 document.getElementById("packetBody").innerHTML=rows.map(p=>`<tr onclick="showPacket(${p.id})">
 <td>${p.id}</td><td>${p.time}</td><td>${p.source}</td><td>${p.destination}</td>
 <td><b>${p.protocol}</b></td><td>${p.network}</td><td>${p.sport}</td><td>${p.dport}</td>
 <td>${p.flags}</td><td>${p.size} B</td></tr>`).join("");
}

async function showPacket(id){
 const p=await fetch("/api/packet/"+id).then(r=>r.json());
 document.getElementById("detail").textContent=JSON.stringify(p,null,2);
 document.getElementById("modal").classList.remove("hidden");
}
function hideModal(){document.getElementById("modal").classList.add("hidden")}
function closeModal(e){if(e.target.id==="modal")hideModal()}
async function startCapture(){await fetch("/api/start",{method:"POST"});refresh()}
async function stopCapture(){await fetch("/api/stop",{method:"POST"});refresh()}
async function clearData(){await fetch("/api/clear",{method:"POST"});refresh()}
refresh();setInterval(refresh,1500);
