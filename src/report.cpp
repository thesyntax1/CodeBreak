#include "report.h"
#include <string>
#include <vector>
#include <sstream>
#include <ctime>

namespace cb {

std::string escapeHtml(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (char ch : s) {
        switch (ch) {
        case '&': o += "&amp;"; break;
        case '<': o += "&lt;"; break;
        case '>': o += "&gt;"; break;
        case '"': o += "&quot;"; break;
        case '\'': o += "&#39;"; break;
        default: o += ch;
        }
    }
    return o;
}

static std::string nowStamp() {
    std::time_t t = std::time(nullptr);
    char buf[64];
    std::tm tmv;
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    return buf;
}

static std::string jsonForScript(const std::string& json) {
    std::string o;
    o.reserve(json.size());
    for (size_t i = 0; i + 1 < json.size(); i++) {
        if (json[i] == '<' && json[i + 1] == '/') { o += "<\\/"; i++; continue; }
        o += json[i];
    }
    if (!json.empty()) o += json.back();
    return o;
}

std::string buildHtmlReport(const std::string& analysisJson, const std::string& sourcePath) {
    std::ostringstream h;
    h << "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
      << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
      << "<title>CodeBreak Analysis Report</title>\n"
      << "<style>\n"
      << "body{background:#0b0e14;color:#d7e0f0;font-family:Segoe UI,system-ui,sans-serif;margin:0;font-size:13px}\n"
      << "header{background:linear-gradient(180deg,#131a2a,#0f141f);padding:16px 24px;border-bottom:1px solid #232c40}\n"
      << "header h1{font-size:16px;margin:0}\n"
      << "header .sub{color:#8b98b4;font-family:Consolas,monospace;font-size:11px;margin-top:4px;word-break:break-all}\n"
      << ".wrap{max-width:1080px;margin:0 auto;padding:22px 24px}\n"
      << ".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}\n"
      << ".card{background:#121722;border:1px solid #232c40;border-radius:10px;padding:14px 16px}\n"
      << ".card .k{color:#8b98b4;font-size:10px;text-transform:uppercase;letter-spacing:.6px}\n"
      << ".card .v{font-family:Consolas,monospace;font-size:16px;font-weight:600;margin-top:4px;word-break:break-all}\n"
      << "h2{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#5f6c88;margin:26px 0 10px}\n"
      << ".gauge{height:14px;background:#1c2436;border-radius:7px;overflow:hidden;position:relative}\n"
      << ".gauge .f{position:absolute;left:0;top:0;bottom:0;border-radius:7px}\n"
      << ".badge{display:inline-block;font-size:10px;font-weight:600;padding:2px 8px;border-radius:4px;font-family:Consolas,monospace}\n"
      << ".cl-clean{color:#3fd68f}.cl-low{color:#6cb6ff}.cl-medium{color:#f5c451}.cl-high{color:#ff9f43}.cl-critical{color:#ff6b6b}\n"
      << ".bg-clean{background:#3fd68f}.bg-low{background:#6cb6ff}.bg-medium{background:#f5c451}.bg-high{background:#ff9f43}.bg-critical{background:#ff6b6b}\n"
      << ".sig{border:1px solid #232c40;border-left-width:3px;background:#121722;border-radius:8px;padding:10px 12px;margin-bottom:8px}\n"
      << ".sig .t{font-weight:600}\n.sig .d{color:#8b98b4;font-size:11px;margin-top:2px}\n"
      << ".bar{background:#1c2436;height:6px;border-radius:3px;margin-top:6px}\n.bar .f{height:6px;border-radius:3px;background:#4d9fff}\n"
      << "table{width:100%;border-collapse:collapse;font-size:12px}\nth{text-align:left;color:#5f6c88;font-size:10px;text-transform:uppercase;padding:6px 8px;border-bottom:1px solid #232c40}\n"
      << "td{padding:6px 8px;border-bottom:1px solid rgba(35,44,64,.5);font-family:Consolas,monospace}\n"
      << ".ind{display:flex;gap:10px;padding:8px 12px;border:1px solid #232c40;border-radius:8px;margin-bottom:6px;background:#121722}\n"
      << ".dot{width:8px;height:8px;border-radius:50%;margin-top:5px;flex-shrink:0}\n"
      << ".dot.info{background:#6cb6ff}.dot.medium{background:#f5c451}.dot.high{background:#ff6b6b}.dot.critical{background:#ff2d55}\n"
      << ".tree{background:#0d1220;border:1px solid #232c40;border-radius:10px;padding:12px;font-family:Consolas,monospace;font-size:12px;max-height:70vh;overflow:auto}\n"
      << "details{margin-left:12px;border-left:1px solid #232c40;padding-left:8px}\nsummary{cursor:pointer;color:#a99cf5;white-space:pre-wrap}\n.tree .s{color:#d7e0f0}.tree .k{color:#6cb6ff}.tree .num{color:#f5a451}\n"
      << "code.block{display:block;background:#0d1220;border:1px solid #232c40;border-radius:8px;padding:10px;white-space:pre-wrap;word-break:break-all;font-size:11px;color:#8b98b4}\n"
      << "footer{color:#5f6c88;text-align:center;padding:18px;font-size:11px;font-family:Consolas,monospace}\n"
      << "</style></head>\n<body>\n"
      << "<header><h1>CodeBreak <span style='color:#4d9fff'>Analysis Report</span></h1>"
      << "<div class='sub'>" << escapeHtml(sourcePath) << "</div></header>\n"
      << "<div class='wrap'><div id='root'></div><footer>Generated by CodeBreak &#183; " << nowStamp() << "</footer></div>\n"
      << "<script id='data' type='application/json'>" << jsonForScript(analysisJson) << "</script>\n"
      << "<script>\n"
      << "const D=JSON.parse(document.getElementById('data').textContent);\n"
      << "const col=document.createElement.bind(document);\n"
      << "function riskColor(l){return{l:'#3fd68f',low:'#6cb6ff',medium:'#f5c451',high:'#ff9f43',critical:'#ff6b6b'}[l]||'#6cb6ff';}\n"
      << "function badge(txt,color){const s=col('span');s.className='badge '+(color?'':'')+txt;s.textContent=txt;s.style.background=color+'22';s.style.color=color;s.style.border='1px solid '+color+'55';return s;}\n"
      << "function esc(x){return String(x).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}\n"
      << "function cards(o){const keys=Object.keys(o);const wrap=col('div');wrap.className='cards';\n"
      << "keys.forEach(k=>{const c=col('div');c.className='card';const kk=col('div');kk.className='k';kk.textContent=k;const vv=col('div');vv.className='v';vv.textContent=o[k];c.appendChild(kk);c.appendChild(vv);wrap.appendChild(c);});return wrap;}\n"
      << "const root=document.getElementById('root');\n"
      << "const r=D.risk||{score:0,level:'clean',signals:[],summary:''};\n"
      << "const rc=riskColor(r.level);\n"
      << "let h='';\n"
      << "h+='<h2>File</h2>'+cards({Name:D.file.name,Size:D.file.sizeHuman,'Detected format':D.format.label,'Risk score':r.score+' / 100',Level:r.level.toUpperCase()}).outerHTML;\n"
      << "h+='<div class=\"card\" style=\"margin-top:12px\"><div class=\"k\">SHA-256</div><div class=\"v\" style=\"font-size:12px;color:#b8c6e4\">'+esc(D.hashes.sha256)+'</div></div>';\n"
      << "h+='<h2>Threat Risk Assessment</h2>';\n"
      << "h+='<div class=\"card\"><div style=\"display:flex;justify-content:space-between;align-items:center\"><span style=\"font-size:34px;font-weight:700;font-family:Consolas,monospace;color:'+rc+'\">'+r.score+'<span style=\"font-size:14px;color:#5f6c88\"> / 100</span></span>'+badge(r.level,rc).outerHTML+'</div>';\n"
      << "h+='<div class=\"gauge\" style=\"margin-top:10px\"><div class=\"f\" style=\"width:'+r.score+'%;background:'+rc+'\"></div></div>';\n"
      << "h+='<div style=\"color:#8b98b4;font-size:12px;margin-top:10px\">'+esc(r.summary||'')+'</div></div>';\n"
      << "if(r.signals&&r.signals.length){h+='<h2>Contributing Signals</h2>';\n"
      << "r.signals.forEach(s=>{const mw=Math.max(...r.signals.map(x=>x.weight),1);h+='<div class=\"sig\" style=\"border-left-color:'+rc+'\"><div class=\"t\">'+esc(s.category)+' <span class=\"badge\" style=\"color:#a99cf5\">'+s.weight+' pts</span></div><div class=\"d\">'+esc(s.title)+'</div><div class=\"bar\"><div class=\"f\" style=\"width:'+(s.weight/mw*100)+'%\"></div></div></div>';});}\n"
      << "h+='<h2>Findings ('+(D.indicators?D.indicators.length:0)+')</h2>';\n"
      << "if(!D.indicators||!D.indicators.length)h+='<div style=\"color:#5f6c88\">No notable findings.</div>';\n"
      << "else D.indicators.forEach(i=>{h+='<div class=\"ind\"><div class=\"dot '+esc(i.severity)+'\"></div><div><div>'+esc(i.title)+' <span class=\"badge\">'+esc(i.severity)+'</span></div><div style=\"color:#8b98b4;font-size:11px\">'+esc(i.detail)+'</div></div></div>';});\n"
      << "h+='<h2>Hash Values</h2><table><tr><th>Algorithm</th><th>Value</th></tr>';\n"
      << "['md5','sha1','sha256'].forEach(a=>{h+='<tr><td>'+a.toUpperCase()+'</td><td>'+esc(D.hashes[a])+'</td></tr>';});h+='</table>';\n"
      << "if(D.entropy){h+='<h2>Entropy</h2><div class=\"card\"><div class=\"v\" style=\"color:'+riskColor(D.entropy.overall>7.4?'high':'clean')+'\"\">'+D.entropy.overall.toFixed(3)+'<span style=\"font-size:12px;color:#5f6c88\"> bits/byte overall</span></div></div>';}\n"
      << "h+='<h2>Full Analysis Structure</h2><div class=\"tree\">'+jsonTree(D)+'</div>';\n"
      << "root.innerHTML=h;\n"
      << "function jsonTree(v){return tree(v,0);}\n"
      << "function isObj(v){return v&&typeof v==='object';}\n"
      << "function tree(v,depth){if(!isObj(v))return escScalar(v);\n"
      << "if(Array.isArray(v)){if(!v.length)return '[ ]';let inner=v.map((x,i)=>'<details'+(depth<1?' open':'')+'><summary>'+esc('['+i+']')+'</summary>'+tree(x,depth+1)+'</details>').join('');return '['+inner+']';}\n"
      << "let ks=Object.keys(v);if(!ks.length)return '{ }';\n"
      << "let inner=ks.map(k=>{let val=isObj(v[k])?'':'<span class=\"num\">'+escVal(v[k])+'</span>';return '<details'+(depth<2?' open':'')+'><summary><span class=\"k\">'+esc(k)+'</span> '+(isObj(v[k])?'':'= ')+val+'</summary>'+(isObj(v[k])?tree(v[k],depth+1):'')+'</details>';}).join('');\n"
      << "return '{'+inner+'}';}\n"
      << "function escVal(v){if(v===null)return 'null';if(typeof v==='number')return String(v);if(typeof v==='boolean')return String(v);return JSON.stringify(v);}\n"
      << "function escScalar(v){return '<span class=\"s\">'+esc(escVal(v))+'</span>';}\n"
      << "</script></body></html>\n";
    return h.str();
}

std::string buildBatchHtml(const std::vector<BatchItem>& items, uint64_t totalBytes, double elapsedMs) {
    int clean = 0, low = 0, medium = 0, high = 0, critical = 0, failed = 0;
    for (const auto& it : items) {
        if (!it.ok) { failed++; continue; }
        if (it.riskLevel == "critical") critical++;
        else if (it.riskLevel == "high") high++;
        else if (it.riskLevel == "medium") medium++;
        else if (it.riskLevel == "low") low++;
        else clean++;
    }
    std::ostringstream h;
    h << "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\n"
      << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>CodeBreak Batch Report</title>\n"
      << "<style>body{background:#0b0e14;color:#d7e0f0;font-family:Segoe UI,sans-serif;margin:0;font-size:13px}"
      << "header{background:linear-gradient(180deg,#131a2a,#0f141f);padding:16px 24px;border-bottom:1px solid #232c40}"
      << "header h1{font-size:16px;margin:0}.wrap{max-width:1080px;margin:0 auto;padding:22px 24px}"
      << ".sum{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}"
      << ".pill{padding:8px 14px;border-radius:8px;border:1px solid #232c40;background:#121722;font-family:Consolas,monospace}"
      << "table{width:100%;border-collapse:collapse;font-size:12px}th{text-align:left;color:#5f6c88;text-transform:uppercase;font-size:10px;padding:6px 8px;border-bottom:1px solid #232c40;position:sticky;top:0;background:#0f141f}"
      << "td{padding:6px 8px;border-bottom:1px solid rgba(35,44,64,.5);font-family:Consolas,monospace;white-space:nowrap}"
      << "td.path{white-space:normal;word-break:break-all}.lv{font-weight:700}"
      << ".lv-clean{color:#3fd68f}.lv-low{color:#6cb6ff}.lv-medium{color:#f5c451}.lv-high{color:#ff9f43}.lv-critical{color:#ff6b6b}"
      << "footer{color:#5f6c88;text-align:center;padding:18px;font-size:11px;font-family:Consolas,monospace}"
      << "</style></head><body>\n"
      << "<header><h1>CodeBreak <span style='color:#4d9fff'>Batch Scan Report</span></h1></header>\n"
      << "<div class='wrap'><div class='sum'>"
      << "<span class='pill'>Scanned <b>" << items.size() << "</b></span>"
      << "<span class='pill'>Clean <b>" << clean << "</b></span>"
      << "<span class='pill'>Low <b>" << low << "</b></span>"
      << "<span class='pill'>Medium <b>" << medium << "</b></span>"
      << "<span class='pill'>High <b>" << high << "</b></span>"
      << "<span class='pill'>Critical <b>" << critical << "</b></span>"
      << "<span class='pill'>Failed <b>" << failed << "</b></span>"
      << "<span class='pill'>Total data " << (totalBytes >> 20) << " MB</span>"
      << "<span class='pill'>" << elapsedMs << " ms</span>"
      << "</div><div style='overflow:auto;max-height:80vh'><table><tr><th>Path</th><th>Format</th><th>Size</th><th>Risk</th><th>SHA-256</th></tr>";
    for (const auto& it : items) {
        if (!it.ok) {
            h << "<tr><td class='path'>" << escapeHtml(it.path) << "</td><td>error</td><td>-</td><td>-</td><td>" << escapeHtml(it.error) << "</td></tr>";
            continue;
        }
        std::string lv = it.riskLevel.empty() ? "clean" : it.riskLevel;
        h << "<tr><td class='path'>" << escapeHtml(it.path) << "</td><td>" << escapeHtml(it.format) << "</td><td>"
          << it.size << "</td><td class='lv lv-" << lv << "'>" << it.riskScore << " " << lv << "</td><td>"
          << escapeHtml(it.sha256) << "</td></tr>";
    }
    h << "</table></div><footer>Generated by CodeBreak &#183; " << nowStamp() << "</footer></div></body></html>\n";
    return h.str();
}

}
