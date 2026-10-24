/** Offline MIME inspection. No network, storage, rendering or attachment execution. */
export const MAX_EMAIL_BYTES = 5 * 1024 * 1024;
export type Header = {name:string;value:string};
export type Attachment = {name:string;type:string;bytes:number;sha256:string;notes:string[]};
export type EmailAnalysis = {headers:Header[];summary:Record<string,string>;authentication:{method:string;result:string;source:string}[];received:string[];urls:{url:string;host:string;notes:string[]}[];attachments:Attachment[];bodies:{type:string;text:string}[];warnings:string[];partCount:number};

function bytes(value:string){return Uint8Array.from(value,c=>c.charCodeAt(0)&255);}
function decodeText(value:Uint8Array,charset='utf-8') {return new TextDecoder(charset,{fatal:false}).decode(value);}
function quotedPrintable(value:string) {return bytes(value.replace(/=\r?\n/g,'').replace(/=([a-f\d]{2})/gi,(_,h)=>String.fromCharCode(parseInt(h,16))));}
export function decodeWords(value:string):string {
  return value.replace(/(\?=)[ \t]+(?==\?)/g,'$1').replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi,(whole,charset,encoding,data)=>{
    try{return decodeText(encoding.toLowerCase()==='b'?bytes(atob(data)):quotedPrintable(data.replace(/_/g,' ')),charset);}catch{return whole;}
  });
}
function parseHeaders(raw:string):{headers:Header[];body:string} {
  const text=raw.replace(/\r\n/g,'\n');const at=text.indexOf('\n\n');
  const block=at<0?text:text.slice(0,at);const headers:Header[]=[];
  for(const line of block.split('\n')) {
    if(/^[ \t]/.test(line)&&headers.length){headers[headers.length-1].value+=' '+line.trim();continue;}
    const m=/^([!#$%&'*+\-.^_`|~0-9A-Za-z]+):[ \t]*(.*)$/.exec(line);
    if(m)headers.push({name:m[1],value:m[2]});
  }
  return {headers,body:at<0?'':text.slice(at+2)};
}
function get(headers:Header[],name:string) {return headers.find(h=>h.name.toLowerCase()===name)?.value||'';}
function parameter(value:string,name:string) {
  const fields=[...value.matchAll(/;\s*([\w*-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^;]*)/g)];
  const field=fields.find(m=>m[1].toLowerCase()===name+'*')||fields.find(m=>m[1].toLowerCase()===name);
  if(!field)return '';
  let v=field[2].trim().replace(/^"|"$/g,'').replace(/\\(.)/g,'$1');
  if(field[1].endsWith('*')){try{v=decodeURIComponent(v.replace(/^[^']*'[^']*'/,''));}catch{}}
  return decodeWords(v);
}
function entities(text:string) {return text.replace(/&(?:amp|quot|apos|lt|gt|#\d+|#x[\da-f]+);/gi,s=>{
  const names:Record<string,string>={'&amp;':'&','&quot;':'"','&apos;':"'",'&lt;':'<','&gt;':'>'};
  if(names[s.toLowerCase()])return names[s.toLowerCase()];
  const n=s.toLowerCase().startsWith('&#x')?parseInt(s.slice(3,-1),16):parseInt(s.slice(2,-1),10);
  return n>0&&n<=0x10ffff?String.fromCodePoint(n):s;
});}
function urlsIn(text:string) {return [...entities(text).matchAll(/https?:\/\/[^\s<>"'`]+/gi)].map(m=>m[0].replace(/[),.;]+$/,''));}

export async function analyzeEmail(raw:string):Promise<EmailAnalysis> {
  if(!raw.trim())throw new Error('Choose an email file or paste the full raw email first.');
  if(new TextEncoder().encode(raw).length>MAX_EMAIL_BYTES)throw new Error('Email exceeds the 5 MB analysis limit.');
  const top=parseHeaders(raw);
  if(!top.headers.length)throw new Error('No email headers found. Supply a raw .eml message with headers, not just body text.');
  const warnings:string[]=[];
  if(!/\r?\n\r?\n/.test(raw))warnings.push('No header/body separator found; body analysis is unavailable.');
  const out:EmailAnalysis={headers:top.headers,summary:{},authentication:[],received:top.headers.filter(h=>h.name.toLowerCase()==='received').map(h=>h.value),urls:[],attachments:[],bodies:[],warnings,partCount:0};
  for(const name of ['from','to','reply-to','return-path','subject','date','message-id'])out.summary[name]=decodeWords(get(top.headers,name))||'Not present';
  for(const name of ['from','subject','date','message-id'])if(top.headers.filter(h=>h.name.toLowerCase()===name).length>1)warnings.push('Multiple '+name+' headers; inspect all raw headers before trusting the summary.');
  for(const header of top.headers.filter(h=>['authentication-results','arc-authentication-results'].includes(h.name.toLowerCase()))) {
    for(const m of header.value.matchAll(/\b(spf|dkim|dmarc)\s*=\s*([a-z_-]+)/gi))out.authentication.push({method:m[1].toUpperCase(),result:m[2].toLowerCase(),source:header.name+': '+header.value});
  }
  for(const method of ['SPF','DKIM','DMARC'])if(!out.authentication.some(a=>a.method===method))out.authentication.push({method,result:'not reported',source:'No matching Authentication-Results claim found.'});
  const urlSet=new Set<string>();
  async function walk(source:string,depth:number) {
    if(depth>10||out.partCount>=100){if(!warnings.includes('MIME inspection limit reached. Some parts were not analyzed.'))warnings.push('MIME inspection limit reached. Some parts were not analyzed.');return;}
    out.partCount++;
    const {headers,body}=parseHeaders(source);
    const contentType=get(headers,'content-type')||'text/plain';const type=contentType.split(';')[0].trim().toLowerCase();
    if(type.startsWith('multipart/')) {
      const boundary=parameter(contentType,'boundary');
      if(!boundary){warnings.push('Multipart message missing a boundary; content not decoded.');return;}
      let part:string[]|null=null,closed=false,found=false;
      for(const line of body.split('\n')) {
        const trimmed=line.trimEnd();
        if(trimmed==='--'+boundary||trimmed==='--'+boundary+'--'){
          found=true;if(part)await walk(part.join('\n'),depth+1);
          if(trimmed.endsWith('--')&&trimmed==='--'+boundary+'--'){closed=true;part=null;break;}part=[];
        }else if(part)part.push(line);
      }
      if(part)await walk(part.join('\n'),depth+1);
      if(!found||!closed)warnings.push('Incomplete MIME boundary sequence; inspect raw source for missing content.');
      return;
    }
    const encoding=get(headers,'content-transfer-encoding').trim().toLowerCase();
    let decoded:Uint8Array;
    try {
      if(encoding==='base64')decoded=bytes(atob(body.replace(/\s/g,'')));
      else if(encoding==='quoted-printable')decoded=quotedPrintable(body);
      else if(['','7bit','8bit','binary'].includes(encoding))decoded=new TextEncoder().encode(body);
      else {warnings.push('Unsupported transfer encoding '+encoding+'; part skipped.');return;}
    }catch{warnings.push('Invalid '+encoding+' data in a MIME part; part skipped.');return;}
    const disposition=get(headers,'content-disposition');
    const name=parameter(disposition,'filename')||parameter(contentType,'name');
    if(name||/^attachment\b/i.test(disposition)||!['text/plain','text/html'].includes(type)) {
      const notes:string[]=[];
      if(/\.(exe|scr|com|bat|cmd|js|vbs|ps1|msi|hta|jar|lnk|docm|xlsm)$/i.test(name))notes.push('Executable or active-content extension; requires careful review.');
      if(/\.(zip|rar|7z|gz)$/i.test(name))notes.push('Archive contents were not unpacked or scanned.');
      if(['','7bit','8bit','binary'].includes(encoding))notes.push('Hash uses UTF-8 decoded text bytes; exact original binary bytes are not available for this transfer encoding.');
      const sha256=[...new Uint8Array(await crypto.subtle.digest('SHA-256',new Uint8Array(decoded)))].map(b=>b.toString(16).padStart(2,'0')).join('');
      out.attachments.push({name:name||'Unnamed MIME part',type,bytes:decoded.length,sha256,notes});return;
    }
    let text:string;
    try{text=decodeText(decoded,parameter(contentType,'charset')||'utf-8');}catch{warnings.push('Unsupported charset; showing UTF-8 fallback.');text=decodeText(decoded);}
    for(const url of urlsIn(text)){if(urlSet.size<500)urlSet.add(url);else if(!warnings.includes('URL list limited to 500 unique entries.'))warnings.push('URL list limited to 500 unique entries.');}
    out.bodies.push({type,text});
  }
  await walk(raw,0);
  for(const url of urlSet){try{const parsed=new URL(url);const notes:string[]=[];
    if(parsed.protocol==='http:')notes.push('Unencrypted HTTP link');
    if(parsed.username||parsed.password)notes.push('Embedded credentials / misleading URL prefix');
    if(parsed.hostname.includes('xn--'))notes.push('Internationalized domain (punycode); review spelling');
    if(/^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname)||parsed.hostname.startsWith('['))notes.push('IP address instead of a domain');
    out.urls.push({url,host:parsed.hostname,notes});
  }catch{warnings.push('An extracted URL could not be parsed.');}}
  return out;
}
