import test from 'node:test';
import assert from 'node:assert/strict';
import handler from '../api/[...path].js';

function response(){return {headers:{},code:0,data:null,setHeader(k,v){this.headers[k]=v;},status(v){this.code=v;return this;},json(v){this.data=v;return this;},send(v){this.data=v;return this;},end(){return this;}};}
test('missing backend is an honest 503',async()=>{delete process.env.VULNX_API_ORIGIN;const res=response();await handler({method:'GET',headers:{},url:'/api/state'},res);assert.equal(res.code,503);});
test('proxy preserves auth cookies and PDF bytes without forwarding arbitrary headers',async()=>{
 const original=global.fetch;process.env.VULNX_API_ORIGIN='https://backend.example';
 let captured;
 global.fetch=async(url,options)=>{captured={url:String(url),options};return new Response('%PDF-fixture',{headers:{'content-type':'application/pdf','set-cookie':'auth=test; HttpOnly; Secure'}});};
 try{const res=response();await handler({method:'GET',url:'/api/reports/id.pdf',headers:{cookie:'auth=abc','x-evil':'no'}},res);assert.equal(res.code,200);assert.equal(res.data.toString(),'%PDF-fixture');assert.equal(captured.url,'https://backend.example/api/reports/id.pdf');assert.equal(captured.options.headers.cookie,'auth=abc');assert.equal(captured.options.headers['x-evil'],undefined);assert.equal(res.headers['Set-Cookie'].length,1);}finally{global.fetch=original;delete process.env.VULNX_API_ORIGIN;}
});
test('proxy rejects non-HTTPS configuration',async()=>{process.env.VULNX_API_ORIGIN='http://backend.example';const res=response();await handler({method:'GET',url:'/api/state',headers:{}},res);assert.equal(res.code,502);delete process.env.VULNX_API_ORIGIN;});
