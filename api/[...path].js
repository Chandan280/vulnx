// Same-origin API bridge; scanners execute only on the persistent backend.
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (!['GET', 'POST', 'OPTIONS'].includes(req.method)) return res.status(405).json({error:'Method not allowed.'});
  const configured = process.env.VULNX_API_ORIGIN;
  if (!configured) return res.status(503).json({error:'Backend deployment is not configured.'});
  try {
    const backend = new URL(configured);
    if (backend.protocol !== 'https:' || backend.username || backend.password || backend.pathname !== '/') throw new Error('Invalid backend configuration');
    const incoming = new URL(req.url, 'https://frontend.invalid');
    if (!incoming.pathname.startsWith('/api/')) return res.status(404).end();
    backend.pathname = incoming.pathname;
    backend.search = incoming.search;
    const headers = {};
    for (const name of ['cookie','origin','content-type','x-vulnx-csrf']) if (req.headers[name]) headers[name] = req.headers[name];
    const body = req.method === 'POST' ? (typeof req.body === 'string' ? req.body : JSON.stringify(req.body)) : undefined;
    if (body && Buffer.byteLength(body) > 8192) return res.status(413).json({error:'Request too large.'});
    const response = await fetch(backend, {method:req.method, headers, body, redirect:'error', signal:AbortSignal.timeout(25000)});
    for (const name of ['content-type','content-disposition','x-content-type-options']) if (response.headers.has(name)) res.setHeader(name,response.headers.get(name));
    const cookies = response.headers.getSetCookie();
    if (cookies.length) res.setHeader('Set-Cookie',cookies);
    res.status(response.status).send(Buffer.from(await response.arrayBuffer()));
  } catch {
    res.status(502).json({error:'The assessment backend is unavailable. No scan result was produced by this request.'});
  }
}
