const cfg = window.MADINA_CONFIG || {API_BASE_URL:"http://localhost:4000/api"};
async function api(path, options={}) {
  const res = await fetch(cfg.API_BASE_URL + path, {
    credentials:"include",
    headers:{"Content-Type":"application/json",...(options.headers||{})},
    ...options
  });
  const data = await res.json().catch(()=>({}));
  if(!res.ok) throw new Error(data.error || "Request failed");
  return data;
}
function qs(s){return document.querySelector(s)}
function money(n){return new Intl.NumberFormat("en-NG",{style:"currency",currency:"NGN",maximumFractionDigits:0}).format(n||0)}
