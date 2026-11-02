import html
import json
import secrets

from starlette.responses import HTMLResponse


def approval_page(flow: dict, flow_id: str) -> HTMLResponse:
    data = json.loads(flow["data"])
    client = html.escape(data["client_name"])
    code = html.escape(flow["approval_code"])
    nonce = secrets.token_urlsafe(20)
    content = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect Discord history — Discord History MCP</title>
<style nonce="NONCE">
:root{color-scheme:light;font-family:'Hiragino Kaku Gothic ProN','Yu Gothic',sans-serif;color:#17254a;background:#f7f8fc}
*{box-sizing:border-box}body{margin:0}main{max-width:660px;margin:8vh auto;padding:28px}
header{color:#4353c6;font-weight:700;margin-bottom:32px}h1{font-size:clamp(25px,5vw,34px);line-height:1.4;margin:0 0 20px}
p,li{font-size:15px;line-height:1.9}small{color:#606a80;line-height:1.8}section{margin-top:30px}
.command{border:1px solid #dfe3ed;background:#fff;padding:20px;overflow-wrap:anywhere}
code{font:16px ui-monospace,monospace}.copy{margin-top:16px}button{font:inherit;font-weight:600;padding:11px 18px;background:#5865f2;color:white;border:0;border-radius:5px;cursor:pointer}
button:focus-visible{outline:3px solid #17254a;outline-offset:3px}.status{border-top:1px solid #dfe3ed;margin-top:28px;padding-top:18px;color:#606a80}
.error{color:#8a4b1c}ul{padding-left:22px}a{color:#4353c6}@media(max-width:540px){main{margin-top:20px;padding:24px}}
</style><main><header>Discord History MCP</header><h1>Connect your Discord history</h1>
<p><strong>CLIENT</strong> is requesting a connection.</p>
<section><p>Run this command in the Discord server you want to connect.</p>
<div class="command"><code id="command">/mcp code:CODE</code><br><button class="copy" id="copy">Copy command</button></div>
<p>Check the client and callback in the bot’s private reply, then choose “Allow history access”. Keep this page open.</p></section>
<section><ul><li>Only text history readable by both you and the bot can be retrieved.</li>
<li>The MCP client cannot send, edit or delete messages.</li><li>Permission lasts 30 days. Revoke it in Discord with <code>/mcp action:revoke</code>.</li></ul></section>
<p class="status" id="status" role="status" aria-live="polite">Waiting for approval in Discord. This code expires after 10 minutes.</p>
<small>Approve only a connection you started and recognize. Otherwise, close this tab.</small></main>
<script nonce="NONCE">
document.getElementById('copy').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(document.getElementById('command').textContent);document.getElementById('copy').textContent='Copied'}catch{document.getElementById('copy').textContent='Select and copy the command above'}});
let stopped=false;async function poll(){if(stopped)return;try{const response=await fetch(STATUS_URL,{cache:'no-store'});if(!response.ok)throw new Error();const data=await response.json();
if(data.redirect_url&&['approved','denied'].includes(data.status)){stopped=true;document.getElementById('status').textContent=data.status==='approved'?'Approved. Returning to your client…':'Denied. Returning to your client…';window.location.replace(data.redirect_url);return}
if(['expired','denied','consumed'].includes(data.status)){stopped=true;const node=document.getElementById('status');node.classList.add('error');node.textContent=data.status==='denied'?'This connection was denied.':'This request has ended. Start again in your MCP client.';return}
}catch{document.getElementById('status').textContent='Checking the connection…'}setTimeout(poll,2000)}poll();
</script></html>"""
    # Replace code placeholders first; untrusted client names are HTML-escaped last.
    content = content.replace("NONCE", nonce).replace("CODE", code)
    content = content.replace("STATUS_URL", json.dumps(f"/connect/{flow_id}/status"))
    content = content.replace("CLIENT", client)
    return HTMLResponse(
        content,
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": f"default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        },
    )
