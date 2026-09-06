"""Shared, script-free presentation for the authenticated operator workspace."""

from __future__ import annotations

import base64
import hashlib
from html import escape

STYLES = """
:root{
color-scheme:light;
--ink:#172b4d;
--muted:#67768e;
--line:#e5eaf1;
--blue:#2563eb;
--nav:#12233f}

*{
box-sizing:border-box}
body{
margin:0;
background:#f4f6fa;
color:var(--ink);
font:14px/1.5 system-ui,-apple-system,BlinkMacSystemFont,
"Segoe UI",sans-serif}

a{
color:var(--blue);
text-decoration:none}
a:hover{
text-decoration:underline}
a:focus-visible{
outline:3px solid #78aaff;
outline-offset:4px;
border-radius:3px}

.skip{
position:absolute;
left:16px;
top:-70px;
background:white;
padding:12px;
z-index:9}
.skip:focus{
top:12px}

.sidebar{
position:fixed;
inset:0 auto 0 0;
width:224px;
background:var(--nav);
color:#dce6f7;
display:flex;
flex-direction:column;
padding:30px 20px}

.brand{
display:flex;
align-items:center;
gap:12px;
color:white;
font-size:19px;
font-weight:700;
letter-spacing:-.5px}
.brand-mark{
display:grid;
place-items:center;
width:38px;
height:38px;
background:#3477f5;
border-radius:10px;
font-size:13px;
letter-spacing:1px}

.brand small{
display:block;
font-size:10px;
color:#9aafcf;
letter-spacing:2px;
font-weight:500}
.nav-label{
margin:44px 12px 12px;
color:#91a5c6;
font-size:10px;
letter-spacing:1.7px;
font-weight:600}

.nav-link{
display:flex;
align-items:center;
gap:12px;
padding:12px;
border-radius:7px;
background:#234371;
color:white;
font-weight:600}
.nav-link span{
font-size:19px}
.side-bottom{
margin-top:auto;
border-top:1px solid #31425d;
padding:20px 10px 0;
color:#a5b5ce;
font-size:12px}
.side-bottom strong{
display:block;
color:#e2eaf7;
font-weight:500;
margin-bottom:4px}

.workspace{
margin-left:224px}
.topbar{
height:76px;
padding:0 40px;
background:white;
border-bottom:1px solid var(--line);
display:flex;
align-items:center;
justify-content:space-between;
gap:16px}
.breadcrumb{
font-size:13px;
color:var(--muted)}
.breadcrumb span{
padding:0 12px;
color:#bcc5d2}
.account{
display:flex;
align-items:center;
gap:11px}
.avatar{
width:34px;
height:34px;
background:#eaf0fc;
color:#3563a5;
border-radius:50%;
display:grid;
place-items:center;
font-weight:700;
font-size:12px}
.account strong{
font-size:12px;
display:block}
.account small{
display:block;
color:var(--muted);
font-size:11px}
.signout{
font-size:12px;
margin-left:16px;
color:var(--muted)}

main{
max-width:1560px;
margin:auto;
padding:34px 40px 40px}
.page-heading{
display:flex;
justify-content:space-between;
align-items:center;
gap:20px;
margin-bottom:28px}
.eyebrow{
text-transform:uppercase;
letter-spacing:1.7px;
font-size:10px;
color:#70819b;
font-weight:700;
margin-bottom:7px}
h1{
font-size:29px;
letter-spacing:-.8px;
line-height:1.2;
margin:0 0 9px;
font-weight:650;
overflow-wrap:anywhere}
h2{
font-size:16px;
margin:0;
font-weight:650}
.description{
color:var(--muted);
margin:0;
font-size:13px}
.button{
display:inline-flex;
align-items:center;
justify-content:center;
white-space:nowrap;
border:1px solid var(--line);
background:white;
border-radius:7px;
padding:9px 15px;
font-size:12px;
font-weight:600;
color:#344864;
box-shadow:0 1px 2px #172b4d05}
.button:hover{
background:#edf3ff;
text-decoration:none;
border-color:#b8cdf8}

.metrics{
display:grid;
grid-template-columns:repeat(4,minmax(0,1fr));
gap:18px;
margin-bottom:28px}
.metric{
padding:22px;
background:white;
border:1px solid var(--line);
border-radius:10px;
box-shadow:0 2px 3px #172b4d02}
.metric-top{
display:flex;
align-items:center;
justify-content:space-between;
color:#67768e;
font-size:12px;
font-weight:500}
.metric-icon{
height:29px;
width:29px;
display:grid;
place-items:center;
background:#eef3fc;
border-radius:7px;
color:#5274aa}
.metric strong{
display:block;
font-size:30px;
letter-spacing:-1px;
margin:8px 0 3px;
font-weight:650}
.metric small{
font-size:11px;
color:var(--muted)}
.metric.online .metric-icon{
background:#e9f7f0;
color:#22845a}
.metric.stale .metric-icon{
background:#fff5df;
color:#a77916}
.metric.offline .metric-icon{
background:#f0f2f6;
color:#7a8494}

.panel{
background:white;
border:1px solid var(--line);
border-radius:10px;
overflow:hidden;
box-shadow:0 2px 3px #172b4d02}
.panel-heading{
padding:21px 24px;
display:flex;
justify-content:space-between;
align-items:center;
gap:16px;
border-bottom:1px solid var(--line)}
.panel-heading p{
margin:4px 0 0;
font-size:12px;
color:var(--muted)}
.count{
font-size:11px;
padding:3px 8px;
border-radius:5px;
background:#eef3fb;
color:#557296;
margin-left:8px;
white-space:nowrap}
.table-scroll{
overflow-x:auto}
table{
border-collapse:collapse;
width:100%;
text-align:left;
white-space:nowrap}
th{
padding:13px 22px;
font-size:10px;
text-transform:uppercase;
letter-spacing:.8px;
background:#fafbfd;
color:#76859c;
font-weight:600;
border-bottom:1px solid var(--line)}
td{
padding:19px 22px;
border-bottom:1px solid #edf0f5;
font-size:12px}
tr:last-child td{
border-bottom:0}
tbody tr:hover{
background:#f8faff}
.device{
display:flex;
align-items:center;
gap:12px}
.device-icon{
width:35px;
height:35px;
border:1px solid #e1e8f2;
border-radius:8px;
display:grid;
place-items:center;
background:#f7f9fd;
color:#617998;
font-size:17px}
.device a{
font-weight:650;
color:#263e60;
font-size:13px}
.device small{
display:block;
color:#8693a6;
font-size:10px;
margin-top:2px}
.badge{
display:inline-flex;
align-items:center;
gap:6px;
padding:4px 9px;
border-radius:5px;
background:#f0f3f7;
color:#67768e;
font-size:11px;
text-transform:capitalize;
font-weight:500}
.badge.online,.badge.active{
background:#eaf7f0;
color:#26734c}
.badge.stale{
background:#fff5df;
color:#94660b}
.badge.revoked{
background:#fff0ef;
color:#a84242}
.dot{
width:5px;
height:5px;
border-radius:50%;
background:currentColor}
.secondary{
color:var(--muted)}
.table-footer{
display:flex;
align-items:center;
justify-content:space-between;
gap:16px;
padding:16px 24px;
border-top:1px solid var(--line);
color:var(--muted);
font-size:11px}
.empty{
text-align:center;
padding:60px 20px;
color:var(--muted)}
.empty strong{
display:block;
color:var(--ink);
font-size:16px;
margin-bottom:6px}

.detail-grid{
display:grid;
grid-template-columns:minmax(0,1.5fr) minmax(280px,1fr);
gap:24px;
align-items:start}
.detail-grid .panel{
margin-bottom:24px}
.facts{
display:grid;
grid-template-columns:145px minmax(0,1fr);
margin:0;
padding:9px 24px}
dt,dd{
margin:0;
padding:13px 0;
border-bottom:1px solid #edf0f5;
font-size:12px}
dt{
color:var(--muted)}
dd{
overflow-wrap:anywhere}
dt:last-of-type,dd:last-of-type{
border-bottom:0}
.status-strip{
display:flex;
gap:10px;
margin-top:14px}
.note{
padding:20px 24px;
font-size:12px;
color:var(--muted);
margin:0}
.page-footer{
margin-top:22px;
display:flex;
justify-content:space-between;
font-size:10px;
color:#8995a7;
gap:15px}
.back{
font-size:12px;
display:inline-block;
margin-bottom:18px}
time{
white-space:nowrap}

@media(min-width:1600px){
main{
padding-top:44px}
.metric{
padding:26px}
}

@media(max-width:1100px){
.sidebar{
width:190px}
.workspace{
margin-left:190px}
main{
padding:26px 24px}
.topbar{
padding:0 24px}
.metrics{
gap:12px}
.metric{
padding:17px}
.detail-grid{
grid-template-columns:1fr}
}

@media(max-width:760px){
.sidebar{
position:static;
width:auto;
padding:16px 20px;
flex-direction:row;
align-items:center;
justify-content:space-between;
gap:18px}
.brand{
font-size:16px}
.brand small,.nav-label,.side-bottom{
display:none}
.nav-link{
padding:8px 12px;
font-size:12px}
.workspace{
margin-left:0}
.topbar{
height:62px;
padding:0 20px}
.account small,.signout{
display:none}
main{
padding:24px 16px}
.metrics{
grid-template-columns:repeat(2,minmax(0,1fr));
gap:12px}
h1{
font-size:25px}
.page-heading{
align-items:flex-start}
.metric strong{
font-size:27px}
.panel-heading{
padding:18px}
.facts{
padding:8px 18px;
grid-template-columns:120px minmax(0,1fr)}
.page-footer{
flex-direction:column;
gap:3px}
}

@media(prefers-reduced-motion:reduce){
*{
scroll-behavior:auto}
}

"""

STYLE_SOURCE = (
    "'sha256-"
    + base64.b64encode(hashlib.sha256(STYLES.encode()).digest()).decode()
    + "'"
)


def document(title: str, content: str, *, updated: str) -> str:
    """Wrap trusted markup; every interpolated label is escaped here."""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{escape(title)} — NorthGate RMM</title><style>{STYLES}</style></head>"
        '<body><a class="skip" href="#main">Skip to content</a>'
        '<aside class="sidebar"><a class="brand" href="/endpoints">'
        '<span class="brand-mark">NG</span><span>NorthGate<small>'
        "OPERATIONS</small></span></a>"
        '<div><p class="nav-label">WORKSPACE</p><nav aria-label="Main navigation">'
        '<a class="nav-link" href="/endpoints" aria-current="page">'
        '<span aria-hidden="true">▦</span> Endpoints</a></nav></div>'
        '<div class="side-bottom"><strong>NorthGate RMM</strong>Endpoint '
        "monitoring</div></aside>"
        '<div class="workspace"><header class="topbar"><div class="breadcrumb">'
        'Workspace<span>/</span>Endpoints</div><div class="account">'
        '<span class="avatar" aria-hidden="true">OP</span>'
        "<div><strong>Operator</strong><small>Viewer access</small></div>"
        '<a class="signout" href="/oauth2/sign_out">Sign out</a></div></header>'
        f'<main id="main">{content}<footer class="page-footer">'
        f"<span>NorthGate · Endpoint workspace</span><span>Updated "
        f"{escape(updated)}</span>"
        "</footer></main></div></body></html>"
    )
