// =============================================================================
// web/pages.rs — server-rendered HTML for the management GUI
//
// Minimal, dependency-free templating: each function returns a full HTML string
// built around a shared dark-themed layout. No external template engine or JS
// framework — keeps the binary self-contained (per the design brief).
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// escape
// Escape the five HTML-significant characters for safe interpolation.
// ─────────────────────────────────────────────────────────────────────────────
pub fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Shared CSS for every page.
const STYLE: &str = "\
:root{color-scheme:dark}\
*{box-sizing:border-box}\
body{margin:0;font:15px/1.5 system-ui,sans-serif;background:#0e1116;color:#e6edf3}\
header{display:flex;align-items:center;justify-content:space-between;\
padding:14px 22px;background:#161b22;border-bottom:1px solid #30363d}\
header .brand{font-weight:700;letter-spacing:.3px}\
header .brand span{color:#3fb950}\
main{max-width:880px;margin:40px auto;padding:0 22px}\
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;margin-bottom:20px}\
h1{font-size:22px;margin:0 0 6px}\
h2{font-size:16px;margin:0 0 14px;color:#9da7b3}\
label{display:block;margin:14px 0 6px;font-size:13px;color:#9da7b3}\
input{width:100%;padding:10px 12px;border:1px solid #30363d;border-radius:7px;\
background:#0e1116;color:#e6edf3;font-size:14px}\
button{margin-top:18px;padding:10px 18px;border:0;border-radius:7px;\
background:#238636;color:#fff;font-weight:600;cursor:pointer;font-size:14px}\
button:hover{background:#2ea043}\
button.link{background:none;color:#58a6ff;padding:0;margin:0;font-weight:400}\
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}\
.err{background:#3d1a1d;border:1px solid #f85149;color:#ffa198;padding:10px 12px;\
border-radius:7px;margin-bottom:8px;font-size:14px}\
.muted{color:#7d8590;font-size:13px}\
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600}\
.pill.ok{background:#132e1a;color:#3fb950;border:1px solid #238636}\
.pill.warn{background:#3d2a12;color:#d29922;border:1px solid #9e6a03}\
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}\
.kv{padding:12px 14px;background:#0e1116;border:1px solid #30363d;border-radius:8px}\
.kv .k{font-size:12px;color:#7d8590}.kv .v{font-size:15px;margin-top:2px}";

// ─────────────────────────────────────────────────────────────────────────────
// layout
// Wrap page `body` in the shared shell; `user` adds the header + logout control.
// ─────────────────────────────────────────────────────────────────────────────
pub fn layout(title: &str, user: Option<&str>, body: &str) -> String {
    let header_right = match user {
        Some(name) => format!(
            "<form method=\"post\" action=\"/gui/logout\" style=\"margin:0\">\
             <span class=\"muted\">{}</span> &nbsp;\
             <button class=\"link\" type=\"submit\">Log out</button></form>",
            escape(name)
        ),
        None => String::new(),
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{} · EasyVault</title><style>{}</style></head><body>\
         <header><div class=\"brand\">Easy<span>Vault</span></div><div>{}</div></header>\
         <main>{}</main></body></html>",
        escape(title),
        STYLE,
        header_right,
        body
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// setup_page
// First-run page to create the initial master user.
// ─────────────────────────────────────────────────────────────────────────────
pub fn setup_page(error: Option<&str>) -> String {
    let err = error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();
    let body = format!(
        "<div class=\"card\"><h1>Welcome to EasyVault</h1>\
         <h2>Create the master account</h2>{err}\
         <form method=\"post\" action=\"/gui/setup\">\
         <label>Username</label><input name=\"username\" autofocus required>\
         <label>Password</label><input name=\"password\" type=\"password\" required>\
         <p class=\"muted\">At least 8 characters. This account manages all users and vaults.</p>\
         <button type=\"submit\">Create master account</button></form></div>"
    );
    layout("Setup", None, &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// login_page
// Username + password login form.
// ─────────────────────────────────────────────────────────────────────────────
pub fn login_page(error: Option<&str>) -> String {
    let err = error.map(|e| format!("<div class=\"err\">{}</div>", escape(e))).unwrap_or_default();
    let body = format!(
        "<div class=\"card\"><h1>Sign in</h1>{err}\
         <form method=\"post\" action=\"/gui/login\">\
         <label>Username</label><input name=\"username\" autofocus required>\
         <label>Password</label><input name=\"password\" type=\"password\" required>\
         <button type=\"submit\">Sign in</button></form></div>"
    );
    layout("Sign in", None, &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// dashboard_page
// Authenticated landing: identity, instance seal state, and a vault summary.
// ─────────────────────────────────────────────────────────────────────────────
pub fn dashboard_page(username: &str, is_master: bool, sealed: bool, vault_count: i64) -> String {
    let role = if is_master {
        "<span class=\"pill ok\">master</span>"
    } else {
        "<span class=\"pill warn\">user</span>"
    };
    let seal = if sealed {
        "<span class=\"pill warn\">sealed</span>"
    } else {
        "<span class=\"pill ok\">unsealed</span>"
    };
    let seal_note = if sealed {
        "<p class=\"muted\">The instance is sealed — secret operations are blocked until \
         it is unsealed via <code>/v1/sys/unseal</code>.</p>"
    } else {
        ""
    };
    let body = format!(
        "<div class=\"card\"><h1>Dashboard</h1>\
         <h2>Signed in as {user} {role}</h2>\
         <div class=\"grid\">\
         <div class=\"kv\"><div class=\"k\">Instance</div><div class=\"v\">{seal}</div></div>\
         <div class=\"kv\"><div class=\"k\">Vaults</div><div class=\"v\">{vaults}</div></div>\
         </div>{seal_note}</div>\
         <div class=\"card\"><h2>Vaults</h2>\
         <p class=\"muted\">Vault management arrives in the next increment.</p></div>",
        user = escape(username),
        role = role,
        seal = seal,
        vaults = vault_count,
        seal_note = seal_note
    );
    layout("Dashboard", Some(username), &body)
}
