//! Browser page served by the OAuth loopback listener after the redirect lands.

/// Which outcome the callback page reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallbackPageKind {
    Success,
    Failure,
}

const PAGE_TEMPLATE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{title}} · AionUi</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--text:#1d2129;--muted:#6b7280;--border:#e5e7eb;--accent:#16a34a;--accent-soft:#dcfce7;color-scheme:light}
.failure{--accent:#dc2626;--accent-soft:#fee2e2}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b21;--text:#e5e7eb;--muted:#9ca3af;--border:#2a2e36;--accent-soft:rgba(22,163,74,.16);color-scheme:dark}.failure{--accent-soft:rgba(220,38,38,.16)}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:var(--bg);color:var(--text);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
.card{width:100%;max-width:420px;padding:40px 32px 32px;text-align:center;background:var(--card);border:1px solid var(--border);border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.06);animation:rise .4s ease-out both}
.icon{width:64px;height:64px;margin:0 auto 20px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:var(--accent-soft);color:var(--accent)}
.icon svg{width:32px;height:32px}
.icon path{stroke-dasharray:40;stroke-dashoffset:40;animation:draw .5s .25s ease-out forwards}
h1{margin:0 0 8px;font-size:20px;font-weight:600}
p{margin:0;color:var(--muted)}
.brand{margin-top:28px;padding-top:16px;border-top:1px solid var(--border);font-size:12px;color:var(--muted);letter-spacing:.04em}
@keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@keyframes draw{to{stroke-dashoffset:0}}
@media (prefers-reduced-motion:reduce){.card,.icon path{animation:none;stroke-dashoffset:0}}
</style>
</head>
<body class="{{kind}}">
<main class="card">
<div class="icon">{{icon}}</div>
<h1>{{title}}</h1>
<p>{{message}}</p>
<div class="brand">AionUi · MCP OAuth</div>
</main>
</body>
</html>"#;

const ICON_SUCCESS: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>"#;
const ICON_FAILURE: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M7 7l10 10M17 7L7 17"/></svg>"#;

/// Render the full HTML document for a callback outcome.
///
/// All substituted text is static; request data never reaches the page.
pub(crate) fn render_callback_page(kind: CallbackPageKind) -> String {
    let (class, icon, title, message) = match kind {
        CallbackPageKind::Success => (
            "success",
            ICON_SUCCESS,
            "Authorization successful",
            "Your MCP server is now connected. You can close this window and return to AionUi.",
        ),
        CallbackPageKind::Failure => (
            "failure",
            ICON_FAILURE,
            "Authorization failed",
            "The authorization was not completed. Return to AionUi for details.",
        ),
    };
    PAGE_TEMPLATE
        .replace("{{kind}}", class)
        .replace("{{icon}}", icon)
        .replace("{{title}}", title)
        .replace("{{message}}", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_page_is_complete_document() {
        let page = render_callback_page(CallbackPageKind::Success);
        assert!(page.starts_with("<!doctype html>"));
        assert!(page.contains(r#"<body class="success">"#));
        assert!(page.contains("<h1>Authorization successful</h1>"));
        assert!(page.contains(ICON_SUCCESS));
        assert!(!page.contains("{{"));
    }

    #[test]
    fn failure_page_uses_failure_variant() {
        let page = render_callback_page(CallbackPageKind::Failure);
        assert!(page.contains(r#"<body class="failure">"#));
        assert!(page.contains("<h1>Authorization failed</h1>"));
        assert!(page.contains(ICON_FAILURE));
        assert!(!page.contains("{{"));
    }
}
