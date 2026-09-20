use crate::pipe::send_command;
use crate::{Detection, UserEvent};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use tao::event_loop::EventLoopProxy;
use tao::window::Window;
use wry::{WebView, WebViewBuilder};

const ACCENT: &str = "#0135DE";
const ICON_PNG: &[u8] = include_bytes!("../../assets/icon.png");
const TEMPLATE: &str = include_str!("../../assets/notify.html");

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn escape_js(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

fn icon_data_uri() -> String {
    format!("data:image/png;base64,{}", STANDARD.encode(ICON_PNG))
}

fn truncate_name(name: &str) -> String {
    let char_count = name.chars().count();
    if char_count <= 10 {
        return name.to_string();
    }
    let head: String = name.chars().take(10).collect();
    match name.rfind('.') {
        Some(idx) if idx > 0 && idx < name.len() - 1 => {
            let ext = &name[idx + 1..];
            format!("{}...{}", head, ext)
        }
        _ => format!("{}...", head),
    }
}

fn render(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + 2048);
    let mut rest = template;
    'outer: while !rest.is_empty() {
        for (key, value) in vars {
            if let Some(tail) = rest.strip_prefix(*key) {
                out.push_str(value);
                rest = tail;
                continue 'outer;
            }
        }
        let ch = rest.chars().next().unwrap();
        out.push(ch);
        rest = &rest[ch.len_utf8()..];
    }
    out
}

fn build_html(det: &Detection) -> String {
    let action_html = match &det.quarantine_id {
        Some(id) => format!(
            r#"<button class="btn" onclick="send('restore:{id}')">Restore</button><span class="link" onclick="send('details:{exe_js}')">View Details</span>"#,
            id = escape_js(id),
            exe_js = escape_js(&det.exe),
        ),
        None => format!(
            r#"<span class="link" onclick="send('details:{exe_js}')">View Details</span>"#,
            exe_js = escape_js(&det.exe),
        ),
    };
    let title = if det.quarantine_id.is_some() {
        "Threat quarantined"
    } else {
        "Threat blocked"
    };
    let icon = icon_data_uri();
    let name = escape_html(&truncate_name(&det.name));
    let exe = escape_html(&det.exe);
    render(
        TEMPLATE,
        &[
            ("__ACCENT__", ACCENT),
            ("__ICON__", icon.as_str()),
            ("__TITLE__", title),
            ("__NAME__", name.as_str()),
            ("__EXE__", exe.as_str()),
            ("__ACTIONS__", action_html.as_str()),
        ],
    )
}

pub fn build_warm_webview(window: &Window) -> wry::Result<WebView> {
    WebViewBuilder::new().with_html("<html></html>").build(window)
}

pub fn build_popup_webview(
    window: &Window,
    det: &Detection,
    proxy: EventLoopProxy<UserEvent>,
) -> wry::Result<WebView> {
    let id = window.id();
    WebViewBuilder::new()
        .with_transparent(true)
        .with_html(build_html(det))
        .with_ipc_handler(move |req: wry::http::Request<String>| {
            let msg = req.body().as_str();
            if msg == "ready" {
                let _ = proxy.send_event(UserEvent::Reveal(id));
            } else if msg == "dismiss" {
                let _ = proxy.send_event(UserEvent::Close(id));
            } else if let Some(qid) = msg.strip_prefix("restore:") {
                send_command(&format!("restore:{}", qid));
                let _ = proxy.send_event(UserEvent::Close(id));
            } else if let Some(path) = msg.strip_prefix("details:") {
                println!("details requested: {}", path);
                let _ = proxy.send_event(UserEvent::Close(id));
            }
        })
        .build(window)
}
