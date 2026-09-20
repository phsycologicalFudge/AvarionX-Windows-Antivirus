use crate::webview::{build_popup_webview, build_warm_webview};
use crate::{log_line, Detection, UserEvent};
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use tao::dpi::{LogicalPosition, LogicalSize, PhysicalPosition};
use tao::event_loop::{EventLoopProxy, EventLoopWindowTarget};
use tao::platform::windows::WindowBuilderExtWindows;
use tao::window::{Window, WindowBuilder, WindowId};
use windows::Win32::Foundation::RECT;
use windows::Win32::UI::WindowsAndMessaging::{
    SystemParametersInfoW, SPI_GETWORKAREA, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
};
use wry::WebView;

const CARD_WIDTH: f64 = 480.0;
const CARD_HEIGHT: f64 = 210.0;
const MARGIN: f64 = 16.0;
const GAP: f64 = 12.0;

fn work_area() -> RECT {
    let mut rect = RECT::default();
    unsafe {
        let _ = SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            Some(&mut rect as *mut _ as *mut _),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        );
    }
    rect
}

pub struct PopupManager {
    order: Vec<WindowId>,
    windows: HashMap<WindowId, (Window, WebView)>,
    queue: std::collections::VecDeque<Detection>,
    warm_webview: Option<(Window, WebView)>,
}

impl PopupManager {
    pub fn new() -> Self {
        Self {
            order: Vec::new(),
            windows: HashMap::new(),
            queue: std::collections::VecDeque::new(),
            warm_webview: None,
        }
    }

    pub fn warm_up(&mut self, target: &EventLoopWindowTarget<UserEvent>) {
        let window = match WindowBuilder::new()
            .with_inner_size(LogicalSize::new(1.0, 1.0))
            .with_position(LogicalPosition::new(-10000.0, -10000.0))
            .with_decorations(false)
            .with_visible(false)
            .with_skip_taskbar(true)
            .build(target)
        {
            Ok(w) => w,
            Err(e) => {
                log_line(&format!("warm-up window build failed: {:?}", e));
                return;
            }
        };
        match build_warm_webview(&window) {
            Ok(wv) => {
                log_line("webview2 environment warmed up");
                self.warm_webview = Some((window, wv));
            }
            Err(e) => {
                log_line(&format!("warm-up webview build failed: {:?}", e));
            }
        }
    }

    fn reflow(&self) {
        let area = work_area();
        for (i, id) in self.order.iter().enumerate() {
            if let Some((window, _)) = self.windows.get(id) {
                let scale = window.scale_factor();
                let card_w = CARD_WIDTH * scale;
                let card_h = CARD_HEIGHT * scale;
                let margin = MARGIN * scale;
                let gap = GAP * scale;
                let y = area.bottom as f64 - margin - (i as f64 + 1.0) * card_h - (i as f64) * gap;
                let x = area.right as f64 - margin - card_w;
                window.set_outer_position(PhysicalPosition::new(x.round() as i32, y.round() as i32));
            }
        }
    }

    pub fn add(&mut self, target: &EventLoopWindowTarget<UserEvent>, proxy: EventLoopProxy<UserEvent>, det: Detection) {
        if !self.order.is_empty() {
            self.queue.push_back(det);
            return;
        }
        self.show(target, proxy, det);
    }

    fn show(&mut self, target: &EventLoopWindowTarget<UserEvent>, proxy: EventLoopProxy<UserEvent>, det: Detection) {
        let window = match WindowBuilder::new()
            .with_inner_size(LogicalSize::new(CARD_WIDTH, CARD_HEIGHT))
            .with_position(PhysicalPosition::new(0, 0))
            .with_decorations(false)
            .with_always_on_top(true)
            .with_skip_taskbar(true)
            .with_resizable(false)
            .with_transparent(true)
            .with_visible(false)
            .with_focused(false)
            .build(target)
        {
            Ok(w) => w,
            Err(e) => {
                log_line(&format!("window build failed: {:?}", e));
                return;
            }
        };
        window.set_inner_size(LogicalSize::new(CARD_WIDTH, CARD_HEIGHT));
        let id = window.id();
        let fallback = proxy.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(1500));
            let _ = fallback.send_event(UserEvent::Reveal(id));
        });
        let webview = match build_popup_webview(&window, &det, proxy) {
            Ok(wv) => wv,
            Err(e) => {
                log_line(&format!("webview build failed: {:?}", e));
                return;
            }
        };
        self.order.push(id);
        self.windows.insert(id, (window, webview));
        self.reflow();
    }

    pub fn reveal(&self, id: WindowId) {
        if let Some((window, _)) = self.windows.get(&id) {
            if !window.is_visible() {
                self.reflow();
                window.set_visible(true);
                log_line("popup shown");
            }
        }
    }

    pub fn remove(&mut self, target: &EventLoopWindowTarget<UserEvent>, proxy: EventLoopProxy<UserEvent>, id: WindowId) {
        self.order.retain(|w| *w != id);
        self.windows.remove(&id);
        self.reflow();
        if self.order.is_empty() {
            if let Some(next) = self.queue.pop_front() {
                self.show(target, proxy, next);
            }
        }
    }
}
