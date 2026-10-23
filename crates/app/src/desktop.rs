#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui::{self, Color32, RichText, Vec2};
use std::{
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};
use vasp::{engine, store::Store};
use vasp_core::protocol::*;

const INK: Color32 = Color32::from_rgb(24, 49, 73);
const PAPER: Color32 = Color32::from_rgb(243, 247, 250);
const TEAL: Color32 = Color32::from_rgb(8, 127, 140);
const AMBER: Color32 = Color32::from_rgb(146, 85, 0);
const RED: Color32 = Color32::from_rgb(179, 48, 63);
const MUTED: Color32 = Color32::from_rgb(91, 112, 130);

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Overview,
    Findings,
    Devices,
    Research,
    Activity,
    Settings,
}
enum Action {
    BrokerStatus,
    RemoveBlocks,
    Scan,
    Feeds,
    Tick,
    Analyze,
    Stop,
    Refresh,
    Configure(engine::Config),
}
#[derive(Default)]
struct Snapshot {
    devices: Vec<Observation>,
    findings: Vec<Finding>,
    schedules: Vec<(String, vasp_core::scheduler::Schedule)>,
    activity: Vec<(u64, String)>,
    reports: Vec<String>,
    config: engine::Config,
}
struct Update {
    snapshot: Option<Snapshot>,
    message: String,
    error: bool,
}
struct Console {
    page: Page,
    snapshot: Snapshot,
    tx: mpsc::Sender<Action>,
    rx: mpsc::Receiver<Update>,
    busy: bool,
    message: String,
    error: bool,
    last_tick: Instant,
    selected: Option<String>,
    query: String,
    config_json: String,
    tray: Option<tray_icon::TrayIcon>,
    quitting: bool,
    screenshot: Option<PathBuf>,
    capture_sent: bool,
}

fn tray() -> Option<tray_icon::TrayIcon> {
    use tray_icon::{
        Icon, TrayIconBuilder,
        menu::{Menu, MenuItem},
    };
    let menu = Menu::new();
    let show = MenuItem::with_id("show", "Open VASP", true, None);
    let scan = MenuItem::with_id("scan", "Scan this PC", true, None);
    let stop = MenuItem::with_id("stop", "Disable automatic actions", true, None);
    let quit = MenuItem::with_id("quit", "Quit VASP", true, None);
    menu.append_items(&[&show, &scan, &stop, &quit]).ok()?;
    let mut rgba = vec![0u8; 32 * 32 * 4];
    for y in 0..32 {
        for x in 0..32 {
            let dx = x as f32 - 15.5;
            let dy = y as f32 - 15.5;
            let distance = (dx * dx + dy * dy).sqrt();
            let color = if (9.0..12.0).contains(&distance) {
                [8, 127, 140, 255]
            } else if distance < 4.0 {
                [24, 49, 73, 255]
            } else {
                [0, 0, 0, 0]
            };
            rgba[(y * 32 + x) * 4..(y * 32 + x + 1) * 4].copy_from_slice(&color);
        }
    }
    TrayIconBuilder::new()
        .with_tooltip("VASP — observe only")
        .with_menu(Box::new(menu))
        .with_icon(Icon::from_rgba(rgba, 32, 32).ok()?)
        .build()
        .ok()
}

fn main() -> eframe::Result {
    let mut args = std::env::args().skip(1);
    let mut data = PathBuf::from("data");
    let mut screenshot = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data" => {
                if let Some(path) = args.next() {
                    data = path.into();
                }
            }
            "--smoke-screenshot" => screenshot = args.next().map(PathBuf::from),
            _ => {}
        }
    }
    let mut setup = eframe::egui_wgpu::WgpuSetupCreateNew::default();
    setup.instance_descriptor.backends = wgpu::Backends::DX12;
    setup.power_preference = wgpu::PowerPreference::LowPower;
    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Wgpu,
        wgpu_options: eframe::egui_wgpu::WgpuConfiguration {
            present_mode: wgpu::PresentMode::Fifo,
            wgpu_setup: setup.into(),
            ..Default::default()
        },
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 790.0])
            .with_min_inner_size([850.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "VASP | Local security",
        options,
        Box::new(move |cc| {
            let mut console = Console::new(cc, data);
            console.screenshot = screenshot;
            Ok(Box::new(console))
        }),
    )
}
impl Console {
    fn new(cc: &eframe::CreationContext<'_>, data: PathBuf) -> Self {
        let mut style = (*cc.egui_ctx.style()).clone();
        style.visuals = egui::Visuals::light();
        style.visuals.panel_fill = PAPER;
        style.visuals.window_fill = Color32::WHITE;
        style.visuals.override_text_color = Some(INK);
        style.visuals.selection.bg_fill = TEAL;
        style.visuals.selection.stroke.color = Color32::WHITE;
        style.spacing.item_spacing = Vec2::new(12.0, 10.0);
        style.spacing.button_padding = Vec2::new(14.0, 9.0);
        style
            .text_styles
            .insert(egui::TextStyle::Heading, egui::FontId::proportional(28.0));
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(15.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
        cc.egui_ctx.set_style(style);
        let mut fonts = egui::FontDefinitions::default();
        if let Ok(bytes) = std::fs::read("C:\\Windows\\Fonts\\segoeui.ttf") {
            fonts
                .font_data
                .insert("Segoe".into(), egui::FontData::from_owned(bytes).into());
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "Segoe".into());
        }
        cc.egui_ctx.set_fonts(fonts);
        let (tx, commands) = mpsc::channel();
        let (updates, rx) = mpsc::channel();
        let ctx = cc.egui_ctx.clone();
        std::thread::spawn(move || {
            let mut store = match Store::open(&data) {
                Ok(s) => s,
                Err(e) => {
                    let _ = updates.send(Update {
                        snapshot: None,
                        message: format!("Cannot open protected local storage: {e}"),
                        error: true,
                    });
                    ctx.request_repaint();
                    return;
                }
            };
            for action in commands {
                let result: anyhow::Result<String> = (|| match action {
                    Action::BrokerStatus => Ok(vasp::broker::request(
                        vasp_core::broker::Command::Status {},
                        store.device_id()?,
                    )?
                    .reason),
                    Action::RemoveBlocks => Ok(vasp::broker::request(
                        vasp_core::broker::Command::RemoveTemporaryBlocks {},
                        store.device_id()?,
                    )?
                    .reason),
                    Action::Scan => {
                        let count = engine::scan(&mut store)?;
                        Ok(format!("Observation saved. {count} findings to review."))
                    }
                    Action::Feeds => {
                        engine::refresh(&mut store, true)?;
                        Ok("Research refresh finished. Check source health for failures.".into())
                    }
                    Action::Tick => {
                        engine::tick(&mut store)?;
                        Ok("Scheduled checks finished.".into())
                    }
                    Action::Analyze => {
                        let c = engine::config(&store)?;
                        vasp::models::analyze(&mut store, &c.model)?;
                        Ok("Advisory analysis saved. No system changes were made.".into())
                    }
                    Action::Stop => {
                        let id = store.device_id()?;
                        store.set(
                            "local_policy",
                            &vasp_core::policy::LocalPolicy::observe_only(id),
                        )?;
                        store.audit("automatic-actions-disabled-locally")?;
                        let broker = vasp::broker::request(
                            vasp_core::broker::Command::StopAutomaticActions {},
                            id,
                        );
                        Ok(match broker { Ok(r) => r.reason, Err(_) => "Local automatic actions disabled. Broker unavailable; this preview cannot create blocks.".into() })
                    }
                    Action::Refresh => Ok("Local state loaded.".into()),
                    Action::Configure(c) => {
                        if c.schema != 1 {
                            anyhow::bail!("Unsupported configuration version");
                        }
                        store.set("config", &c)?;
                        store.audit("configuration-updated-locally")?;
                        Ok("Configuration saved. Existing credentials remain in Windows Credential Manager.".into())
                    }
                })();
                let snapshot = (|| -> anyhow::Result<Snapshot> {
                    let mut q = store
                        .conn
                        .prepare("SELECT json FROM reports ORDER BY at DESC LIMIT 10")?;
                    let reports = q
                        .query_map([], |r| r.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(Snapshot {
                        devices: store.devices()?,
                        findings: store.findings()?,
                        schedules: store.schedules()?,
                        activity: store.audit_tail()?,
                        reports,
                        config: engine::config(&store)?,
                    })
                })();
                let update = match (result, snapshot) {
                    (Ok(message), Ok(s)) => Update {
                        snapshot: Some(s),
                        message,
                        error: false,
                    },
                    (Err(e), s) => Update {
                        snapshot: s.ok(),
                        message: e.to_string(),
                        error: true,
                    },
                    (_, Err(e)) => Update {
                        snapshot: None,
                        message: e.to_string(),
                        error: true,
                    },
                };
                if updates.send(update).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        });
        let _ = tx.send(Action::Refresh);
        Self {
            page: Page::Overview,
            snapshot: Snapshot::default(),
            tx,
            rx,
            busy: true,
            message: "Opening local security state…".into(),
            error: false,
            last_tick: Instant::now() - Duration::from_secs(30),
            selected: None,
            query: String::new(),
            config_json: String::new(),
            tray: tray(),
            quitting: false,
            screenshot: None,
            capture_sent: false,
        }
    }
    fn action(&mut self, action: Action) {
        if self.busy {
            return;
        }
        if self.tx.send(action).is_ok() {
            self.busy = true;
            self.message = "Working locally…".into();
            self.error = false;
        }
    }
    fn heading(ui: &mut egui::Ui, title: &str, description: &str) {
        ui.heading(title);
        ui.label(RichText::new(description).color(MUTED));
        ui.add_space(18.0);
    }
    fn overview(&mut self, ui: &mut egui::Ui) {
        Self::heading(
            ui,
            "Your security picture",
            "Evidence from your devices, with the limits kept in view.",
        );
        egui::Frame::new().fill(INK).inner_margin(24.0).corner_radius(10.0).show(ui,|ui|{
            ui.horizontal(|ui|{let(rect,_)=ui.allocate_exact_size(Vec2::splat(104.0),egui::Sense::hover());let p=ui.painter();let c=rect.center();p.circle_stroke(c,39.0,egui::Stroke::new(8.0_f32,Color32::from_rgb(70,98,120)));p.circle_stroke(c,22.0,egui::Stroke::new(2.0_f32,Color32::WHITE));p.circle_filled(c,7.0,Color32::WHITE);
                ui.vertical(|ui|{ui.label(RichText::new("Observing, not enforcing").size(25.0).color(Color32::WHITE));ui.label(RichText::new("Automatic blocking is unavailable in this development release.").color(Color32::from_rgb(207,223,235)));ui.label(RichText::new("Your existing Windows protections remain responsible for blocking attacks.").color(Color32::from_rgb(207,223,235)));});});
        });
        ui.add_space(20.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.busy,
                    egui::Button::new(RichText::new("Scan this PC").color(Color32::WHITE))
                        .fill(TEAL),
                )
                .clicked()
            {
                self.action(Action::Scan);
            }
            if ui
                .add_enabled(!self.busy, egui::Button::new("Refresh research"))
                .clicked()
            {
                self.action(Action::Feeds);
            }
            if ui
                .add_enabled(!self.busy, egui::Button::new("Explain findings"))
                .clicked()
            {
                self.action(Action::Analyze);
            }
        });
        ui.add_space(20.0);
        ui.columns(2, |columns| {
            columns[0].with_layout(egui::Layout::top_down(egui::Align::LEFT), |ui| {
                let urgent = self.snapshot.findings.iter().any(|f| f.priority <= Priority::Medium);
                ui.label(RichText::new(if urgent { "Needs attention" } else { "Research candidates" }).size(20.0));
                if self.snapshot.findings.is_empty() { ui.label("No findings recorded. This is not proof that every application is safe."); }
                for finding in self.snapshot.findings.iter().take(3) {
                    ui.separator();
                    ui.label(RichText::new(&finding.title).strong());
                    ui.label(RichText::new(format!("{:?} · {:?}", finding.priority, finding.applicability)).color(if finding.priority <= Priority::High { RED } else { AMBER }));
                }
                if ui.button(format!("Review all {} findings", self.snapshot.findings.len())).clicked() { self.page = Page::Findings; }
            });
            columns[1].with_layout(egui::Layout::top_down(egui::Align::LEFT), |ui| {
                ui.label(RichText::new("Coverage").size(20.0));
                if self.snapshot.devices.is_empty() { ui.label("Run the first scan to see what VASP can inspect on this PC."); }
                for device in &self.snapshot.devices {
                    ui.separator();
                    ui.label(RichText::new(&device.os_name).strong());
                    let available = device.coverage.iter().filter(|c| c.state == CoverageState::Available).count();
                    ui.label(format!("{available} of {} collection areas available", device.coverage.len()));
                    ui.label(format!("{} applications · {} listening services", device.software.len(), device.listeners.len()));
                }
                ui.add_space(16.0);
                ui.label(RichText::new("Other LAN devices").strong());
                ui.label("Visible neighbors are not enrolled or protected. TELUS router enforcement is unavailable.");
            });
        });
    }
    fn findings(&mut self, ui: &mut egui::Ui) {
        Self::heading(
            ui,
            "Findings",
            "Open a finding to inspect evidence and the recommended next step.",
        );
        ui.add(
            egui::TextEdit::singleline(&mut self.query)
                .hint_text("Filter findings…")
                .desired_width(400.0),
        );
        for f in &self.snapshot.findings {
            if !f.title.to_lowercase().contains(&self.query.to_lowercase()) {
                continue;
            }
            let expanded = self.selected.as_ref() == Some(&f.id);
            egui::Frame::new()
                .fill(Color32::WHITE)
                .inner_margin(16.0)
                .corner_radius(6.0)
                .show(ui, |ui| {
                    if ui
                        .selectable_label(expanded, RichText::new(&f.title).strong())
                        .clicked()
                    {
                        self.selected = if expanded { None } else { Some(f.id.clone()) };
                    }
                    ui.label(
                        RichText::new(format!(
                            "{:?} priority / {:?} applicability",
                            f.priority, f.applicability
                        ))
                        .color(MUTED),
                    );
                    if expanded {
                        ui.label(&f.explanation);
                        ui.add_space(6.0);
                        for e in &f.evidence {
                            ui.label(e);
                        }
                        ui.label(RichText::new("Recommended next step").strong());
                        ui.label(&f.remediation);
                        for url in &f.source_urls {
                            ui.label(url);
                        }
                        ui.label(
                            RichText::new("No automatic action authorized by this finding.")
                                .color(AMBER),
                        );
                    }
                });
            ui.add_space(6.0);
        }
    }
    fn devices(&self, ui: &mut egui::Ui) {
        Self::heading(
            ui,
            "Devices and visibility",
            "Only explicitly enrolled Windows devices provide endpoint observations.",
        );
        for o in &self.snapshot.devices {
            ui.group(|ui|{ui.label(RichText::new(format!("{} {}",o.os_name,o.os_version)).size(20.0));ui.label(format!("Device {}",o.device_id));ui.label(format!("Last observation: {} seconds ago",vasp_core::now().saturating_sub(o.observed_at)));
            for c in &o.coverage{ui.horizontal_wrapped(|ui|{let color=match c.state{CoverageState::Available=>TEAL,CoverageState::Partial=>AMBER,CoverageState::Unavailable=>MUTED};ui.label(RichText::new(format!("● {}",c.area)).color(color));ui.label(&c.detail);});}
            egui::CollapsingHeader::new(format!("{} applications",o.software.len())).show(ui,|ui|{for s in &o.software{ui.label(format!("{}  {}",s.name,s.version));}});
            egui::CollapsingHeader::new(format!("{} passive LAN neighbors",o.neighbors.len())).show(ui,|ui|{ui.label("These entries can be stale. Visibility does not establish reachability or protection.");for n in &o.neighbors{ui.label(format!("{} / interface {} / not enrolled",n.address,n.interface));}});
        });
            ui.add_space(16.0);
        }
    }
    fn research(&self, ui: &mut egui::Ui) {
        Self::heading(
            ui,
            "Research and analysis",
            "Sources can fail or grow stale. AI output is advisory text with no execution authority.",
        );
        for (name, s) in &self.snapshot.schedules {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(name).strong());
                ui.label(
                    RichText::new(if s.last_error.is_some() {
                        "Partial or failed"
                    } else if s.stale(vasp_core::now()) {
                        "Stale or unavailable"
                    } else {
                        "Current"
                    })
                    .color(
                        if s.last_error.is_some() || s.stale(vasp_core::now()) {
                            AMBER
                        } else {
                            TEAL
                        },
                    ),
                );
            });
            if let Some(e) = &s.last_error {
                ui.label(e);
            }
            ui.separator();
        }
        if self.snapshot.reports.is_empty() {
            ui.label("No AI reports yet. Configure a provider and budget in Settings to enable analysis.");
        }
        for raw in &self.snapshot.reports {
            if let Ok(report) = serde_json::from_str::<vasp_core::ai::AnalystReport>(raw) {
                ui.group(|ui| {
                    ui.label(RichText::new("AI advisory / untrusted text").color(AMBER));
                    ui.label(report.summary);
                    ui.label(format!(
                        "{} read-only investigations proposed; no commands executed",
                        report.investigations.len()
                    ));
                });
            }
        }
    }
    fn settings(&mut self, ui: &mut egui::Ui) {
        Self::heading(
            ui,
            "Controls",
            "Cloud is off by default. Model settings cannot expand endpoint permissions.",
        );
        ui.label("Automatic protection");
        ui.label(
            RichText::new(
                "Unavailable pending broker integration, recovery testing and security review.",
            )
            .color(AMBER),
        );
        if ui
            .add_enabled(
                !self.busy,
                egui::Button::new("Keep automatic actions disabled"),
            )
            .clicked()
        {
            self.action(Action::Stop);
        }
        if ui
            .add_enabled(!self.busy, egui::Button::new("Check local broker"))
            .clicked()
        {
            self.action(Action::BrokerStatus);
        }
        if ui
            .add_enabled(
                !self.busy,
                egui::Button::new("Remove VASP temporary blocks"),
            )
            .clicked()
        {
            self.action(Action::RemoveBlocks);
        }
        ui.add_space(16.0);
        ui.label(RichText::new("Model and research configuration").strong());
        ui.label("Credentials are stored separately in Windows Credential Manager using the vasp credential command. Do not paste keys here.");
        if self.config_json.is_empty() {
            self.config_json =
                serde_json::to_string_pretty(&self.snapshot.config).unwrap_or_default();
        }
        ui.add(
            egui::TextEdit::multiline(&mut self.config_json)
                .code_editor()
                .desired_rows(14)
                .desired_width(f32::INFINITY),
        );
        if ui
            .add_enabled(!self.busy, egui::Button::new("Save configuration"))
            .clicked()
        {
            match serde_json::from_str(&self.config_json) {
                Ok(c) => self.action(Action::Configure(c)),
                Err(e) => {
                    self.message = format!("Invalid configuration: {e}");
                    self.error = true;
                }
            }
        }
        ui.add_space(12.0);
        ui.label("LAN pairing uses explicit certificate fingerprints through the CLI. This console does not expose a browser administration server.");
    }
}
impl eframe::App for Console {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        while let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            match event.id.as_ref() {
                "show" => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                "scan" => self.action(Action::Scan),
                "stop" => self.action(Action::Stop),
                "quit" => {
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                _ => {}
            }
        }
        if ctx.input(|i| i.viewport().close_requested()) && self.tray.is_some() && !self.quitting {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        while let Ok(update) = self.rx.try_recv() {
            if let Some(s) = update.snapshot {
                self.snapshot = s;
            }
            self.message = update.message;
            self.error = update.error;
            self.busy = false;
        }
        if let Some(path) = &self.screenshot {
            if !self.busy && !self.capture_sent {
                self.capture_sent = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            }
            for event in ctx.input(|i| i.events.clone()) {
                if let egui::Event::Screenshot { image, .. } = event {
                    let pixels: Vec<u8> = image.pixels.iter().flat_map(|p| p.to_array()).collect();
                    let _ = image::save_buffer(
                        path,
                        &pixels,
                        image.size[0] as u32,
                        image.size[1] as u32,
                        image::ColorType::Rgba8,
                    );
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        } else if !self.busy && self.last_tick.elapsed() > Duration::from_secs(30) {
            self.last_tick = Instant::now();
            self.action(Action::Tick);
        }
        egui::SidePanel::left("navigation")
            .exact_width(190.0)
            .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(20.0))
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.label(RichText::new("VASP").size(32.0).strong().color(INK));
                ui.label(RichText::new("Local security").color(MUTED));
                ui.add_space(36.0);
                for (page, label) in [
                    (Page::Overview, "Overview"),
                    (Page::Findings, "Findings"),
                    (Page::Devices, "Devices"),
                    (Page::Research, "Research"),
                    (Page::Activity, "Activity"),
                    (Page::Settings, "Settings"),
                ] {
                    if ui
                        .add_sized(
                            [150.0, 38.0],
                            egui::Button::new(label).selected(self.page == page),
                        )
                        .clicked()
                    {
                        self.page = page;
                    }
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(
                        RichText::new("Development release 0.1")
                            .small()
                            .color(MUTED),
                    );
                    ui.label(RichText::new("● Observe only").color(AMBER));
                });
            });
        egui::TopBottomPanel::bottom("status")
            .exact_height(40.0)
            .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(10.0))
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    // Stable geometry and no continuous animation during long feed requests.
                    ui.allocate_ui(Vec2::splat(18.0), |ui| {
                        if self.busy {
                            ui.label(RichText::new("●").color(TEAL));
                        }
                    });
                    ui.label(RichText::new(&self.message).color(if self.error {
                        RED
                    } else {
                        MUTED
                    }));
                });
            });
        egui::CentralPanel::default().frame(egui::Frame::new().fill(PAPER).inner_margin(28.0)).show(ctx,|ui|{egui::ScrollArea::vertical().show(ui,|ui|match self.page{Page::Overview=>self.overview(ui),Page::Findings=>self.findings(ui),Page::Devices=>self.devices(ui),Page::Research=>self.research(ui),Page::Settings=>self.settings(ui),Page::Activity=>{Self::heading(ui,"Activity","A local, integrity-linked record. It is not an attestation that Windows is uncompromised.");for(at,event)in &self.snapshot.activity{ui.horizontal_wrapped(|ui|{ui.label(RichText::new(at.to_string()).color(MUTED));ui.label(event);});ui.separator();}}});});
        ctx.request_repaint_after(Duration::from_secs(1));
    }
}
