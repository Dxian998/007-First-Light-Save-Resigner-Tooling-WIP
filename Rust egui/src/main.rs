#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(dead_code)]

use eframe::egui;
use egui::{Color32, FontId, RichText, Stroke, Vec2};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

mod cli;
mod crypto;
mod utils;
mod ops;
mod parser;
mod rc;

use ops::{cmd_resign_file, cmd_resign_folder};
use rc::remote_cache_vdf_file::RemoteCacheVdfFile;

// ── colour palette ───────────────────────────────────────────────
const BG_DEEP:    Color32 = Color32::from_rgb(10,  12,  16);
const BG_PANEL:   Color32 = Color32::from_rgb(18,  22,  30);
const BG_FIELD:   Color32 = Color32::from_rgb(24,  29,  40);
const BG_HOVER:   Color32 = Color32::from_rgb(30,  37,  52);
const ACCENT:     Color32 = Color32::from_rgb(180, 150, 80);   // gold
const ACCENT_DIM: Color32 = Color32::from_rgb(100,  83,  42);
const TEXT_PRI:   Color32 = Color32::from_rgb(220, 215, 200);
const TEXT_SEC:   Color32 = Color32::from_rgb(120, 115, 105);
const TEXT_HINT:  Color32 = Color32::from_rgb(130, 125, 115);
const SUCCESS:    Color32 = Color32::from_rgb(80,  170, 110);
const ERROR_COL:  Color32 = Color32::from_rgb(200,  80,  70);
const BORDER:     Color32 = Color32::from_rgb(40,   47,  62);

fn try_parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() { return None; }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn display_path(path: &str) -> String {
    const MAX_CHARS: usize = 48;
    let chars: Vec<char> = path.chars().collect();
    if chars.len() <= MAX_CHARS {
        path.to_string()
    } else {
        let tail: String = chars[chars.len() - MAX_CHARS..].iter().collect();
        format!("…{}", tail)
    }
}

// ── state ────────────────────────────────────────────────────────
#[derive(PartialEq, Clone, Copy)]
enum PathMode { File, Folder }

#[derive(PartialEq, Clone, Copy)]
enum Tab { ResignSave, VdfGenerator }

struct App {
    tab:       Tab,
    path:      String,
    path_mode: PathMode,
    to_id:     String,
    from_id:   String,
    vdf_path:  String,
    is_busy:   Arc<Mutex<bool>>,
    status:    Arc<Mutex<Status>>,
}

#[derive(Clone)]
struct Status {
    text: String,
    kind: StatusKind,
}

#[derive(Clone, PartialEq)]
enum StatusKind { Idle, Running, Ok, Err }

impl Default for App {
    fn default() -> Self {
        Self {
            tab:       Tab::ResignSave,
            path:      String::new(),
            path_mode: PathMode::Folder,
            to_id:     String::new(),
            from_id:   String::new(),
            vdf_path:  String::new(),
            is_busy:   Arc::new(Mutex::new(false)),
            status:    Arc::new(Mutex::new(Status {
                text: String::new(),
                kind: StatusKind::Idle,
            })),
        }
    }
}

// ── app entry ────────────────────────────────────────────────────
fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([540.0, 595.0])
            .with_min_inner_size([540.0, 595.0])
            .with_title("007 First Light - Save Resigner")
            .with_decorations(true)
            .with_maximize_button(false)
            .with_resizable(false),
        ..Default::default()
    };

    eframe::run_native(
        "007 First Light - Save Resigner",
        options,
        Box::new(|cc| {
            setup_fonts(&cc.egui_ctx);
            Ok(Box::new(App::default()))
        }),
    )
}

fn setup_fonts(ctx: &egui::Context) {
    // Style tweaks — spacing, rounding, colours
    let mut style = (*ctx.global_style()).clone();
    style.spacing.item_spacing       = Vec2::new(10.0, 8.0);
    style.spacing.button_padding     = Vec2::new(14.0, 7.0);
    style.spacing.window_margin      = egui::Margin::same(0_i8);
    style.visuals.window_fill        = BG_DEEP;
    style.visuals.panel_fill         = BG_DEEP;
    style.visuals.window_stroke      = Stroke::new(0.0_f32, Color32::TRANSPARENT);
    style.visuals.widgets.noninteractive.bg_fill   = BG_PANEL;
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT_SEC);
    style.visuals.widgets.inactive.bg_fill         = BG_FIELD;
    style.visuals.widgets.inactive.fg_stroke       = Stroke::new(1.0_f32, TEXT_PRI);
    style.visuals.widgets.hovered.bg_fill          = BG_HOVER;
    style.visuals.widgets.hovered.fg_stroke        = Stroke::new(1.0_f32, ACCENT);
    style.visuals.widgets.active.bg_fill           = ACCENT_DIM;
    style.visuals.widgets.active.fg_stroke         = Stroke::new(1.0_f32, ACCENT);
    style.visuals.selection.bg_fill                = ACCENT_DIM;
    style.visuals.selection.stroke                 = Stroke::new(1.0_f32, ACCENT);
    style.visuals.extreme_bg_color                 = BG_FIELD;
    style.visuals.override_text_color              = Some(TEXT_PRI);
    style.visuals.window_corner_radius             = egui::CornerRadius::same(0_u8);
    style.visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(0_u8);
    style.visuals.widgets.inactive.corner_radius   = egui::CornerRadius::same(0_u8);
    style.visuals.widgets.hovered.corner_radius    = egui::CornerRadius::same(0_u8);
    style.visuals.widgets.active.corner_radius     = egui::CornerRadius::same(0_u8);
    style.visuals.widgets.open.corner_radius       = egui::CornerRadius::same(0_u8);
    ctx.set_global_style(style);
}

// ── ui ───────────────────────────────────────────────────────────
impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Handle drag and drop
        let dropped_path = ui.ctx().input(|i| {
            i.raw.dropped_files.first().and_then(|f| f.path.clone())
        });
        if let Some(path) = dropped_path {
            match self.tab {
                Tab::ResignSave => {
                    self.path = path.display().to_string();
                    self.path_mode = if path.is_dir() { PathMode::Folder } else { PathMode::File };
                }
                Tab::VdfGenerator => {
                    if path.is_dir() {
                        self.vdf_path = path.display().to_string();
                    }
                }
            }
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(BG_DEEP).inner_margin(egui::Margin::same(0_i8)))
            .show_inside(ui, |ui| {
                let body_rect = ui.max_rect();

                ui.scope_builder(egui::UiBuilder::new().max_rect(body_rect), |ui| {
                    ui.add_space(20.0);
                    egui::Frame::NONE
                        .inner_margin(egui::Margin {
                            left: 24_i8,
                            right: 24_i8,
                            top: 0_i8,
                            bottom: 24_i8,
                        })
                        .show(ui, |ui| {
                            self.draw_body(ui);
                        });
                });
            });

        // Global cursor-invisibility bug fix:
        // Unconditionally force the cursor to be the default arrow
        ui.ctx().output_mut(|o| {
            o.cursor_icon = egui::CursorIcon::Default;
        });
    }
}

impl App {
    fn draw_body(&mut self, ui: &mut egui::Ui) {
        let is_busy = *self.is_busy.lock().unwrap();

        // ── tab bar ──────────────────────────────────────────────
        ui.horizontal(|ui| {
            for (t, label) in [(Tab::ResignSave, "Resign Save"), (Tab::VdfGenerator, "VDF Generator")] {
                let selected = self.tab == t;
                let fg = if selected { ACCENT } else { TEXT_SEC };
                let bg = if selected { ACCENT_DIM } else { BG_FIELD };
                let stroke = if selected {
                    Stroke::new(1.0_f32, ACCENT)
                } else {
                    Stroke::new(1.0_f32, BORDER)
                };
                let resp = egui::Frame::NONE
                    .fill(bg)
                    .stroke(stroke)
                    .inner_margin(egui::Margin::symmetric(14_i8, 6_i8))
                    .show(ui, |ui| {
                        ui.label(RichText::new(label).font(FontId::proportional(12.5)).color(fg));
                    })
                    .response
                    .interact(egui::Sense::click());
                if resp.clicked() && !is_busy {
                    self.tab = t;
                    *self.status.lock().unwrap() = Status { text: String::new(), kind: StatusKind::Idle };
                }
            }
        });

        ui.add_space(16.0);
        self.divider(ui);
        ui.add_space(16.0);

        match self.tab {
            Tab::ResignSave    => self.draw_resign(ui),
            Tab::VdfGenerator  => self.draw_vdf(ui),
        }
    }

    fn draw_resign(&mut self, ui: &mut egui::Ui) {
        let is_busy = *self.is_busy.lock().unwrap();

        self.to_id.retain(|c| c.is_ascii_digit());
        if self.to_id.len() > 17 { self.to_id.truncate(17); }
        self.from_id.retain(|c| c.is_ascii_digit());
        if self.from_id.len() > 17 { self.from_id.truncate(17); }

        // ── section: target ──────────────────────────────────────
        self.section_label(ui, "TARGET SAVE");
        ui.add_space(12.0);

        // path field
        let full_w = ui.available_width();
        ui.horizontal(|ui| {
            let field_w = full_w - 130.0;
            egui::Frame::NONE
                .fill(BG_FIELD)
                .stroke(Stroke::new(1.0_f32, BORDER))
                .inner_margin(egui::Margin::symmetric(10_i8, 6_i8))
                .show(ui, |ui| {
                    ui.set_min_width(field_w);
                    let hint = match self.path_mode {
                        PathMode::File   => "Path to save file (or drag & drop here)…",
                        PathMode::Folder => "Path to save folder (or drag & drop here)…",
                    };
                    let display = if self.path.is_empty() {
                        RichText::new(hint).color(TEXT_HINT)
                    } else {
                        RichText::new(display_path(&self.path)).color(TEXT_PRI)
                    };
                    ui.add(egui::Label::new(display));
                });

            let btn_label = match self.path_mode {
                PathMode::File   => "Browse File",
                PathMode::Folder => "Browse Folder",
            };
            if self.gold_button(ui, btn_label, is_busy).clicked() && !is_busy {
                match self.path_mode {
                    PathMode::File => {
                        if let Some(p) = rfd::FileDialog::new().pick_file() {
                            self.path = p.display().to_string();
                        }
                    }
                    PathMode::Folder => {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            self.path = p.display().to_string();
                        }
                    }
                }
            }
        });

        ui.add_space(8.0);

        // mode toggle
        ui.horizontal(|ui| {
            for (mode, label) in [(PathMode::Folder, "Folder"), (PathMode::File, "Single File")] {
                let selected = self.path_mode == mode;
                let fg = if selected { ACCENT } else { TEXT_SEC };
                let bg = if selected { ACCENT_DIM } else { BG_FIELD };
                let stroke = if selected {
                    Stroke::new(1.0_f32, ACCENT)
                } else {
                    Stroke::new(1.0_f32, BORDER)
                };
                let response = egui::Frame::NONE
                    .fill(bg)
                    .stroke(stroke)
                    .inner_margin(egui::Margin::symmetric(10_i8, 4_i8))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(label)
                                .font(FontId::proportional(12.0))
                                .color(fg),
                        );
                    })
                    .response;

                let click_resp = response.interact(egui::Sense::click());
                if click_resp.clicked() && !is_busy {
                    self.path_mode = mode;
                }
            }
        });

        ui.add_space(20.0);
        self.divider(ui);
        ui.add_space(20.0);

        // ── section: identity ────────────────────────────────────
        self.section_label(ui, "STEAM IDENTITY");
        ui.add_space(10.0);

        ui.vertical(|ui| {
            ui.label(RichText::new("Target SteamID64").font(FontId::proportional(12.5)).color(TEXT_SEC));
            ui.add_space(4.0);
            ui.add_enabled_ui(!is_busy, |ui| {
                let edit = egui::TextEdit::singleline(&mut self.to_id)
                    .desired_width(f32::INFINITY)
                    .font(FontId::monospace(13.0))
                    .hint_text("e.g. 76561198000000000")
                    .text_color(TEXT_PRI);
                ui.add(edit);
            });
        });

        ui.add_space(6.0);

        ui.vertical(|ui| {
            ui.label(RichText::new("Source SteamID64 (optional)").font(FontId::proportional(12.5)).color(TEXT_SEC));
            ui.add_space(4.0);
            ui.add_enabled_ui(!is_busy, |ui| {
                let edit = egui::TextEdit::singleline(&mut self.from_id)
                    .desired_width(f32::INFINITY)
                    .font(FontId::monospace(13.0))
                    .hint_text("Leave blank to auto-detect")
                    .text_color(TEXT_PRI);
                ui.add(edit);
            });
        });

        ui.add_space(6.0);

        ui.add_space(20.0);
        self.divider(ui);
        ui.add_space(20.0);

        // ── execute button ───────────────────────────────────────
        {
            let w = ui.available_width();
            let (rect, response) = ui.allocate_exact_size(Vec2::new(w, 44.0), egui::Sense::click());
            let active  = !is_busy;
            let hovered = response.hovered() && active;
            let bg      = if hovered { ACCENT } else { ACCENT_DIM };
            ui.painter().rect_filled(rect, 2.0, bg);
            ui.painter().rect_stroke(rect, 2.0, Stroke::new(1.0_f32, bg), egui::StrokeKind::Inside);
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "▶  EXECUTE RESIGN",
                FontId::proportional(14.0),
                if hovered { BG_DEEP } else if active { TEXT_PRI } else { TEXT_SEC },
            );
            if response.clicked() && active {
                self.execute();
            }
        }

        // ── status panel ─────────────────────────────────────────
        let st = self.status.lock().unwrap().clone();
        ui.add_space(16.0);

        let (text, col) = if is_busy {
            ("Processing save files…", ACCENT)
        } else {
            match st.kind {
                StatusKind::Running => ("Processing save files…", ACCENT),
                StatusKind::Ok      => (&st.text as &str, SUCCESS),
                StatusKind::Err     => (&st.text as &str, ERROR_COL),
                StatusKind::Idle    => ("Ready to resign save files", TEXT_SEC),
            }
        };

        self.draw_status(ui, is_busy || st.kind == StatusKind::Running, text, col);
    }

    fn draw_status(&self, ui: &mut egui::Ui, spinning: bool, text: &str, col: Color32) {
        let w = ui.max_rect().width();
        let (rect, _) = ui.allocate_exact_size(Vec2::new(w, 44.0), egui::Sense::hover());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, BG_PANEL);
        painter.rect_stroke(rect, 0.0, Stroke::new(1.0_f32, BORDER), egui::StrokeKind::Inside);
        let display = if spinning {
            let dots = match (ui.ctx().input(|i| i.time) * 2.0) as usize % 4 {
                0 => "",
                1 => ".",
                2 => "..",
                _ => "...",
            };
            ui.ctx().request_repaint();
            format!("{}{}", text, dots)
        } else {
            text.to_string()
        };
        painter.text(rect.center(), egui::Align2::CENTER_CENTER, &display, FontId::proportional(13.0), col);
    }

    fn section_label(&self, ui: &mut egui::Ui, text: &str) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(text)
                    .font(FontId::proportional(13.0))
                    .color(ACCENT)
                    .strong(),
            );
        });
    }

    fn divider(&self, ui: &mut egui::Ui) {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), egui::Sense::hover());
        ui.painter().hline(rect.x_range(), rect.top(), Stroke::new(1.0_f32, BORDER));
    }

    fn label_col(&self, ui: &mut egui::Ui, text: &str) {
        ui.allocate_ui_with_layout(
            Vec2::new(180.0, 28.0),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.label(
                    RichText::new(text)
                        .font(FontId::proportional(12.5))
                        .color(TEXT_SEC),
                );
            },
        );
    }

    fn gold_button(&self, ui: &mut egui::Ui, label: &str, disabled: bool) -> egui::Response {
        ui.add_enabled_ui(!disabled, |ui| {
            let (rect, response) = ui.allocate_exact_size(Vec2::new(100.0, 32.0), egui::Sense::click());
            let bg = if response.hovered() { ACCENT } else { BG_HOVER };
            let fg = if response.hovered() { BG_DEEP } else { ACCENT };
            let stroke_col = if response.hovered() { ACCENT } else { ACCENT_DIM };
            ui.painter().rect_filled(rect, 2.0, bg);
            ui.painter().rect_stroke(rect, 2.0, Stroke::new(1.0_f32, stroke_col), egui::StrokeKind::Inside);
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                label,
                FontId::proportional(11.5),
                fg,
            );
            response
        }).inner
    }

    fn execute(&mut self) {
        if self.path.is_empty() {
            *self.status.lock().unwrap() = Status {
                text: "No path selected. Choose a file or folder.".into(),
                kind: StatusKind::Err,
            };
            return;
        }

        if self.to_id.len() != 17 {
            *self.status.lock().unwrap() = Status {
                text: "Target SteamID64 must be exactly 17 digits.".into(),
                kind: StatusKind::Err,
            };
            return;
        }

        let to = match try_parse_u64(&self.to_id) {
            Some(v) => v,
            None => {
                *self.status.lock().unwrap() = Status {
                    text: "Invalid target SteamID64. Must be a 17-digit number.".into(),
                    kind: StatusKind::Err,
                };
                return;
            }
        };

        if !self.from_id.is_empty() && self.from_id.len() != 17 {
            *self.status.lock().unwrap() = Status {
                text: "Source SteamID64 must be exactly 17 digits.".into(),
                kind: StatusKind::Err,
            };
            return;
        }

        let from    = try_parse_u64(&self.from_id);
        let path    = PathBuf::from(&self.path);
        let folder  = self.path_mode == PathMode::Folder;

        let is_busy = Arc::clone(&self.is_busy);
        let status  = Arc::clone(&self.status);

        *is_busy.lock().unwrap() = true;
        *status.lock().unwrap() = Status { text: "Running…".into(), kind: StatusKind::Running };

        thread::spawn(move || {
            let res = std::panic::catch_unwind(|| {
                println!("\n=== Resign starting ===");
                if folder {
                    cmd_resign_folder(&path, to, from, true);
                } else {
                    cmd_resign_file(&path, to, from);
                }
                println!("=== Resign finished ===\n");
            });

            *is_busy.lock().unwrap() = false;
            *status.lock().unwrap() = if res.is_ok() {
                Status { text: "Resign completed successfully.".into(), kind: StatusKind::Ok }
            } else {
                Status { text: "Operation failed — check the console for details.".into(), kind: StatusKind::Err }
            };
        });
    }

    fn draw_vdf(&mut self, ui: &mut egui::Ui) {
        let is_busy = *self.is_busy.lock().unwrap();

        // ── section: remote folder ───────────────────────────────
        self.section_label(ui, "REMOTE FOLDER");
        ui.add_space(12.0);

        let full_w = ui.available_width();
        ui.horizontal(|ui| {
            let field_w = full_w - 130.0;
            egui::Frame::NONE
                .fill(BG_FIELD)
                .stroke(Stroke::new(1.0_f32, BORDER))
                .inner_margin(egui::Margin::symmetric(10_i8, 6_i8))
                .show(ui, |ui| {
                    ui.set_min_width(field_w);
                    let display = if self.vdf_path.is_empty() {
                        RichText::new("Path to Steam remote folder (or drag & drop)…").color(TEXT_HINT)
                    } else {
                        RichText::new(display_path(&self.vdf_path)).color(TEXT_PRI)
                    };
                    ui.add(egui::Label::new(display));
                });

            if self.gold_button(ui, "Browse Folder", is_busy).clicked() && !is_busy {
                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                    self.vdf_path = p.display().to_string();
                }
            }
        });

        ui.add_space(6.0);
        ui.label(
            RichText::new("Select the remote folder from your Steam save directory.\n(e.g. …\\userdata\\<AccountId>\\3768760\\remote)")
                .font(FontId::proportional(11.5))
                .color(TEXT_SEC),
        );

        ui.add_space(20.0);
        self.divider(ui);
        ui.add_space(20.0);

        // ── execute button ───────────────────────────────────────
        {
            let w = ui.available_width();
            let (rect, response) = ui.allocate_exact_size(Vec2::new(w, 44.0), egui::Sense::click());
            let active  = !is_busy;
            let hovered = response.hovered() && active;
            let bg      = if hovered { ACCENT } else { ACCENT_DIM };
            ui.painter().rect_filled(rect, 2.0, bg);
            ui.painter().rect_stroke(rect, 2.0, Stroke::new(1.0_f32, bg), egui::StrokeKind::Inside);
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "⚙  GENERATE VDF",
                FontId::proportional(14.0),
                if hovered { BG_DEEP } else if active { TEXT_PRI } else { TEXT_SEC },
            );
            if response.clicked() && active {
                self.execute_vdf();
            }
        }

        // ── status panel ─────────────────────────────────────────
        let st = self.status.lock().unwrap().clone();
        ui.add_space(16.0);

        let (text, col) = if is_busy {
            ("Generating VDF…", ACCENT)
        } else {
            match st.kind {
                StatusKind::Running => ("Generating VDF…", ACCENT),
                StatusKind::Ok      => (&st.text as &str, SUCCESS),
                StatusKind::Err     => (&st.text as &str, ERROR_COL),
                StatusKind::Idle    => ("Ready to generate remotecache.vdf", TEXT_SEC),
            }
        };

        self.draw_status(ui, is_busy || st.kind == StatusKind::Running, text, col);
    }

    fn execute_vdf(&mut self) {
        if self.vdf_path.is_empty() {
            *self.status.lock().unwrap() = Status {
                text: "No folder selected.".into(),
                kind: StatusKind::Err,
            };
            return;
        }

        let path    = self.vdf_path.clone();
        let is_busy = Arc::clone(&self.is_busy);
        let status  = Arc::clone(&self.status);

        *is_busy.lock().unwrap() = true;
        *status.lock().unwrap() = Status { text: "Running…".into(), kind: StatusKind::Running };

        thread::spawn(move || {
            let result = RemoteCacheVdfFile::from_folder(&path)
                .and_then(|vdf| {
                    let count = vdf.cached_files.len();
                    vdf.export_as_file(&path)?;
                    Ok(count)
                });

            *is_busy.lock().unwrap() = false;
            *status.lock().unwrap() = match result {
                Ok(n)    => Status { text: format!("VDF generated successfully with {} files.", n), kind: StatusKind::Ok },
                Err(e)   => Status { text: format!("Error: {}", e), kind: StatusKind::Err },
            };
        });
    }
}