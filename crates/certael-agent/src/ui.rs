use anyhow::{anyhow, Result};
use eframe::egui;
use std::{
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

const CANVAS: egui::Color32 = egui::Color32::from_rgb(0x0B, 0x12, 0x1B);
const SURFACE: egui::Color32 = egui::Color32::from_rgb(0x11, 0x1C, 0x28);
const RAISED: egui::Color32 = egui::Color32::from_rgb(0x18, 0x25, 0x34);
const BORDER: egui::Color32 = egui::Color32::from_rgb(0x2A, 0x3A, 0x4C);
const PRIMARY: egui::Color32 = egui::Color32::from_rgb(0xF4, 0xF7, 0xFA);
const SECONDARY: egui::Color32 = egui::Color32::from_rgb(0xA8, 0xB5, 0xC4);
const MUTED: egui::Color32 = egui::Color32::from_rgb(0x7D, 0x8C, 0x9E);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(0x58, 0xC7, 0xD4);
const FOCUS: egui::Color32 = egui::Color32::from_rgb(0x78, 0xDC, 0xE6);
const RECOVERY: egui::Color32 = egui::Color32::from_rgb(0xFF, 0xB4, 0xA9);
const BUTTON: egui::Color32 = egui::Color32::from_rgb(0x28, 0x68, 0x73);

pub fn run() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Certael Agent")
            .with_inner_size([720.0, 600.0])
            .with_min_inner_size([560.0, 440.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Certael Agent",
        options,
        Box::new(|_| Ok(Box::<AgentApp>::default())),
    )
    .map_err(|error| anyhow!(error.to_string()))
}

pub fn run_splash(
    registered: crate::registry::RegisteredGame,
    launch_attempt_id: String,
) -> Result<()> {
    run_splash_inner(registered, launch_attempt_id, None, [1040.0, 800.0], 1.0)
}

#[cfg(debug_assertions)]
pub fn run_splash_preview(
    registered: crate::registry::RegisteredGame,
    launch_attempt_id: String,
    screenshot_path: PathBuf,
    viewport_size: [f32; 2],
    zoom: f32,
) -> Result<()> {
    run_splash_inner(
        registered,
        launch_attempt_id,
        Some(screenshot_path),
        viewport_size,
        zoom,
    )
}

fn run_splash_inner(
    registered: crate::registry::RegisteredGame,
    launch_attempt_id: String,
    screenshot_path: Option<PathBuf>,
    viewport_size: [f32; 2],
    zoom: f32,
) -> Result<()> {
    let title = registered
        .branding
        .as_ref()
        .map(|branding| branding.claims.display_name.as_str())
        .unwrap_or(&registered.claims.game_id);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(format!("Launching {title}"))
            .with_inner_size(viewport_size)
            .with_min_inner_size([720.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Certael Agent launch",
        options,
        Box::new(move |creation| {
            configure_splash_style(&creation.egui_ctx);
            creation.egui_ctx.set_zoom_factor(zoom);
            Ok(Box::new(SplashApp::new(
                creation,
                registered,
                launch_attempt_id,
                screenshot_path,
            )))
        }),
    )
    .map_err(|error| anyhow!(error.to_string()))
}

fn configure_splash_style(context: &egui::Context) {
    let mut style = (*context.style_of(egui::Theme::Dark)).clone();
    style.spacing.item_spacing = egui::vec2(12.0, 10.0);
    style.spacing.button_padding = egui::vec2(18.0, 11.0);
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = CANVAS;
    style.visuals.window_fill = CANVAS;
    style.visuals.override_text_color = Some(PRIMARY);
    style.visuals.widgets.noninteractive.bg_fill = SURFACE;
    style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    style.visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(3);
    style.visuals.widgets.inactive.bg_fill = RAISED;
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    style.visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(3);
    style.visuals.widgets.hovered.bg_fill = BUTTON;
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, FOCUS);
    style.visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(3);
    style.visuals.widgets.active.bg_fill = BUTTON;
    style.visuals.widgets.active.bg_stroke = egui::Stroke::new(2.0, FOCUS);
    style.visuals.widgets.active.corner_radius = egui::CornerRadius::same(3);
    style.visuals.selection.bg_fill = BUTTON;
    context.set_style_of(egui::Theme::Dark, style);
}

struct SplashApp {
    registered: crate::registry::RegisteredGame,
    launch_attempt_id: String,
    icon: Option<egui::TextureHandle>,
    hero: Option<(egui::TextureHandle, f32)>,
    status: Option<crate::status::RuntimeStatus>,
    last_refresh: Instant,
    ready_since: Option<Instant>,
    action_message: Option<String>,
    #[cfg(debug_assertions)]
    screenshot_path: Option<PathBuf>,
    #[cfg(debug_assertions)]
    screenshot_requested: bool,
    failure_resized: bool,
}

impl SplashApp {
    fn new(
        creation: &eframe::CreationContext<'_>,
        registered: crate::registry::RegisteredGame,
        launch_attempt_id: String,
        screenshot_path: Option<PathBuf>,
    ) -> Self {
        #[cfg(not(debug_assertions))]
        let _ = screenshot_path;
        let icon = registered.branding.as_ref().and_then(|branding| {
            load_texture(
                &creation.egui_ctx,
                "certael-game-icon",
                &branding.icon.path,
                false,
            )
            .ok()
            .map(|value| value.0)
        });
        let hero = registered.branding.as_ref().and_then(|branding| {
            branding.hero.as_ref().and_then(|hero| {
                load_texture(&creation.egui_ctx, "certael-game-hero", &hero.path, true).ok()
            })
        });
        Self {
            registered,
            launch_attempt_id,
            icon,
            hero,
            status: None,
            last_refresh: Instant::now() - Duration::from_secs(1),
            ready_since: None,
            action_message: None,
            #[cfg(debug_assertions)]
            screenshot_path,
            #[cfg(debug_assertions)]
            screenshot_requested: false,
            failure_resized: false,
        }
    }

    fn refresh(&mut self) {
        if let Ok(status) = crate::status::read(&self.registered.status_path) {
            if status.launch_attempt_id.as_deref() == Some(&self.launch_attempt_id) {
                if status.state == "protected" && self.ready_since.is_none() {
                    self.ready_since = Some(Instant::now());
                }
                self.status = Some(status);
            }
        }
        self.last_refresh = Instant::now();
    }

    fn state(&self) -> &str {
        self.status
            .as_ref()
            .map(|value| value.state.as_str())
            .unwrap_or("verifying_agent_version")
    }

    fn failed(&self) -> bool {
        matches!(
            self.state(),
            "launch_failed" | "update_failed" | "expired" | "lost" | "revoked"
        )
    }

    fn display_name(&self) -> &str {
        self.registered
            .branding
            .as_ref()
            .map(|branding| branding.claims.display_name.as_str())
            .unwrap_or(&self.registered.claims.game_id)
    }

    fn publisher_name(&self) -> Option<&str> {
        self.registered
            .branding
            .as_ref()
            .map(|branding| branding.claims.publisher_name.as_str())
    }

    fn run_agent_command(&mut self, command: &str) {
        let Some(registry_root) = self.registered.state_root.parent() else {
            self.action_message = Some("The game registration cannot be located.".into());
            return;
        };
        let Ok(executable) = std::env::current_exe() else {
            self.action_message = Some("Certael Agent cannot start this action.".into());
            return;
        };
        match Command::new(executable)
            .arg(command)
            .arg("--registration-id")
            .arg(&self.registered.claims.registration_id)
            .arg("--registry-root")
            .arg(registry_root)
            .spawn()
        {
            Ok(_) => self.action_message = Some(match command {
                "repair-game" => "The registered game repair action is starting.".into(),
                "launch-offline-game" => "The game is starting without protected play.".into(),
                _ => "The requested action is starting.".into(),
            }),
            Err(_) => self.action_message = Some(
                "Certael Agent could not start that action. Close this window and use the game launcher."
                    .into(),
            ),
        }
    }
}

fn load_texture(
    context: &egui::Context,
    name: &str,
    path: &std::path::Path,
    hero: bool,
) -> Result<(egui::TextureHandle, f32)> {
    let (pixels, width, height) = if hero {
        crate::branding::decode_hero_rgba(path)?
    } else {
        crate::branding::decode_icon_rgba(path)?
    };
    let image =
        egui::ColorImage::from_rgba_unmultiplied([width as usize, height as usize], &pixels);
    Ok((
        context.load_texture(name, image, egui::TextureOptions::LINEAR),
        width as f32 / height as f32,
    ))
}

impl eframe::App for SplashApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        #[cfg(debug_assertions)]
        if let Some(path) = &self.screenshot_path {
            let screenshot = ui.input(|input| {
                input.events.iter().find_map(|event| match event {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(image) = screenshot {
                if save_screenshot(path, &image).is_ok() {
                    context.send_viewport_cmd(egui::ViewportCommand::Close);
                    return;
                }
            }
        }
        if self.last_refresh.elapsed() >= Duration::from_millis(100) {
            self.refresh();
        }
        if self
            .ready_since
            .is_some_and(|ready| ready.elapsed() >= Duration::from_millis(1200))
        {
            context.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if context.input(|input| input.key_pressed(egui::Key::Escape)) {
            context.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if self.failed() && !self.failure_resized {
            self.failure_resized = true;
            context.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1040.0, 560.0)));
        }
        context.request_repaint_after(Duration::from_millis(100));
        egui::Frame::new()
            .fill(CANVAS)
            .inner_margin(28.0)
            .show(ui, |ui| {
                self.render_header(ui);
                ui.add_space(18.0);
                let show_hero = !self.failed() && ui.available_height() >= 420.0;
                if show_hero {
                    self.render_hero(ui);
                    ui.add_space(20.0);
                }
                self.render_progress(ui);
                ui.add_space(20.0);
                if self.failed() {
                    self.render_failure(ui);
                } else {
                    self.render_active_state(ui);
                }
                ui.add_space(18.0);
                ui.separator();
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("Certael Agent")
                            .color(SECONDARY)
                            .strong(),
                    );
                    ui.add_space(12.0);
                    ui.label(
                        egui::RichText::new("Protection is confirmed by the game server.")
                            .color(MUTED),
                    );
                });
            });
        #[cfg(debug_assertions)]
        if self.screenshot_path.is_some() && !self.screenshot_requested {
            self.screenshot_requested = true;
            context.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
        }
    }
}

#[cfg(debug_assertions)]
fn save_screenshot(path: &std::path::Path, image: &egui::ColorImage) -> Result<()> {
    let file = std::fs::File::create(path)?;
    let mut encoder = png::Encoder::new(file, image.size[0] as u32, image.size[1] as u32);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header()?;
    let mut bytes = Vec::with_capacity(image.pixels.len() * 4);
    for pixel in &image.pixels {
        bytes.extend_from_slice(&pixel.to_array());
    }
    writer.write_image_data(&bytes)?;
    Ok(())
}

impl SplashApp {
    fn render_header(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if let Some(icon) = &self.icon {
                ui.add(
                    egui::Image::new(icon)
                        .fit_to_exact_size(egui::vec2(52.0, 52.0))
                        .corner_radius(6),
                );
                ui.add_space(10.0);
            }
            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new(self.display_name())
                        .size(25.0)
                        .color(PRIMARY)
                        .strong(),
                );
                if let Some(publisher) = self.publisher_name() {
                    ui.label(egui::RichText::new(publisher).size(15.0).color(SECONDARY));
                }
            });
        });
    }

    fn render_hero(&self, ui: &mut egui::Ui) {
        let available = ui.available_width();
        let vertical_budget = (ui.available_height() - 210.0).max(160.0);
        let height = (available / 2.28).min(420.0).min(vertical_budget);
        if let Some((hero, source_aspect)) = &self.hero {
            let target_aspect = available / height;
            let uv = if *source_aspect > target_aspect {
                let visible = target_aspect / *source_aspect;
                let inset = (1.0 - visible) * 0.5;
                egui::Rect::from_min_max(egui::pos2(inset, 0.0), egui::pos2(1.0 - inset, 1.0))
            } else {
                let visible = *source_aspect / target_aspect;
                let inset = (1.0 - visible) * 0.5;
                egui::Rect::from_min_max(egui::pos2(0.0, inset), egui::pos2(1.0, 1.0 - inset))
            };
            ui.add(
                egui::Image::new(hero)
                    .fit_to_exact_size(egui::vec2(available, height))
                    .maintain_aspect_ratio(false)
                    .uv(uv)
                    .corner_radius(6),
            );
        } else {
            egui::Frame::new()
                .fill(SURFACE)
                .stroke(egui::Stroke::new(1.0, BORDER))
                .corner_radius(6)
                .inner_margin(24.0)
                .show(ui, |ui| {
                    ui.set_min_height(height - 48.0);
                    ui.vertical_centered(|ui| {
                        ui.add_space((height - 116.0).max(0.0) * 0.5);
                        if let Some(icon) = &self.icon {
                            ui.add(
                                egui::Image::new(icon)
                                    .fit_to_exact_size(egui::vec2(76.0, 76.0))
                                    .corner_radius(8),
                            );
                        }
                        ui.label(
                            egui::RichText::new(self.display_name())
                                .size(24.0)
                                .strong()
                                .color(PRIMARY),
                        );
                    });
                });
        }
    }

    fn render_progress(&self, ui: &mut egui::Ui) {
        let reason = self
            .status
            .as_ref()
            .and_then(|status| status.public_reason.as_deref());
        let failed_phase = self.failed().then(|| failure_phase(reason));
        let phase = failed_phase.unwrap_or_else(|| phase_for_state(self.state()));
        let width = ui.available_width();
        let height = 70.0;
        let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
        let painter = ui.painter();
        let left = rect.left() + 56.0;
        let right = rect.right() - 56.0;
        let center_y = rect.top() + 22.0;
        let positions = [left, (left + right) * 0.5, right];
        let labels = ["Checks", "Launching protected mode", "Protected session"];
        painter.line_segment(
            [egui::pos2(left, center_y), egui::pos2(right, center_y)],
            egui::Stroke::new(2.0, BORDER),
        );
        if phase > 0 {
            let end = positions[phase.min(2)];
            painter.line_segment(
                [egui::pos2(left, center_y), egui::pos2(end, center_y)],
                egui::Stroke::new(2.0, ACCENT),
            );
        }
        for (index, x) in positions.into_iter().enumerate() {
            let center = egui::pos2(x, center_y);
            let failed = failed_phase == Some(index);
            let complete = index < phase || self.state() == "protected";
            let active = index == phase && self.state() != "protected" && !failed;
            painter.circle_filled(center, 13.0, CANVAS);
            painter.circle_stroke(
                center,
                if active || failed { 13.0 } else { 11.0 },
                egui::Stroke::new(
                    if active || failed { 3.0 } else { 2.0 },
                    if failed {
                        RECOVERY
                    } else if complete || active {
                        ACCENT
                    } else {
                        MUTED
                    },
                ),
            );
            if failed {
                painter.line_segment(
                    [egui::pos2(x, center_y - 6.0), egui::pos2(x, center_y + 2.0)],
                    egui::Stroke::new(2.0, RECOVERY),
                );
                painter.circle_filled(egui::pos2(x, center_y + 7.0), 1.5, RECOVERY);
            } else if complete {
                painter.line_segment(
                    [
                        egui::pos2(x - 5.0, center_y),
                        egui::pos2(x - 1.0, center_y + 4.0),
                    ],
                    egui::Stroke::new(2.0, ACCENT),
                );
                painter.line_segment(
                    [
                        egui::pos2(x - 1.0, center_y + 4.0),
                        egui::pos2(x + 6.0, center_y - 5.0),
                    ],
                    egui::Stroke::new(2.0, ACCENT),
                );
            } else if active {
                painter.circle_filled(center, 5.0, ACCENT);
            }
            painter.text(
                egui::pos2(x, rect.top() + 48.0),
                egui::Align2::CENTER_CENTER,
                labels[index],
                egui::FontId::proportional(if index == 1 { 14.0 } else { 13.0 }),
                if failed {
                    RECOVERY
                } else if active {
                    PRIMARY
                } else if complete {
                    ACCENT
                } else {
                    MUTED
                },
            );
        }
    }

    fn render_active_state(&self, ui: &mut egui::Ui) {
        let (title, body) = state_copy(self.state(), self.display_name());
        ui.vertical_centered(|ui| {
            ui.label(
                egui::RichText::new(title)
                    .size(23.0)
                    .strong()
                    .color(PRIMARY),
            );
            ui.add_space(6.0);
            ui.label(egui::RichText::new(body).size(15.0).color(SECONDARY));
        });
    }

    fn render_failure(&mut self, ui: &mut egui::Ui) {
        let reason = self
            .status
            .as_ref()
            .and_then(|value| value.public_reason.as_deref());
        let (message, help) = failure_copy(reason);
        ui.label(
            egui::RichText::new("Could not start protected play")
                .size(27.0)
                .strong()
                .color(PRIMARY),
        );
        ui.add_space(8.0);
        ui.label(egui::RichText::new(message).size(18.0).color(PRIMARY));
        ui.label(egui::RichText::new(help).size(15.0).color(SECONDARY));
        ui.add_space(18.0);
        ui.horizontal_wrapped(|ui| {
            if !self
                .registered
                .claims
                .repair_executable_relative_path
                .is_empty()
                && ui
                    .add_sized(
                        [180.0, 46.0],
                        egui::Button::new(
                            egui::RichText::new("Repair game files")
                                .strong()
                                .color(PRIMARY),
                        )
                        .fill(BUTTON)
                        .stroke(egui::Stroke::new(2.0, FOCUS)),
                    )
                    .clicked()
            {
                self.run_agent_command("repair-game");
            }
            if self.registered.claims.offline_play_allowed
                && ui
                    .add_sized([140.0, 46.0], egui::Button::new("Play offline"))
                    .on_hover_text(
                        "Starts without protected play. Online protected modes remain unavailable.",
                    )
                    .clicked()
            {
                self.run_agent_command("launch-offline-game");
            }
            if ui
                .add_sized([92.0, 46.0], egui::Button::new("Close"))
                .clicked()
            {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });
        if self.registered.claims.offline_play_allowed {
            ui.label(
                egui::RichText::new("Offline play is available only because this game allows it.")
                    .size(13.0)
                    .color(MUTED),
            );
        }
        if let Some(message) = &self.action_message {
            ui.add_space(8.0);
            ui.label(egui::RichText::new(message).color(ACCENT));
        }
    }
}

fn phase_for_state(state: &str) -> usize {
    match state {
        "verifying_agent_version"
        | "loading_signed_registration"
        | "checking_required_update"
        | "installing_required_update"
        | "update_required"
        | "update_ready"
        | "update_failed"
        | "hashing_registered_game_files" => 0,
        "starting_game" | "awaiting_server_admission" | "verifying_signed_launch_bundle" => 1,
        "protected" => 2,
        _ => 1,
    }
}

fn failure_phase(reason: Option<&str>) -> usize {
    match reason {
        Some("REGISTERED_GAME_FILES_MISMATCH")
        | Some("REGISTERED_GAME_FILES_UNREADABLE")
        | Some("AGENT_VERSION_UNVERIFIED")
        | Some("AGENT_UPDATE_FAILED") => 0,
        _ => 1,
    }
}

fn state_copy(state: &str, game: &str) -> (String, &'static str) {
    match state {
        "verifying_agent_version" => ("Verifying Certael Agent".into(), "Checking the selected stable Agent version."),
        "loading_signed_registration" => ("Loading signed game registration".into(), "Confirming this game’s publisher and protected-play settings."),
        "checking_required_update" => ("Checking required Agent update".into(), "Protected play will continue only with a supported Agent version."),
        "installing_required_update" | "update_required" => ("Updating Certael Agent".into(), "Verifying and staging the required signed update."),
        "update_ready" => ("Agent update is ready".into(), "Restart protected play to use the verified update."),
        "hashing_registered_game_files" => ("Checking protected game files".into(), "Hashing the files listed in the signed game registration."),
        "starting_game" => (format!("Starting {game}"), "The game is launching with its private Agent channel."),
        "awaiting_server_admission" => ("Waiting for secure server admission".into(), "The game is running. Protection is not confirmed until the server admits this session."),
        "verifying_signed_launch_bundle" => ("Establishing protected session".into(), "Verifying the signed policy, launch grant, and build manifest."),
        "protected" => ("Protected session ready".into(), "The game server admitted this verified session."),
        _ => ("Launching protected mode".into(), "Certael Agent is preparing the protected session."),
    }
}

fn failure_copy(reason: Option<&str>) -> (&'static str, &'static str) {
    match reason {
        Some("REGISTERED_GAME_FILES_MISMATCH") | Some("AGENT_BUILD_MISMATCH") => (
            "Game files do not match the registered build.",
            "Repair the game files, then try protected play again.",
        ),
        Some("AGENT_VERSION_UNVERIFIED") => (
            "The selected Certael Agent version could not be verified.",
            "Repair or reinstall Certael Agent, then try again.",
        ),
        Some("AGENT_UPDATE_FAILED") => (
            "The required Agent update could not be installed.",
            "Check your connection or run Agent repair, then try again.",
        ),
        Some("AGENT_ADMISSION_TIMEOUT") => (
            "The game server did not admit this session in time.",
            "Check the game service status and try protected play again.",
        ),
        _ => (
            "Certael Agent could not establish protected play.",
            "Close this window and try again. The game was not marked protected.",
        ),
    }
}

struct GameView {
    registration_id: String,
    state: String,
    reason: Option<String>,
}

struct AgentApp {
    games: Vec<GameView>,
    last_refresh: Instant,
    action: Option<String>,
}

impl Default for AgentApp {
    fn default() -> Self {
        let mut value = Self {
            games: vec![],
            last_refresh: Instant::now() - Duration::from_secs(10),
            action: None,
        };
        value.refresh();
        value
    }
}

impl AgentApp {
    fn refresh(&mut self) {
        let root = crate::registry::default_root();
        self.games = crate::registry::list(&root)
            .unwrap_or_default()
            .into_iter()
            .map(|registration_id| {
                let status = crate::status::path(&registration_id)
                    .ok()
                    .and_then(|path| crate::status::read(&path).ok());
                GameView {
                    registration_id,
                    state: status
                        .as_ref()
                        .map(|value| value.state.clone())
                        .unwrap_or_else(|| "not_running".into()),
                    reason: status.and_then(|value| value.public_reason),
                }
            })
            .collect();
        self.last_refresh = Instant::now();
    }

    fn run_action(&mut self, registration_id: &str, command: &str) {
        let executable = match std::env::current_exe() {
            Ok(value) => value,
            Err(_) => {
                self.action = Some("Agent installation cannot be resolved; run repair.".into());
                return;
            }
        };
        if command == "update-registered-game" {
            match spawn_elevated_update(&executable, registration_id) {
                Ok(()) => {
                    self.action = Some(format!(
                        "Checking trusted updates for {registration_id} with administrator approval…"
                    ));
                }
                Err(_) => {
                    self.action = Some(
                        "The secure updater could not request administrator approval; run the Agent update command as administrator."
                            .into(),
                    );
                }
            }
            return;
        }
        let mut process = Command::new(executable);
        process
            .arg(command)
            .arg("--registration-id")
            .arg(registration_id);
        match process.spawn() {
            Ok(_) => {
                self.action = Some(if command == "launch-game" {
                    format!("Starting {registration_id} in protected mode…")
                } else {
                    format!("Checking trusted updates for {registration_id}…")
                });
            }
            Err(_) => {
                self.action =
                    Some("Action failed to start; run Agent repair as administrator.".into());
            }
        }
    }

    fn run_recovery(&mut self, command: &str) {
        let Ok(executable) = std::env::current_exe() else {
            self.action = Some("Agent installation cannot be resolved; reinstall Agent.".into());
            return;
        };
        let install_root = crate::default_install_root();
        match Command::new(executable)
            .arg(command)
            .arg("--install-root")
            .arg(install_root)
            .spawn()
        {
            Ok(_) => self.action = Some(format!("Agent {command} started…")),
            Err(_) => self.action = Some("Recovery failed to start; run as administrator.".into()),
        }
    }
}

#[cfg(target_os = "linux")]
fn spawn_elevated_update(executable: &std::path::Path, registration_id: &str) -> Result<()> {
    Command::new("pkexec")
        .arg(executable)
        .arg("update-registered-game")
        .arg("--registration-id")
        .arg(registration_id)
        .arg("--activate")
        .spawn()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn spawn_elevated_update(executable: &std::path::Path, registration_id: &str) -> Result<()> {
    const SCRIPT: &str = r#"on run argv
set commandText to quoted form of item 1 of argv & " update-registered-game --registration-id " & quoted form of item 2 of argv & " --activate"
do shell script commandText with administrator privileges
end run"#;
    Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(SCRIPT)
        .arg(executable)
        .arg(registration_id)
        .spawn()?;
    Ok(())
}

#[cfg(windows)]
fn spawn_elevated_update(executable: &std::path::Path, registration_id: &str) -> Result<()> {
    use std::{iter, os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};

    let operation: Vec<u16> = "runas".encode_utf16().chain(iter::once(0)).collect();
    let executable: Vec<u16> = executable
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let parameters: Vec<u16> =
        format!("update-registered-game --registration-id \"{registration_id}\" --activate")
            .encode_utf16()
            .chain(iter::once(0))
            .collect();
    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            operation.as_ptr(),
            executable.as_ptr(),
            parameters.as_ptr(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if result as isize <= 32 {
        return Err(anyhow!("administrator approval was denied or unavailable"));
    }
    Ok(())
}

impl eframe::App for AgentApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.last_refresh.elapsed() >= Duration::from_secs(1) {
            self.refresh();
        }
        ui.ctx().request_repaint_after(Duration::from_secs(1));
        ui.heading("Certael Agent");
        ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));
        ui.separator();
        ui.heading("Registered games");
        if self.games.is_empty() {
            ui.label("No games are registered with Certael Agent.");
        }
        let mut requested = None;
        for game in &self.games {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.strong(&game.registration_id);
                    ui.label(format!("Status: {}", game.state));
                });
                if let Some(reason) = &game.reason {
                    ui.label(format!("Reason: {reason}"));
                }
                ui.horizontal(|ui| {
                    if ui.button("Launch protected").clicked() {
                        requested = Some((game.registration_id.clone(), "launch-game"));
                    }
                    if ui.button("Check trusted update").clicked() {
                        requested = Some((game.registration_id.clone(), "update-registered-game"));
                    }
                });
            });
        }
        if let Some((id, command)) = requested {
            self.run_action(&id, command);
        }
        if let Some(action) = &self.action {
            ui.separator();
            ui.label(action);
        }
        ui.separator();
        ui.heading("Recovery");
        ui.horizontal(|ui| {
            if ui.button("Repair interrupted update").clicked() {
                self.run_recovery("recover-update");
            }
            if ui.button("Roll back Agent").clicked() {
                self.run_recovery("rollback-update");
            }
        });
        ui.separator();
        ui.heading("Privacy boundary");
        ui.label("Certael can report approved game-file hashes, process relationship, loaded image names, debugger observation, probe health, and protocol health.");
        ui.label("It does not collect keystrokes, screenshots, raw memory, window titles, identities, unrelated processes, or network history.");
        ui.label("Client evidence is advisory. The authoritative game server decides gameplay.");
        ui.label("Offline games never require Certael Agent.");
        ui.with_layout(egui::Layout::bottom_up(egui::Align::RIGHT), |ui| {
            if ui.button("Exit").clicked() {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });
    }
}

#[cfg(test)]
mod splash_tests {
    use super::*;

    fn relative_luminance(color: egui::Color32) -> f32 {
        fn channel(value: u8) -> f32 {
            let value = value as f32 / 255.0;
            if value <= 0.04045 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        }
        0.2126 * channel(color.r()) + 0.7152 * channel(color.g()) + 0.0722 * channel(color.b())
    }

    fn contrast(foreground: egui::Color32, background: egui::Color32) -> f32 {
        let foreground = relative_luminance(foreground);
        let background = relative_luminance(background);
        (foreground.max(background) + 0.05) / (foreground.min(background) + 0.05)
    }

    #[test]
    fn splash_text_tokens_meet_wcag_aa_on_the_canvas() {
        for color in [PRIMARY, SECONDARY, MUTED, ACCENT, RECOVERY] {
            assert!(
                contrast(color, CANVAS) >= 4.5,
                "{color:?} lacks AA contrast"
            );
        }
        assert!(contrast(PRIMARY, BUTTON) >= 4.5);
    }

    #[test]
    fn every_runtime_milestone_has_plain_language_copy_and_a_phase() {
        let states = [
            "verifying_agent_version",
            "loading_signed_registration",
            "checking_required_update",
            "installing_required_update",
            "update_required",
            "update_ready",
            "hashing_registered_game_files",
            "starting_game",
            "awaiting_server_admission",
            "verifying_signed_launch_bundle",
            "protected",
        ];
        for state in states {
            let (title, body) = state_copy(state, "Hollowstar");
            assert!(!title.is_empty());
            assert!(!body.is_empty());
            assert!(phase_for_state(state) <= 2);
        }
    }

    #[test]
    fn known_failures_are_actionable_and_located_on_the_progress_rail() {
        let reasons = [
            "REGISTERED_GAME_FILES_MISMATCH",
            "AGENT_BUILD_MISMATCH",
            "AGENT_VERSION_UNVERIFIED",
            "AGENT_UPDATE_FAILED",
            "AGENT_ADMISSION_TIMEOUT",
        ];
        for reason in reasons {
            let (message, help) = failure_copy(Some(reason));
            assert!(!message.is_empty());
            assert!(!help.is_empty());
            assert!(failure_phase(Some(reason)) <= 1);
        }
    }
}
