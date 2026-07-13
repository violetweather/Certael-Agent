use anyhow::{anyhow, Result};
use eframe::egui;

pub fn run() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Certael Agent")
            .with_inner_size([620.0, 520.0])
            .with_min_inner_size([520.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Certael Agent",
        options,
        Box::new(|_| Ok(Box::<AgentApp>::default())),
    )
    .map_err(|error| anyhow!(error.to_string()))
}

struct AgentApp {
    status: &'static str,
}

impl Default for AgentApp {
    fn default() -> Self {
        Self {
            status: "Ready — no protected game is running",
        }
    }
}

impl eframe::App for AgentApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(context, |ui| {
            ui.heading("Certael Agent");
            ui.add_space(8.0);
            ui.label(self.status);
            ui.separator();
            ui.heading("What Certael can report");
            ui.label("• Approved game-file hashes and executable identity");
            ui.label("• Agent/game process relationship and loaded image names");
            ui.label("• Debugger observation and in-process probe health");
            ui.label("• Report time, build, session, and protocol health");
            ui.add_space(8.0);
            ui.heading("What Certael does not collect");
            ui.label("• Keystrokes, screenshots, raw memory, or window titles");
            ui.label("• Usernames, email addresses, or full command lines");
            ui.label("• Unrelated process inventories or network history");
            ui.add_space(8.0);
            ui.separator();
            ui.label(
                "Client evidence is advisory. The authoritative game server decides gameplay.",
            );
            ui.label("Offline games never require Certael Agent.");
            ui.with_layout(egui::Layout::bottom_up(egui::Align::RIGHT), |ui| {
                if ui.button("Exit").clicked() {
                    context.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                ui.label(format!("Version {} (pre-1.0)", env!("CARGO_PKG_VERSION")));
            });
        });
    }
}
