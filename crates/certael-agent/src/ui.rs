use anyhow::{anyhow, Result};
use eframe::egui;
use std::{
    process::Command,
    time::{Duration, Instant},
};

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
