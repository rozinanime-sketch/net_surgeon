//! Трей-иконка: вкл/выкл фоновой службы net_surgeon одним кликом.
//!
//! Поверх пользовательской службы systemd (`./run.sh install`): «включить» —
//! это `systemctl --user start net_surgeon.service`, «выключить» — `stop`.
//! Состояние опрашивается раз в пару секунд, цвет значка его отражает:
//! зелёный — обход идёт, серый — выключен.
//!
//! Отдельный бинарь за feature `tray`, только Linux-десктоп: GUI и D-Bus
//! ядру не нужны. Значок рисуется пикселями (цветная точка), а не берётся из
//! темы, чтобы состояние читалось одинаково в любом окружении.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use ksni::menu::StandardItem;
use ksni::{Icon, MenuItem, ToolTip, Tray, TrayService};

const UNIT: &str = "net_surgeon.service";

/// Путь к файлу службы — по нему понимаем, установлена ли она вообще.
fn unit_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
            home.push(".config");
            home
        });
    base.join("systemd/user").join(UNIT)
}

fn service_installed() -> bool {
    unit_path().exists()
}

/// Идёт ли служба прямо сейчас.
fn service_active() -> bool {
    Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", UNIT])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Запустить (`true`) или остановить (`false`) службу.
fn set_service(on: bool) {
    let action = if on { "start" } else { "stop" };
    let _ = Command::new("systemctl").args(["--user", action, UNIT]).status();
}

/// Значок — залитый круг: зелёный, когда обход включён, иначе серый. Рисуем
/// сами, без темы: так цвет-состояние одинаков в KDE, GNOME и прочих.
fn dot(on: bool) -> Vec<Icon> {
    const SIZE: i32 = 24;
    let (r, g, b) = if on { (46u8, 160, 67) } else { (128u8, 128, 128) };
    let center = (SIZE as f32 - 1.0) / 2.0;
    let radius = SIZE as f32 / 2.0 - 1.5;
    let mut data = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            if dx * dx + dy * dy <= radius * radius {
                data.extend_from_slice(&[255, r, g, b]); // ARGB, непрозрачный
            } else {
                data.extend_from_slice(&[0, 0, 0, 0]); // прозрачный фон
            }
        }
    }
    vec![Icon { width: SIZE, height: SIZE, data }]
}

/// Переключить службу и тут же перечитать фактическое состояние.
fn toggle(state: &mut SurgeonTray) {
    if !state.installed {
        return;
    }
    set_service(!state.active);
    state.active = service_active();
}

struct SurgeonTray {
    active: bool,
    installed: bool,
}

impl Tray for SurgeonTray {
    fn id(&self) -> String {
        "net_surgeon".into()
    }

    fn title(&self) -> String {
        "net_surgeon".into()
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        dot(self.active)
    }

    fn tool_tip(&self) -> ToolTip {
        let description = if !self.installed {
            "служба не установлена — ./run.sh install".to_string()
        } else if self.active {
            "обход включён".to_string()
        } else {
            "обход выключен".to_string()
        };
        ToolTip {
            title: "net_surgeon".into(),
            description,
            icon_name: String::new(),
            icon_pixmap: Vec::new(),
        }
    }

    // Левый клик по значку — быстрый тумблер.
    fn activate(&mut self, _x: i32, _y: i32) {
        toggle(self);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let status = if !self.installed {
            "Служба не установлена".to_string()
        } else if self.active {
            "● Обход включён".to_string()
        } else {
            "○ Обход выключен".to_string()
        };
        let toggle_label = if self.active { "Выключить" } else { "Включить" };

        vec![
            StandardItem { label: status, enabled: false, ..Default::default() }.into(),
            MenuItem::Separator,
            StandardItem {
                label: toggle_label.into(),
                enabled: self.installed,
                activate: Box::new(toggle),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Выход (не трогает службу)".into(),
                activate: Box::new(|_| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

fn main() {
    let tray = SurgeonTray { active: service_active(), installed: service_installed() };
    let service = TrayService::new(tray);
    let handle = service.handle();
    service.spawn();

    // Нет внешнего сигнала о смене состояния службы (её могли запустить и из
    // консоли), поэтому просто опрашиваем systemctl и обновляем значок.
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let active = service_active();
        let installed = service_installed();
        handle.update(|t: &mut SurgeonTray| {
            t.active = active;
            t.installed = installed;
        });
    }
}
