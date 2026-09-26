//! Системный прокси Windows: включается вместе с прокси программы и
//! возвращается к прежнему виду при выходе.
//!
//! # Зачем
//!
//! Прозрачного режима на Windows нет, и без этого модуля прокси пришлось бы
//! прописывать в настройках руками, а после выхода не забыть выключить.
//! Браузеры (Chrome, Edge, Firefox по умолчанию) и большинство программ
//! берут прокси из настроек Windows, так что одной записи в реестре хватает,
//! чтобы программа запускалась двойным щелчком.
//!
//! # Почему возврат настроек устроен с запасом
//!
//! Это тот же случай, что с правилами iptables в Linux (см. run.sh): если
//! программа завершилась, а прокси в настройках остался, весь браузер
//! упирается в порт, где никто не слушает, и выглядит это как пропавший
//! интернет, а не как забытая настройка. Поэтому прежние значения
//! возвращаются при любом выходе, который удаётся поймать:
//!
//! * обычный выход из интерфейса и Ctrl-C без него — `restore` в `main`;
//! * паника — через `Drop` у [`RestoreOnDrop`];
//! * закрытие окна консоли, выход из системы, выключение — обработчиком
//!   консольных событий: система даёт на него несколько секунд.
//!
//! Не ловится только принудительное завершение (диспетчер задач). На этот
//! случай следующий запуск узнаёт свой адрес в настройках и считает, что
//! до него прокси был выключен.

use std::io;
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows_sys::Win32::Networking::WinInet::{
    INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
};
use windows_sys::Win32::System::Console::{
    CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT, SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD, REG_SAM_FLAGS, REG_SZ, RRF_RT_REG_DWORD,
    RRF_RT_REG_SZ, RegCloseKey, RegDeleteValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
};

/// Где Windows хранит настройки прокси текущего пользователя. Прав
/// администратора запись сюда не требует.
const SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Настройки до запуска. `None` — значения не было, и при возврате его
/// нужно удалить, а не записать пустым.
struct Saved {
    enable: Option<u32>,
    server: Option<String>,
    bypass: Option<String>,
}

/// Заполняется при первом включении и забирается при возврате, поэтому
/// повторный `restore` ничего не делает.
static SAVED: Mutex<Option<Saved>> = Mutex::new(None);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn check(rc: WIN32_ERROR) -> io::Result<()> {
    if rc == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc as i32))
    }
}

/// Открытый ключ реестра; закрывается сам.
struct Key(HKEY);

impl Key {
    fn open(access: REG_SAM_FLAGS) -> io::Result<Key> {
        let mut key: HKEY = std::ptr::null_mut();
        let path = wide(SETTINGS_KEY);
        check(unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, access, &mut key) })?;
        Ok(Key(key))
    }

    fn get_dword(&self, name: &str) -> io::Result<Option<u32>> {
        let name = wide(name);
        let mut value: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;
        let rc = unsafe {
            RegGetValueW(
                self.0,
                std::ptr::null(),
                name.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                &mut value as *mut u32 as *mut core::ffi::c_void,
                &mut size,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        check(rc)?;
        Ok(Some(value))
    }

    fn get_string(&self, name: &str) -> io::Result<Option<String>> {
        let name = wide(name);
        // Первый вызов узнаёт размер в байтах, вместе с завершающим нулём.
        let mut size: u32 = 0;
        let rc = unsafe {
            RegGetValueW(
                self.0,
                std::ptr::null(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        check(rc)?;

        let mut buf = vec![0u16; (size as usize).div_ceil(2)];
        check(unsafe {
            RegGetValueW(
                self.0,
                std::ptr::null(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                &mut size,
            )
        })?;
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Ok(Some(String::from_utf16_lossy(&buf[..len])))
    }

    fn set_dword(&self, name: &str, value: u32) -> io::Result<()> {
        let name = wide(name);
        check(unsafe {
            RegSetValueExW(
                self.0,
                name.as_ptr(),
                0,
                REG_DWORD,
                &value as *const u32 as *const u8,
                std::mem::size_of::<u32>() as u32,
            )
        })
    }

    fn set_string(&self, name: &str, value: &str) -> io::Result<()> {
        let name = wide(name);
        let data = wide(value);
        check(unsafe {
            RegSetValueExW(
                self.0,
                name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr() as *const u8,
                (data.len() * 2) as u32,
            )
        })
    }

    fn delete(&self, name: &str) -> io::Result<()> {
        let name = wide(name);
        let rc = unsafe { RegDeleteValueW(self.0, name.as_ptr()) };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        check(rc)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

/// Сообщает запущенным программам, что настройки изменились. Без этого
/// браузер, открытый до запуска, продолжал бы ходить напрямую.
fn notify() {
    unsafe {
        InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
        InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
    }
}

/// Закрытие окна консоли, выход из системы, выключение. Возвращает FALSE:
/// событие должны увидеть и остальные обработчики, включая системный,
/// который завершает процесс.
unsafe extern "system" fn on_console_event(event: u32) -> windows_sys::core::BOOL {
    if matches!(event, CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT) {
        let _ = restore();
    }
    0
}

/// Прописывает программу системным прокси. Возвращает адрес, который
/// теперь стоит в настройках.
///
/// Можно звать повторно, например после перезапуска прокси с другим портом:
/// прежние настройки запоминаются только в первый раз.
pub fn enable(port: u16) -> io::Result<String> {
    // Слушатель может быть и на 0.0.0.0, но ходить к себе надёжнее по
    // петлевому адресу.
    let ours = format!("127.0.0.1:{}", port);
    let key = Key::open(KEY_READ | KEY_WRITE)?;

    let mut saved = SAVED.lock().unwrap_or_else(|e| e.into_inner());
    if saved.is_none() {
        let current = Saved {
            enable: key.get_dword("ProxyEnable")?,
            server: key.get_string("ProxyServer")?,
            bypass: key.get_string("ProxyOverride")?,
        };
        // Наш же адрес — след прошлого запуска, который убили, не дав
        // убрать за собой. Вернуть его значило бы оставить прокси навсегда.
        let stale = current.enable == Some(1) && current.server.as_deref() == Some(ours.as_str());
        *saved = Some(if stale { Saved { enable: Some(0), server: None, bypass: None } } else { current });

        unsafe { SetConsoleCtrlHandler(Some(on_console_event), 1) };
    }

    key.set_dword("ProxyEnable", 1)?;
    key.set_string("ProxyServer", &ours)?;
    // Локальные адреса мимо прокси: роутер, принтер, сама программа.
    key.set_string("ProxyOverride", "<local>")?;
    notify();

    Ok(ours)
}

/// Возвращает настройки, какими они были до [`enable`]. `Ok(false)` —
/// возвращать нечего: прокси не включался или уже возвращён.
pub fn restore() -> io::Result<bool> {
    let Some(saved) = SAVED.lock().unwrap_or_else(|e| e.into_inner()).take() else {
        return Ok(false);
    };
    let key = Key::open(KEY_WRITE)?;

    match saved.enable {
        Some(v) => key.set_dword("ProxyEnable", v)?,
        None => key.delete("ProxyEnable")?,
    }
    match &saved.server {
        Some(v) => key.set_string("ProxyServer", v)?,
        None => key.delete("ProxyServer")?,
    }
    match &saved.bypass {
        Some(v) => key.set_string("ProxyOverride", v)?,
        None => key.delete("ProxyOverride")?,
    }
    notify();

    Ok(true)
}

/// Возвращает настройки при выходе из области видимости, в том числе при
/// панике, которая иначе прошла бы мимо `restore` в конце `main`.
pub struct RestoreOnDrop;

impl Drop for RestoreOnDrop {
    fn drop(&mut self) {
        match restore() {
            Ok(true) => eprintln!("[i] {}", rust_i18n::t!("startup.system_proxy_restored")),
            Ok(false) => {}
            Err(e) => eprintln!(
                "[{}] {}",
                crate::observability::glyph::ERROR,
                rust_i18n::t!("startup.system_proxy_restore_failed", error = e)
            ),
        }
    }
}
