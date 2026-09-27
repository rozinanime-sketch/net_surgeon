//! Вызовы WinDivert.dll.
//!
//! Библиотека подгружается во время работы, а не при запуске: без неё
//! программа должна стартовать как раньше, с системным прокси, а не падать
//! с «не найден WinDivert.dll». Так же не нужна и WinDivert.lib при сборке.
//!
//! Объявления — из `windivert.h` версии 2.2.

use std::ffi::c_void;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetProcAddress, LoadLibraryW};

/// `WINDIVERT_ADDRESS`: метаданные пакета.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    timestamp: i64,
    /// Битовые поля Layer, Event, Sniffed, Outbound, Loopback, …
    bits: u32,
    reserved2: u32,
    data: [u8; 64],
}

const _: () = assert!(std::mem::size_of::<Address>() == 80);

const OUTBOUND: u32 = 1 << 17;

impl Address {
    pub fn zeroed() -> Self {
        Address { timestamp: 0, bits: 0, reserved2: 0, data: [0; 64] }
    }

    pub fn outbound(&self) -> bool {
        self.bits & OUTBOUND != 0
    }

    pub fn set_outbound(&mut self, outbound: bool) {
        if outbound {
            self.bits |= OUTBOUND;
        } else {
            self.bits &= !OUTBOUND;
        }
    }
}

/// Слой сетевых пакетов этой машины.
const LAYER_NETWORK: i32 = 0;
const SHUTDOWN_BOTH: i32 = 3;

/// Наибольший пакет: заголовки плюс 64 КБ данных.
pub const MTU_MAX: usize = 40 + 0xffff;

type OpenFn = unsafe extern "C" fn(*const u8, i32, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "C" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "C" fn(HANDLE, *const c_void, u32, *mut u32, *const Address) -> i32;
type ShutdownFn = unsafe extern "C" fn(HANDLE, i32) -> i32;
type CloseFn = unsafe extern "C" fn(HANDLE) -> i32;
type ChecksumsFn = unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32;

struct Api {
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    checksums: ChecksumsFn,
}

/// Путь к WinDivert.dll: рядом с exe, а не где попало. `LoadLibraryW` с
/// голым именем искал бы и в текущей папке, и в PATH, а процесс работает
/// с правами администратора.
fn dll_path() -> Option<Vec<u16>> {
    let mut buf = vec![0u16; 32768];
    let len = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len == 0 || len >= buf.len() {
        return None;
    }
    let exe = std::path::PathBuf::from(String::from_utf16_lossy(&buf[..len]));
    let dll = exe.parent()?.join("WinDivert.dll");
    use std::os::windows::ffi::OsStrExt;
    Some(dll.as_os_str().encode_wide().chain(Some(0)).collect())
}

fn load() -> Result<Api, String> {
    let path = dll_path().ok_or_else(|| "GetModuleFileNameW".to_string())?;
    let module = unsafe { LoadLibraryW(path.as_ptr()) };
    if module.is_null() {
        return Err(rust_i18n::t!("err.windivert_dll_missing").into_owned());
    }
    let sym = |name: &[u8]| {
        let f = unsafe { GetProcAddress(module, name.as_ptr()) };
        f.ok_or_else(|| format!("WinDivert.dll: {}", String::from_utf8_lossy(&name[..name.len() - 1])))
    };
    // SAFETY: сигнатуры повторяют windivert.h; библиотека не выгружается
    // до конца процесса, так что указатели живут вечно.
    unsafe {
        Ok(Api {
            open: std::mem::transmute::<unsafe extern "system" fn() -> isize, OpenFn>(sym(b"WinDivertOpen\0")?),
            recv: std::mem::transmute::<unsafe extern "system" fn() -> isize, RecvFn>(sym(b"WinDivertRecv\0")?),
            send: std::mem::transmute::<unsafe extern "system" fn() -> isize, SendFn>(sym(b"WinDivertSend\0")?),
            shutdown: std::mem::transmute::<unsafe extern "system" fn() -> isize, ShutdownFn>(sym(b"WinDivertShutdown\0")?),
            close: std::mem::transmute::<unsafe extern "system" fn() -> isize, CloseFn>(sym(b"WinDivertClose\0")?),
            checksums: std::mem::transmute::<unsafe extern "system" fn() -> isize, ChecksumsFn>(
                sym(b"WinDivertHelperCalcChecksums\0")?,
            ),
        })
    }
}

fn api() -> Result<&'static Api, String> {
    static API: OnceLock<Result<Api, String>> = OnceLock::new();
    API.get_or_init(load).as_ref().map_err(Clone::clone)
}

/// Открытый перехват. Закрывается при уничтожении; если процесс убит,
/// дескриптор закрывает система, и перехват пропадает вместе с ним.
pub struct Handle {
    api: &'static Api,
    raw: HANDLE,
}

// SAFETY: дескриптор WinDivert — объект ядра, функции библиотеки можно звать
// из любого потока; Shutdown для того и сделан, чтобы будить Recv из другого.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    pub fn open(filter: &str) -> Result<Handle, String> {
        let api = api()?;
        let filter = std::ffi::CString::new(filter).map_err(|e| e.to_string())?;
        let raw = unsafe { (api.open)(filter.as_ptr().cast(), LAYER_NETWORK, 0, 0) };
        if raw == INVALID_HANDLE_VALUE {
            return Err(open_error(std::io::Error::last_os_error()));
        }
        Ok(Handle { api, raw })
    }

    /// Ждёт пакет. `None` — перехват закрыт через [`Handle::shutdown`].
    pub fn recv(&self, buf: &mut [u8], addr: &mut Address) -> Option<std::io::Result<usize>> {
        let mut len = 0u32;
        let ok = unsafe { (self.api.recv)(self.raw, buf.as_mut_ptr().cast(), buf.len() as u32, &mut len, addr) };
        if ok != 0 {
            return Some(Ok(len as usize));
        }
        let err = std::io::Error::last_os_error();
        // ERROR_NO_DATA: очередь пуста и закрыта.
        if err.raw_os_error() == Some(232) { None } else { Some(Err(err)) }
    }

    pub fn send(&self, pkt: &[u8], addr: &Address) -> bool {
        let mut sent = 0u32;
        unsafe { (self.api.send)(self.raw, pkt.as_ptr().cast(), pkt.len() as u32, &mut sent, addr) != 0 }
    }

    /// Пересчитывает контрольные суммы IP и TCP после правки заголовков.
    pub fn fix_checksums(&self, pkt: &mut [u8], addr: &mut Address) {
        unsafe { (self.api.checksums)(pkt.as_mut_ptr().cast(), pkt.len() as u32, addr, 0) };
    }

    /// Будит поток, ждущий в [`Handle::recv`], и больше пакетов не берёт.
    pub fn shutdown(&self) {
        unsafe { (self.api.shutdown)(self.raw, SHUTDOWN_BOTH) };
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { (self.api.close)(self.raw) };
    }
}

/// Понятная причина вместо номера ошибки Windows.
fn open_error(err: std::io::Error) -> String {
    use rust_i18n::t;
    match err.raw_os_error() {
        Some(5) => t!("err.windivert_access_denied").into_owned(),
        Some(2) | Some(3) => t!("err.windivert_driver_missing").into_owned(),
        // ERROR_INVALID_IMAGE_HASH и ERROR_DRIVER_BLOCKED: подпись драйвера
        // не приняли, чаще всего из-за антивируса или политики драйверов.
        Some(577) | Some(1275) => t!("err.windivert_driver_blocked").into_owned(),
        _ => err.to_string(),
    }
}
