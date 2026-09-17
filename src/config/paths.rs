//! Где лежат файлы данных и как в них безопасно писать.
//!
//! # Один якорь вместо относительных путей
//!
//! Все пути в проекте были относительными от текущего каталога: `config.toml`,
//! `bypass_domains.txt`, `strategies.txt`, `locales/*.yml`. Это давало не
//! ошибку, а тихую деградацию — `load_bypass_domains` возвращал пустое
//! множество через `unwrap_or_default()`, и обход выключался целиком, ничего
//! об этом не сообщая; переводы вырождались в голые ключи.
//!
//! Отдельно кусалось `cargo run`: он находит `Cargo.toml`, поднимаясь по
//! дереву, но рабочий каталог НЕ меняет. Запуск из `src/` оставлял CWD равным
//! `src/`, и конфиг не находился — при том что рядом с исполняемым файлом
//! (`target/debug/`) его тоже нет.
//!
//! Поэтому каталог данных вычисляется один раз и служит якорем для всего
//! остального. Порядок поиска:
//!
//! 1. `NET_SURGEON_DIR`, если задан — явное указание сильнее догадок;
//! 2. рабочий каталог и его родители — так находится корень проекта при
//!    запуске из любого подкаталога, включая `cargo run` из `src/`;
//! 3. каталог исполняемого файла и его родители — для `target/release/…`
//!    и для установленного бинаря, лежащего рядом со своим конфигом.
//!
//! Признак нужного каталога — наличие `config.toml`: без него программа всё
//! равно не стартует, так что он и есть естественный маркер.
//!
//! # Почему запись через временный файл
//!
//! `fs::write` усекает файл и только потом пишет. Падение или закончившееся
//! место между этими шагами оставляло обрезанный `strategies.txt` или, хуже,
//! обрезанный `config.toml` — после чего приложение уже не стартовало.
//! `rename` внутри одной файловой системы атомарен, поэтому читатель видит
//! либо старое содержимое целиком, либо новое целиком.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Файл-маркер каталога данных.
const ANCHOR: &str = "config.toml";

/// Насколько высоко подниматься в поисках якоря.
///
/// Предел нужен, чтобы не утащить чужой `config.toml` из общего родительского
/// каталога. Четырёх уровней хватает и для `src/cli/screen`, и для
/// `target/debug`, а выше корня проекта подниматься уже незачем.
const MAX_ANCESTORS: usize = 4;

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Ищет каталог с файлом `name`, начиная с `start` и поднимаясь вверх.
fn find_upwards(start: &Path, name: &str, limit: usize) -> Option<PathBuf> {
    start
        .ancestors()
        .take(limit + 1)
        .find(|dir| dir.join(name).exists())
        .map(Path::to_path_buf)
}

/// Каталог, относительно которого лежат все файлы данных.
pub fn data_dir() -> &'static Path {
    DATA_DIR.get_or_init(|| {
        if let Some(dir) = std::env::var_os("NET_SURGEON_DIR") {
            return PathBuf::from(dir);
        }

        let from_cwd = std::env::current_dir()
            .ok()
            .and_then(|cwd| find_upwards(&cwd, ANCHOR, MAX_ANCESTORS));
        if let Some(dir) = from_cwd {
            return dir;
        }

        let from_exe = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(Path::to_path_buf))
            .and_then(|dir| find_upwards(&dir, ANCHOR, MAX_ANCESTORS));
        if let Some(dir) = from_exe {
            return dir;
        }

        // Якоря нет нигде: сообщение об ошибке и первая запись должны
        // указывать на понятное место, а понятнее рабочего каталога тут
        // ничего нет.
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    })
}

/// Полный путь к файлу данных по его имени (можно с подкаталогом:
/// `locales/ru.yml`).
pub fn resolve(name: &str) -> PathBuf {
    data_dir().join(name)
}

/// Читает файл данных по имени, разрешая путь через [`resolve`].
pub fn read_to_string(name: &str) -> io::Result<String> {
    std::fs::read_to_string(resolve(name))
}

/// Записывает файл целиком или не записывает вовсе: временный файл рядом
/// с целевым, затем `rename`.
///
/// Временный файл создаётся именно РЯДОМ, а не в /tmp: `rename` между разными
/// файловыми системами не работает, а /tmp сплошь и рядом отдельный tmpfs.
pub fn write_atomic(name: &str, contents: &str) -> io::Result<()> {
    let target = resolve(name);

    let mut tmp = target.clone();
    let file_name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string());
    // PID отличает только процессы. Внутри одного процесса `save()` зовут
    // несколько потоков сразу (автодиагностики, сброс записи, таймер), и
    // с общим временным именем один переименовывал файл, который другой
    // ещё дописывал: на диск попадал обрезанный strategies.txt, а второй
    // rename падал с ENOENT. Счётчик делает имя уникальным на каждый вызов.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tmp.set_file_name(format!(".{}.{}.{}.tmp", file_name, std::process::id(), seq));

    // Мусор не остаётся даже при ошибке записи: временный файл убирается
    // на любом неуспешном пути.
    if let Err(e) = std::fs::write(&tmp, contents) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Раскладывает дерево каталогов во временной папке теста.
    fn scratch(sub: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("ns-paths-{}-{}", std::process::id(), sub));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn finds_the_anchor_in_the_starting_directory() {
        let root = scratch("here");
        std::fs::write(root.join(ANCHOR), "").unwrap();

        assert_eq!(find_upwards(&root, ANCHOR, MAX_ANCESTORS).as_deref(), Some(root.as_path()));
    }

    #[test]
    fn finds_the_anchor_from_a_subdirectory() {
        // Ровно случай `cargo run` из src/: якорь уровнем выше.
        let root = scratch("sub");
        std::fs::create_dir_all(root.join("src/cli/screen")).unwrap();
        std::fs::write(root.join(ANCHOR), "").unwrap();

        for start in ["src", "src/cli", "src/cli/screen"] {
            assert_eq!(
                find_upwards(&root.join(start), ANCHOR, MAX_ANCESTORS).as_deref(),
                Some(root.as_path()),
                "не нашли якорь, стартовав из {start}"
            );
        }
    }

    #[test]
    fn does_not_climb_past_the_limit() {
        // Иначе можно утащить чужой config.toml из общего родителя.
        let root = scratch("deep");
        std::fs::create_dir_all(root.join("a/b/c/d/e")).unwrap();
        std::fs::write(root.join(ANCHOR), "").unwrap();

        assert!(find_upwards(&root.join("a/b/c/d/e"), ANCHOR, 2).is_none());
        assert!(find_upwards(&root.join("a/b/c/d/e"), ANCHOR, 5).is_some());
    }

    #[test]
    fn missing_anchor_is_reported_as_not_found() {
        let root = scratch("empty");
        assert_eq!(find_upwards(&root, ANCHOR, MAX_ANCESTORS), None);
    }
}
