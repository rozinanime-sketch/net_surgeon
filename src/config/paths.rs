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
//! Признак нужного каталога — `config.toml` рядом с `bypass_domains.txt`.
//! Один `config.toml` — слишком частое имя: запущенный из чужого проекта
//! (Hugo, Netlify) бинарь брал его конфиг и писал туда свои файлы. Если
//! такой пары нет нигде, у каталога исполняемого файла хватает и одного
//! `config.toml` — это своя установка, где список могли удалить.
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
/// Второй маркер: файл, который есть только у net_surgeon.
const COMPANION: &str = "bypass_domains.txt";

/// Насколько высоко подниматься в поисках якоря.
///
/// Предел нужен, чтобы не утащить чужой `config.toml` из общего родительского
/// каталога. Четырёх уровней хватает и для `src/cli/screen`, и для
/// `target/debug`, а выше корня проекта подниматься уже незачем.
const MAX_ANCESTORS: usize = 4;

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Ищет каталог с файлом `name`, начиная с `start` и поднимаясь вверх.
fn find_upwards(start: &Path, name: &str, limit: usize) -> Option<PathBuf> {
    find_dir_upwards(start, limit, |dir| dir.join(name).exists())
}

fn find_dir_upwards(start: &Path, limit: usize, is_data_dir: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    start.ancestors().take(limit + 1).find(|dir| is_data_dir(dir)).map(Path::to_path_buf)
}

/// Каталог данных net_surgeon, а не любой с `config.toml`.
fn is_ours(dir: &Path) -> bool {
    dir.join(ANCHOR).exists() && dir.join(COMPANION).exists()
}

/// Каталог, относительно которого лежат все файлы данных.
pub fn data_dir() -> &'static Path {
    DATA_DIR.get_or_init(|| {
        // Тесты не должны трогать настоящие файлы. Каталог ищется от
        // текущего, а `cargo test` запускается из корня проекта, где лежит
        // config.toml, — и любой тест, дошедший до `StrategyStore::save()`
        // (например, через сброс стратегии в `adaptive::record_outcome`),
        // перезаписывал рабочий strategies.txt содержимым тестового хранилища.
        #[cfg(test)]
        {
            let dir = std::env::temp_dir().join(format!("net_surgeon-test-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            return dir;
        }

        #[allow(unreachable_code)]
        if let Some(dir) = std::env::var_os("NET_SURGEON_DIR") {
            return PathBuf::from(dir);
        }

        let cwd = std::env::current_dir().ok();
        let exe_dir = std::env::current_exe().ok().and_then(|exe| exe.parent().map(Path::to_path_buf));
        let found = cwd
            .as_deref()
            .and_then(|cwd| find_dir_upwards(cwd, MAX_ANCESTORS, is_ours))
            .or_else(|| exe_dir.as_deref().and_then(|dir| find_dir_upwards(dir, MAX_ANCESTORS, is_ours)))
            .or_else(|| exe_dir.as_deref().and_then(|dir| find_upwards(dir, ANCHOR, MAX_ANCESTORS)));
        if let Some(dir) = found {
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
///
/// Перед `rename` данные сбрасываются на диск (`sync_all`): без этого после
/// пропажи питания на части файловых систем (XFS) переименование уже на
/// диске, а содержимое — нет, и `config.toml` оставался пустым. Права
/// прежнего файла сохраняются (`chmod 600` не сбрасывался в 644), а
/// симлинк не подменяется обычным файлом: пишется файл, на который он
/// указывает.
pub fn write_atomic(name: &str, contents: &str) -> io::Result<()> {
    let target = resolve(name);
    let target = std::fs::canonicalize(&target).unwrap_or(target);

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
    let written = (|| {
        use std::io::Write;
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(contents.as_bytes())?;
        if let Ok(meta) = std::fs::metadata(&target) {
            file.set_permissions(meta.permissions())?;
        }
        file.sync_all()?;
        std::fs::rename(&tmp, &target)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Каталог — тоже, чтобы на диске оказалось и само переименование.
    // Не вышло — не беда: файл уже на месте.
    #[cfg(unix)]
    if let Some(dir) = target.parent()
        && let Ok(dir) = std::fs::File::open(dir)
    {
        let _ = dir.sync_all();
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

    /// Чужой проект с `config.toml` — не наш каталог данных.
    #[test]
    fn foreign_config_toml_is_not_ours() {
        let root = scratch("foreign");
        std::fs::write(root.join(ANCHOR), "").unwrap();
        assert!(!is_ours(&root));
        std::fs::write(root.join(COMPANION), "").unwrap();
        assert!(is_ours(&root));
    }

    /// Запись сохраняет права файла и не подменяет симлинк.
    #[cfg(unix)]
    #[test]
    fn atomic_write_keeps_permissions_and_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let real = data_dir().join("paths_real.txt");
        std::fs::write(&real, "old").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = data_dir().join("paths_link.txt");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();

        write_atomic("paths_link.txt", "new").unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "new");
        assert_eq!(std::fs::metadata(&real).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn missing_anchor_is_reported_as_not_found() {
        let root = scratch("empty");
        assert_eq!(find_upwards(&root, ANCHOR, MAX_ANCESTORS), None);
    }
}
