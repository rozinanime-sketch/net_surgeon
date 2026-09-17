//! Переводимая ошибка.
//!
//! На верхнем уровне вместе с `logging`: ошибку создаёт код, который может
//! не знать про интерфейс, а показывает её `cli`.
//!
//! Раньше I/O-функции (`load_fields`, `save_field`, `save_domains`) возвращали
//! `Result<_, String>` с уже отформатированной русской строкой. Перевести её
//! было невозможно: к моменту, когда ошибка доходит до панели логов, это
//! просто текст, и язык интерфейса на него не влияет.
//!
//! Теперь ошибка несёт ключ локали и аргументы, а в текст превращается
//! только при отрисовке — тем же путём, что и обычные переводимые логи.

#[derive(Debug)]
pub struct AppError {
    pub key: &'static str,
    pub args: Vec<(String, String)>,
}

impl AppError {
    pub fn new(key: &'static str) -> Self {
        Self { key, args: Vec::new() }
    }

    /// Добавляет параметр подстановки (`%{name}` в файле локали).
    pub fn with(mut self, name: &str, value: impl ToString) -> Self {
        self.args.push((name.to_string(), value.to_string()));
        self
    }
}
