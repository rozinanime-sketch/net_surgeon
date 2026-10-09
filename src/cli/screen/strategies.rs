//! Экран «Стратегии» — таблица подобранных решений по доменам.
//!
//! Делает видимым весь адаптивный слой: какая техника выбрана для каждого
//! домена в текущей сети, насколько твёрдо, как показывает себя в бою и не
//! протухла ли запись. Только чтение — стратегии подбираются диагностикой, а
//! не правятся руками (для сброса домена есть удаление файла / передиагностика).
//!
//! Данные приходят снимком (`StrategyStore::snapshot`) через `Action::
//! RefreshStrategies`: экран не держит блокировку хранилища и рисуется из
//! готового вектора. Обновление — при открытии и по клавише `r`.

use crossterm::event::KeyCode;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem},
    Frame,
};
use rust_i18n::t;

use crate::cli::action::Action;
use crate::engine::strategy::{HelloClass, Strategy, StrategyRow};

use super::StepResult;

#[derive(Default)]
pub struct StrategiesState {
    pub rows: Vec<StrategyRow>,
    /// Индекс верхней видимой строки (прокрутка).
    pub scroll: usize,
}

impl StrategiesState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Кладёт свежий снимок, удерживая прокрутку в пределах списка.
    pub fn set_rows(&mut self, rows: Vec<StrategyRow>) {
        self.rows = rows;
        let max = self.rows.len().saturating_sub(1);
        if self.scroll > max {
            self.scroll = max;
        }
    }
}

pub fn handle_key(state: &mut StrategiesState, key: KeyCode) -> StepResult {
    let last = state.rows.len().saturating_sub(1);
    match key {
        KeyCode::Esc | KeyCode::Char('q') => StepResult::Close(Action::None),
        // Перечитать таблицу: dispatch снимет свежий снимок и вернёт его сюда.
        KeyCode::Char('r') => StepResult::Stay(Action::RefreshStrategies),
        KeyCode::Up | KeyCode::Char('k') => {
            state.scroll = state.scroll.saturating_sub(1);
            StepResult::Stay(Action::None)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.scroll = (state.scroll + 1).min(last);
            StepResult::Stay(Action::None)
        }
        KeyCode::PageUp => {
            state.scroll = state.scroll.saturating_sub(10);
            StepResult::Stay(Action::None)
        }
        KeyCode::PageDown => {
            state.scroll = (state.scroll + 10).min(last);
            StepResult::Stay(Action::None)
        }
        KeyCode::Home => {
            state.scroll = 0;
            StepResult::Stay(Action::None)
        }
        KeyCode::End => {
            state.scroll = last;
            StepResult::Stay(Action::None)
        }
        _ => StepResult::Stay(Action::None),
    }
}

/// Человекочитаемый возраст записи: с / м / ч / д.
fn age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}с")
    } else if secs < 3600 {
        format!("{}м", secs / 60)
    } else if secs < 86_400 {
        format!("{}ч", secs / 3600)
    } else {
        format!("{}д", secs / 86_400)
    }
}

/// Название техники для показа. `None` разводится на «отказ» (ничего не
/// сработало) и «прямое» (обход не нужен) — в файле это одна стратегия, но
/// смысл разный, и глазами их надо различать.
fn technique_label(strategy: Strategy, resigned: bool) -> (String, Color) {
    match strategy {
        Strategy::None if resigned => (t!("strategies.resigned").to_string(), Color::LightRed),
        Strategy::None => (t!("strategies.direct").to_string(), Color::DarkGray),
        Strategy::Fake | Strategy::Seqovl | Strategy::FakeMultiDisorder => (strategy.as_str().to_string(), Color::LightMagenta),
        other => (other.as_str().to_string(), Color::LightGreen),
    }
}

pub fn draw(frame: &mut Frame, area: Rect, state: &StrategiesState) {
    frame.render_widget(Clear, area);

    // Заголовок: сеть, если у всех записей она одна, иначе число сетей —
    // ключ стратегии сетевой, и без этого таблица разных сетей сливалась бы.
    let title = network_title(&state.rows);
    let outer = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} ", title))
        .style(Style::default().bg(Color::Rgb(18, 18, 30)));
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    if state.rows.is_empty() {
        let empty = List::new(vec![ListItem::new(Line::from(Span::styled(
            t!("strategies.empty").to_string(),
            Style::default().fg(Color::DarkGray),
        )))]);
        frame.render_widget(empty, inner);
        return;
    }

    // Шапка колонок + строки. Ширины подобраны под нечастый узкий терминал;
    // ratatui обрежет по краю, поэтому домен идёт первым и не теряет начало.
    let header = Line::from(Span::styled(
        format!(
            "{:<28} {:<5} {:<10} {:>5} {:>7} {:>5}",
            t!("strategies.col_domain"),
            t!("strategies.col_class"),
            t!("strategies.col_technique"),
            t!("strategies.col_confidence"),
            t!("strategies.col_live"),
            t!("strategies.col_age"),
        ),
        Style::default().fg(Color::Gray).add_modifier(Modifier::BOLD),
    ));

    let visible = inner.height.saturating_sub(1) as usize; // минус строка шапки
    let mut items: Vec<ListItem> = vec![ListItem::new(header)];
    items.extend(state.rows.iter().skip(state.scroll).take(visible).map(row_item));

    frame.render_widget(List::new(items), inner);
}

fn network_title(rows: &[StrategyRow]) -> String {
    use std::collections::BTreeSet;
    let nets: BTreeSet<&str> = rows.iter().map(|r| r.net_id.as_str()).collect();
    match nets.len() {
        0 => t!("strategies.panel_title").to_string(),
        1 => {
            let net = nets.iter().next().copied().unwrap_or("");
            if net.is_empty() {
                t!("strategies.panel_title").to_string()
            } else {
                format!("{} — {}", t!("strategies.panel_title"), crate::engine::net_state::display_net_id(net))
            }
        }
        n => format!("{} — {}", t!("strategies.panel_title"), t!("strategies.networks", count = n)),
    }
}

fn row_item(r: &StrategyRow) -> ListItem<'static> {
    let (tech, tech_color) = technique_label(r.strategy, r.resigned);
    let class = if r.class == HelloClass::Small { "small" } else { "large" };

    // Уверенность — снимок Уилсона на момент решения; для «отказа» её нет.
    let conf = if r.strategy == Strategy::None {
        "—".to_string()
    } else {
        format!("{:.0}%", r.confidence * 100.0)
    };

    // Бой: успехи/провалы применения. Пусто, пока не накопилось.
    let live_total = r.live_ok + r.live_fail;
    let live = if live_total == 0 { "—".to_string() } else { format!("{}/{}", r.live_ok, r.live_fail) };

    // Протухшую запись гасим и помечаем: она ещё в файле, но при следующем
    // обращении будет переизмерена.
    let base = if r.stale { Style::default().fg(Color::DarkGray) } else { Style::default() };
    let domain_mark = if r.stale { format!("{} ⚠", r.domain) } else { r.domain.clone() };

    // Цвет «боя»: любой провал — жёлтым, иначе зелёным; нет данных — серым.
    let live_color = if live_total == 0 {
        Color::DarkGray
    } else if r.live_fail > 0 {
        Color::Yellow
    } else {
        Color::LightGreen
    };

    let tech_style = if r.stale { base } else { Style::default().fg(tech_color) };
    let live_style = if r.stale { base } else { Style::default().fg(live_color) };

    ListItem::new(Line::from(vec![
        Span::styled(format!("{:<28} ", truncate(&domain_mark, 28)), base.add_modifier(Modifier::BOLD)),
        Span::styled(format!("{class:<5} "), base),
        Span::styled(format!("{tech:<10} "), tech_style),
        Span::styled(format!("{conf:>5} "), base),
        Span::styled(format!("{live:>7} "), live_style),
        Span::styled(format!("{:>5}", age(r.age_secs)), base),
    ]))
}

/// Обрезает строку по числу символов (не байтов), чтобы кириллица не билась.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}
