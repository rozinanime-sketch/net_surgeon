pub fn load_domains() -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string("bypass_domains.txt")
    .unwrap_or_default();
    Ok(text
    .lines()
    .map(|l| l.trim().to_string())
    .filter(|l| !l.is_empty())
    .collect())
}

pub fn save_domains(domains: &[String]) -> Result<(), String> {
    let content = domains.join("\n") + "\n";
    std::fs::write("bypass_domains.txt", content)
    .map_err(|e| format!("Не удалось сохранить bypass_domains.txt: {}", e))
}
