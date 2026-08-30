use super::box_utils::render_rounded_box;
use super::changelog::get_unseen_changelog_entries;
use super::{
    TuiState, dim_color, header_name_color, is_running_stable_release, semver, shorten_model_name,
};
use crate::tui::color_support::rgb;
use crate::tui::connection_type_icon;
use ratatui::prelude::*;
#[cfg(test)]
use std::sync::OnceLock;

#[cfg(test)]
fn unseen_changelog_entries_override() -> &'static std::sync::Mutex<Option<Vec<String>>> {
    static OVERRIDE: OnceLock<std::sync::Mutex<Option<Vec<String>>>> = OnceLock::new();
    OVERRIDE.get_or_init(|| std::sync::Mutex::new(None))
}

fn unseen_changelog_entries() -> Vec<String> {
    #[cfg(test)]
    {
        if let Ok(guard) = unseen_changelog_entries_override().lock()
            && let Some(entries) = guard.clone()
        {
            return entries;
        }
    }
    get_unseen_changelog_entries().clone()
}

#[cfg(test)]
pub(crate) fn set_unseen_changelog_entries_override_for_tests(entries: Option<Vec<String>>) {
    let mut guard = unseen_changelog_entries_override()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = entries;
}

pub(crate) fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().chain(chars).collect(),
    }
}

/// Compact form of a full build version string: `v0.25.19-dev (abc1234, dirty)`
/// becomes `v0.25.19-dev`. Used for the per-line server/client version labels.
fn compact_version_label(version: &str) -> String {
    let trimmed = version.trim();
    match trimmed.split_once(" (") {
        Some((head, _)) => head.trim().to_string(),
        None => trimmed.to_string(),
    }
}

/// Version label for a `server:`/`client:` header line. Normally compact
/// (semver only); keeps the git-hash suffix when the two sides share a semver
/// but differ by build, so the mismatch is still visible at a glance.
fn header_version_label(version: &str, include_hash: bool) -> String {
    if include_hash {
        version.trim().to_string()
    } else {
        compact_version_label(version)
    }
}

fn format_model_name(short: &str, provider_name: &str) -> String {
    if short.contains('/') {
        // Slashed model ids (e.g. `nvidia/nemotron-...`) are served by the
        // OpenRouter slot, which also fronts direct OpenAI-compatible profiles
        // such as NVIDIA NIM or DeepSeek. Label the line with the active
        // provider's display name instead of hard-coding "OpenRouter" so the
        // header matches the profile the user actually selected.
        let label = {
            let trimmed = provider_name.trim();
            if trimmed.is_empty() {
                "OpenRouter".to_string()
            } else {
                trimmed.to_string()
            }
        };
        return format!("{}: {}", label, short);
    }
    if short.contains("opus") {
        if short.contains("4.5") {
            return "Claude 4.5 Opus".to_string();
        }
        return "Claude Opus".to_string();
    }
    if short.contains("sonnet") {
        if short.contains("3.5") {
            return "Claude 3.5 Sonnet".to_string();
        }
        return "Claude Sonnet".to_string();
    }
    if short.contains("haiku") {
        return "Claude Haiku".to_string();
    }
    if short.starts_with("gpt") {
        // Only the numeric GPT families (gpt-4o, gpt-5.2-codex, ...) have a
        // curated form. Other gpt-prefixed ids (gpt-oss-120b) fall through to
        // the generic prettifier instead of producing "GPT-oss120b".
        let rest = short.trim_start_matches("gpt");
        if rest.is_empty() || rest.starts_with(|c: char| c.is_ascii_digit()) {
            return format_gpt_name(short);
        }
    }
    short.to_string()
}

fn format_gpt_name(short: &str) -> String {
    let rest = short.trim_start_matches("gpt");
    if rest.is_empty() {
        return "GPT".to_string();
    }

    if let Some(idx) = rest.find("codex") {
        let version = &rest[..idx];
        if version.is_empty() {
            return "GPT Codex".to_string();
        }
        return format!("GPT-{} Codex", version);
    }

    format!("GPT-{}", rest)
}

/// Generic fallback for model ids with no curated pretty name: title-case the
/// hyphen/underscore segments (`claude-fable-5` -> `Claude Fable 5`). Date or
/// snapshot suffixes (6+ digit runs) are dropped, vowel-less short segments are
/// treated as acronyms (`glm` -> `GLM`), and parameter sizes are uppercased
/// (`70b` -> `70B`). Placeholder labels with spaces/ellipses pass through.
fn prettify_model_id(model: &str) -> String {
    if model.contains(' ') || model.contains('…') || model.contains('/') {
        return model.to_string();
    }

    fn is_acronym(part: &str) -> bool {
        // Well-known initialisms that contain vowels and would otherwise be
        // title-cased as words.
        const KNOWN: &[&str] = &["oss", "ai", "moe", "vl", "it", "fp8", "awq", "exp"];
        if KNOWN.contains(&part.to_ascii_lowercase().as_str()) {
            return true;
        }
        // Short, all-alphabetic, and vowel-less segments read as initialisms:
        // glm, gpt, qwq, llm. Anything with a vowel (pro, max, mini, fable)
        // reads as a word and gets normal title-casing.
        part.len() <= 4
            && part.chars().all(|c| c.is_ascii_alphabetic())
            && !part
                .chars()
                .any(|c| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u' | 'y'))
    }

    fn is_param_size(part: &str) -> bool {
        // 70b / 8x7b / 32k style size or context markers.
        part.len() >= 2
            && part
                .chars()
                .last()
                .is_some_and(|c| matches!(c.to_ascii_lowercase(), 'b' | 'm' | 'k'))
            && part[..part.len() - 1]
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == 'x')
            && part.chars().any(|c| c.is_ascii_digit())
    }

    let parts: Vec<String> = model
        .split(['-', '_'])
        .filter(|part| !part.is_empty())
        // Drop date/snapshot suffixes like 20241022.
        .filter(|part| !(part.len() >= 6 && part.chars().all(|c| c.is_ascii_digit())))
        .map(|part| {
            if is_acronym(part) || is_param_size(part) {
                return part.to_uppercase();
            }
            let mut chars = part.chars();
            match chars.next() {
                Some(first) if first.is_ascii_alphabetic() => {
                    first.to_uppercase().chain(chars).collect::<String>()
                }
                Some(first) => first.to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect();
    if parts.is_empty() {
        model.to_string()
    } else {
        parts.join(" ")
    }
}

/// Final display name for the header model line: curated pretty names first
/// (Claude 4.5 Opus, GPT-5.2 Codex), generic title-cased prettification otherwise.
fn header_model_display_name(model: &str, provider_name: &str) -> String {
    let raw = model.trim();

    // Claude family ids ("claude-opus-4-6", "claude-3-5-sonnet-latest",
    // "claude-haiku-4.5") render as "Claude <version> <Family>" for any
    // version, instead of only the hardcoded 3.5/4.5 cases.
    if raw.starts_with("claude") {
        for family in ["opus", "sonnet", "haiku"] {
            if raw.contains(family) {
                let family_pretty = capitalize(family);
                let version = claude_version_segment(raw, family);
                return match version {
                    Some(version) => format!("Claude {} {}", version, family_pretty),
                    None => format!("Claude {}", family_pretty),
                };
            }
        }
    }

    // GPT ids are formatted from the raw segments ("gpt-5.1-codex-max" ->
    // "GPT-5.1 Codex Max") rather than the legacy mashed short form, which
    // produced "GPT-5.1codexmax"-style names.
    if let Some(rest) = raw.strip_prefix("gpt-")
        && rest.starts_with(|c: char| c.is_ascii_digit())
    {
        let mut segments = rest.split('-');
        let version = segments.next().unwrap_or_default();
        let mut name = format!("GPT-{}", version);
        for segment in segments {
            if segment.is_empty() {
                continue;
            }
            let pretty = prettify_model_id(segment);
            name.push(' ');
            name.push_str(&pretty);
        }
        return name;
    }

    let short_model = shorten_model_name(raw);
    let curated = format_model_name(&short_model, provider_name);
    if curated == short_model {
        // No curated pretty name matched; title-case the raw model id
        // instead of showing the mangled short form (`claudefable5`).
        prettify_model_id(raw)
    } else {
        curated
    }
}

/// Extract the version from a Claude model id, e.g. "claude-opus-4-6" -> "4.6",
/// "claude-3-5-sonnet-latest" -> "3.5", "claude-haiku-4.5" -> "4.5". Snapshot
/// dates (6+ digit runs) are ignored.
fn claude_version_segment(raw: &str, family: &str) -> Option<String> {
    let digits: Vec<&str> = raw
        .split(['-', '_'])
        .filter(|part| *part != family)
        .filter(|part| {
            !part.is_empty()
                && part.len() < 6
                && part.chars().all(|c| c.is_ascii_digit() || c == '.')
                && part.chars().any(|c| c.is_ascii_digit())
        })
        .collect();
    match digits.as_slice() {
        [] => None,
        [single] => Some(single.to_string()),
        [major, minor, ..] => Some(format!(
            "{}.{}",
            major.trim_matches('.'),
            minor.trim_matches('.')
        )),
    }
}

fn header_provider_label(provider_name: &str) -> String {
    let trimmed = provider_name.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    trimmed.to_lowercase()
}

fn abbreviate_home(path: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        let home_str = home.display().to_string();
        if path == home_str {
            return "~".to_string();
        }
        if let Some(rest) = path.strip_prefix(&home_str) {
            return format!("~{}", rest);
        }
    }
    path.to_string()
}

#[cfg(test)]
fn truncate_to_width(text: &str, width: usize) -> String {
    let char_count = text.chars().count();
    if char_count <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    if width == 1 {
        return "…".to_string();
    }

    let mut truncated = text
        .chars()
        .take(width.saturating_sub(1))
        .collect::<String>();
    truncated.push('…');
    truncated
}

#[cfg(test)]
fn choose_header_candidate(width: usize, candidates: Vec<String>) -> String {
    let mut last_non_empty = String::new();
    for candidate in candidates
        .into_iter()
        .filter(|candidate| !candidate.trim().is_empty())
    {
        if candidate.chars().count() <= width {
            return candidate;
        }
        last_non_empty = candidate;
    }

    truncate_to_width(&last_non_empty, width)
}

#[cfg(test)]
fn semver_core() -> String {
    semver()
        .split('-')
        .next()
        .unwrap_or_else(semver)
        .to_string()
}

#[cfg(test)]
fn semver_minor() -> String {
    let core = semver_core();
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[0], parts[1])
    } else {
        core
    }
}

#[cfg(test)]
fn version_display_candidates() -> Vec<String> {
    let name = jcode_build_meta::PRODUCT_NAME;
    let full = format!("{name} {}", semver());
    let core = format!("{name} {}", semver_core());
    let minor = format!("{name} {}", semver_minor());
    let shortest = semver_minor();
    vec![full, core, minor, shortest]
}

#[cfg(test)]
pub(super) fn build_persistent_header(app: &dyn TuiState, width: u16) -> Vec<Line<'static>> {
    build_persistent_header_inner(app, width)
}

fn build_persistent_header_inner(app: &dyn TuiState, width: u16) -> Vec<Line<'static>> {
    let model = app.provider_model();
    let session_name = app.session_display_name().unwrap_or_default();
    let server_name = app.server_display_name();
    // The client line is identified by its session name, so show that name's
    // icon (e.g. "ram" -> 🐏). Previously a remote http/ws connection icon
    // (🌐/🔌) replaced it entirely, which hid the name icon for every remote
    // client. Keep the connection icon as a separate trailing hint instead.
    let icon = crate::id::session_icon(&session_name);
    let connection_icon = connection_type_icon(app.connection_type().as_deref());
    let nice_model = header_model_display_name(&model, &app.provider_name());
    let align = Alignment::Left;
    let mut lines: Vec<Line> = Vec::new();
    let w = width as usize;

    let is_canary = app.is_canary();
    let is_remote = app.is_remote_mode();
    let server_update = app.server_update_available() == Some(true);
    let client_update = app.client_update_available();
    let mut status_items: Vec<&str> = Vec::new();
    if app.is_replay() {
        status_items.push("replay");
    } else if is_remote {
        status_items.push("client");
    }
    if server_update {
        status_items.push("srv↑");
    }
    if client_update {
        status_items.push("cli↑");
    }
    if let Some(badge) = crate::perf::profile().tier.badge() {
        status_items.push(badge);
    }

    // Labeled versions for the `server:` / `client:` lines. Lots of users run
    // mismatched client/server binaries, so both lines carry their own version
    // label (and highlight on mismatch) instead of relying on the single
    // ambiguous version line at the bottom.
    let server_version_full = app.server_display_version();
    let client_version_full = server_name
        .as_ref()
        .map(|_| jcode_build_meta::version().to_string());
    let version_mismatch = matches!(
        (&server_version_full, &client_version_full),
        (Some(server), Some(client)) if server.trim() != client.trim()
    );
    let include_hash = version_mismatch
        && matches!(
            (&server_version_full, &client_version_full),
            (Some(server), Some(client))
                if compact_version_label(server) == compact_version_label(client)
        );
    let version_style = if version_mismatch {
        Style::default().fg(rgb(255, 200, 100))
    } else {
        Style::default().fg(dim_color())
    };
    let server_version_label = server_version_full
        .as_deref()
        .map(|version| header_version_label(version, include_hash));
    let client_version_label = client_version_full
        .as_deref()
        .map(|version| header_version_label(version, include_hash));

    // First line: product name (+ `self-dev` when running a dev/canary build),
    // followed by any remaining status badges rendered dimly.
    {
        let mut spans = vec![Span::styled(
            jcode_build_meta::PRODUCT_NAME.to_string(),
            Style::default().fg(header_name_color()).bold(),
        )];
        if is_canary {
            spans.push(Span::styled(
                " self-dev".to_string(),
                Style::default().fg(dim_color()),
            ));
        }
        if !status_items.is_empty() {
            spans.push(Span::styled(
                format!(" · {}", status_items.join(" · ")),
                Style::default().fg(dim_color()),
            ));
        }
        lines.push(Line::from(spans).alignment(align));
    }

    if let Some(server_name) = server_name.as_deref() {
        let server_icon = app.server_display_icon().unwrap_or_default();
        let server_text = if server_icon.is_empty() {
            format!("server: {}", capitalize(server_name))
        } else {
            format!("server: {} {}", capitalize(server_name), server_icon)
        };
        let mut spans = vec![Span::styled(
            server_text.clone(),
            Style::default().fg(dim_color()),
        )];
        if let Some(version) = server_version_label.as_deref() {
            let suffix = format!(" · {}", version);
            if server_text.chars().count() + suffix.chars().count() <= w {
                spans.push(Span::styled(suffix, version_style));
            }
        }
        lines.push(Line::from(spans).alignment(align));
    }

    if !session_name.is_empty() {
        let client_text = match connection_icon {
            Some(conn) => format!("client: {} {} {}", capitalize(&session_name), icon, conn),
            None => format!("client: {} {}", capitalize(&session_name), icon),
        };
        let mut spans = vec![Span::styled(
            client_text.clone(),
            Style::default().fg(dim_color()),
        )];
        if let Some(version) = client_version_label.as_deref() {
            let suffix = format!(" · {}", version);
            if client_text.chars().count() + suffix.chars().count() <= w {
                spans.push(Span::styled(suffix, version_style));
            }
        }
        lines.push(Line::from(spans).alignment(align));
    } else if server_name.is_none() {
        lines.push(
            Line::from(Span::styled(
                jcode_build_meta::PRODUCT_NAME.to_string(),
                Style::default().fg(header_name_color()),
            ))
            .alignment(align),
        );
    }

    // Single model line: dim active-route method on the left, styled model
    // name in the middle, dim upstream/hint detail after. This used to be a
    // second, unstyled line in the secondary header duplicating the model name.
    let model_is_placeholder = {
        let trimmed = model.trim();
        trimmed.is_empty()
            || trimmed == "connected"
            || trimmed.ends_with('…')
            || trimmed.starts_with("connecting")
    };
    let provider_label = if model_is_placeholder {
        String::new()
    } else {
        header_provider_label(&app.provider_name())
    };
    let upstream = if model_is_placeholder {
        None
    } else {
        app.upstream_provider()
    };
    let mut model_spans: Vec<Span> = Vec::new();
    let mut model_line_len = nice_model.chars().count();
    // Keep a little headroom below the full width so the line never
    // wraps when the render area subtracts side margins.
    let fit_width = w.saturating_sub(4);
    if !model_is_placeholder && !nice_model.is_empty() {
        let hint = "/model to switch · ";
        if model_line_len + hint.chars().count() <= fit_width {
            model_line_len += hint.chars().count();
            model_spans.push(Span::styled(
                hint.to_string(),
                Style::default().fg(dim_color()),
            ));
        }
    }
    if !provider_label.is_empty() {
        let prefix = format!("{} · ", provider_label);
        if model_line_len + prefix.chars().count() <= fit_width {
            model_line_len += prefix.chars().count();
            model_spans.push(Span::styled(prefix, Style::default().fg(dim_color())));
        }
    }
    model_spans.push(Span::styled(
        nice_model.clone(),
        // Match the info widget's model accent (pink, bold) instead of plain
        // white so the model reads as a distinct, styled element.
        Style::default().fg(rgb(196, 164, 106)).bold(),
    ));
    if let Some(upstream) = upstream.as_deref() {
        let suffix = format!(" via {}", upstream);
        if model_line_len + suffix.chars().count() <= fit_width {
            model_spans.push(Span::styled(suffix, Style::default().fg(dim_color())));
        }
    }
    if !nice_model.is_empty() {
        lines.push(Line::from(model_spans).alignment(align));
    }

    // When there is no server/client version labeling (standalone mode),
    // still surface the running version on the jcode line's own row.
    if client_version_label.is_none() {
        let version_text = if is_running_stable_release() {
            let tag = jcode_build_meta::git_tag();
            if tag.is_empty() || tag.contains('-') {
                format!("{} · release", semver())
            } else {
                format!("{} · release {}", semver(), tag)
            }
        } else {
            semver().to_string()
        };
        lines.push(
            Line::from(Span::styled(version_text, Style::default().fg(dim_color())))
                .alignment(align),
        );
    }

    lines
}

#[cfg(test)]
pub(crate) fn build_header_lines(app: &dyn TuiState, width: u16) -> Vec<Line<'static>> {
    build_header_lines_inner(app, width)
}

fn build_header_lines_inner(app: &dyn TuiState, width: u16) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();
    let align = ratatui::layout::Alignment::Left;
    let w = width as usize;

    let mcps = app.mcp_servers();
    if !mcps.is_empty() {
        const MAX_MCPS: usize = 4;
        let shown: Vec<String> = mcps
            .iter()
            .take(MAX_MCPS)
            .map(|(name, count)| {
                if *count > 0 {
                    format!("{} ({} tools)", name, count)
                } else {
                    format!("{} (…)", name)
                }
            })
            .collect();
        let mut mcp_text = format!("mcp: {}", shown.join(", "));
        if mcps.len() > MAX_MCPS {
            mcp_text.push_str(&format!(" +{} more", mcps.len() - MAX_MCPS));
        }
        if mcp_text.chars().count() > w {
            mcp_text = format!("mcp: {} servers", mcps.len());
        }
        lines.push(
            Line::from(Span::styled(mcp_text, Style::default().fg(dim_color()))).alignment(align),
        );
    }

    let skills = app.available_skills();
    if !skills.is_empty() {
        const MAX_SKILLS: usize = 6;
        let shown: Vec<String> = skills
            .iter()
            .take(MAX_SKILLS)
            .map(|s| format!("/{}", s))
            .collect();
        let mut skills_text = format!("skills: {}", shown.join(" "));
        if skills.len() > MAX_SKILLS {
            skills_text.push_str(&format!(" +{} more", skills.len() - MAX_SKILLS));
        }
        if skills_text.chars().count() > w {
            skills_text = format!("skills: {} loaded", skills.len());
        }
        lines.push(
            Line::from(Span::styled(skills_text, Style::default().fg(dim_color())))
                .alignment(align),
        );
    }

    if let Some(dir) = app.working_dir() {
        let display_dir = abbreviate_home(&dir);
        let mut text = display_dir;
        if let Some(branch) = app.git_branch() {
            let with_branch = format!("{} ({})", text, branch);
            if with_branch.chars().count() <= w {
                text = with_branch;
            }
        }
        lines.push(
            Line::from(Span::styled(text, Style::default().fg(dim_color()))).alignment(align),
        );
    }

    lines.push(Line::from(""));
    lines
}

/// Build the "Updates" rounded box (unseen release notes) so it can be
/// rendered inside the top padding above the header. `max_lines` bounds the
/// total height including the box borders; entries beyond the budget are
/// collapsed into a "…N more" line. Returns an empty vec when there are no
/// unseen entries or the budget/width is too small for a box.
pub(super) fn build_updates_box_lines(width: u16, max_lines: usize) -> Vec<Line<'static>> {
    let w = width as usize;
    if w <= 20 || max_lines < 3 {
        return Vec::new();
    }
    let new_entries = unseen_changelog_entries();
    if new_entries.is_empty() {
        return Vec::new();
    }

    // Budget for content lines inside the box (borders take 2 lines).
    let content_budget = (max_lines - 2).min(8);
    let has_more = new_entries.len() > content_budget;
    let display_count = if has_more {
        content_budget.saturating_sub(1)
    } else {
        new_entries.len()
    };

    let mut content: Vec<Line> = Vec::new();
    for entry in new_entries.iter().take(display_count) {
        content.push(Line::from(Span::styled(
            format!("• {}", entry),
            Style::default().fg(dim_color()),
        )));
    }
    if has_more {
        content.push(Line::from(Span::styled(
            format!(
                "  …{} more · inherited release history disabled",
                new_entries.len() - display_count
            ),
            Style::default().fg(dim_color()),
        )));
    }
    if content.is_empty() {
        return Vec::new();
    }

    render_rounded_box(
        "Updates",
        content,
        w.saturating_sub(2),
        Style::default().fg(dim_color()),
    )
    .into_iter()
    .map(|line| line.alignment(Alignment::Left))
    .collect()
}

/// Build both header sections without probing account or credential stores.
pub(super) fn build_header_sections(
    app: &dyn TuiState,
    width: u16,
) -> (Vec<Line<'static>>, Vec<Line<'static>>) {
    (
        build_persistent_header_inner(app, width),
        build_header_lines_inner(app, width),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;
    use crate::provider::{EventStream, Provider};
    use crate::tool::Registry;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::sync::OnceLock;

    struct MockProvider;

    #[async_trait]
    impl Provider for MockProvider {
        async fn complete(
            &self,
            _messages: &[Message],
            _tools: &[crate::message::ToolDefinition],
            _system: &str,
            _resume_session_id: Option<&str>,
        ) -> Result<EventStream> {
            Err(anyhow::anyhow!(
                "Mock provider should not be used for streaming completions in ui header tests"
            ))
        }

        fn name(&self) -> &str {
            "mock"
        }

        fn fork(&self) -> Arc<dyn Provider> {
            Arc::new(MockProvider)
        }
    }

    fn ensure_test_jcode_home_if_unset() {
        static TEST_HOME: OnceLock<std::path::PathBuf> = OnceLock::new();

        if std::env::var_os("JCODE_HOME").is_some() {
            return;
        }

        let path = TEST_HOME.get_or_init(|| {
            let path = std::env::temp_dir().join(format!("jcode-test-home-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&path);
            path
        });
        crate::env::set_var("JCODE_HOME", path);
    }

    fn create_test_app() -> crate::tui::app::App {
        ensure_test_jcode_home_if_unset();

        let provider: Arc<dyn Provider> = Arc::new(MockProvider);
        let rt = tokio::runtime::Runtime::new().expect("test runtime");
        let registry = rt.block_on(Registry::new(provider.clone()));
        crate::tui::app::App::new_for_test_harness(provider, registry)
    }

    #[test]
    fn left_aligned_mode_keeps_persistent_header_left_aligned() {
        let mut app = create_test_app();
        app.set_centered(false);

        let lines = build_persistent_header(&app, 80);
        let non_empty: Vec<&Line<'_>> = lines
            .iter()
            .filter(|line| !line.spans.iter().all(|span| span.content.trim().is_empty()))
            .collect();

        assert!(!non_empty.is_empty(), "expected persistent header lines");
        assert!(
            non_empty
                .iter()
                .all(|line| line.alignment == Some(Alignment::Left)),
            "persistent header should be left aligned: {non_empty:?}"
        );
    }

    #[test]
    fn left_aligned_mode_keeps_secondary_header_left_aligned() {
        let mut app = create_test_app();
        app.set_centered(false);

        let lines = build_header_lines(&app, 80);
        let non_empty: Vec<&Line<'_>> = lines
            .iter()
            .filter(|line| !line.spans.iter().all(|span| span.content.trim().is_empty()))
            .collect();

        assert!(!non_empty.is_empty(), "expected header detail lines");
        assert!(
            non_empty
                .iter()
                .all(|line| line.alignment == Some(Alignment::Left)),
            "header detail lines should be left aligned: {non_empty:?}"
        );
    }

    #[test]
    fn combined_header_sections_match_individual_builders() {
        let app = create_test_app();
        let (persistent, secondary) = build_header_sections(&app, 80);

        assert_eq!(persistent, build_persistent_header(&app, 80));
        assert_eq!(secondary, build_header_lines(&app, 80));
    }

    #[test]
    fn version_display_candidates_compact_for_narrow_width() {
        let rendered = choose_header_candidate(8, version_display_candidates());
        // Version-agnostic: at width 8 only the bare minor semver fits.
        assert_eq!(rendered, semver_minor());
    }

    fn rendered_header_lines(app: &crate::tui::app::App, width: u16) -> Vec<String> {
        build_persistent_header(app, width)
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn persistent_header_labels_server_and_client_versions() {
        let mut app = create_test_app();
        app.set_remote_server_identity_for_tests(
            Some("blazing"),
            Some("🔥"),
            Some("v0.14.2-dev (old1234)"),
            Some("session_fox_1705012345678"),
        );

        let lines = rendered_header_lines(&app, 120);
        let server_line = lines
            .iter()
            .find(|line| line.contains("server:"))
            .expect("server line");
        let client_line = lines
            .iter()
            .find(|line| line.contains("client:"))
            .expect("client line");

        assert!(
            server_line.contains("server: Blazing 🔥 · v0.14.2-dev"),
            "server line should carry the server version: {server_line}"
        );
        let client_version = compact_version_label(jcode_build_meta::version());
        assert!(
            client_line.contains("client: Fox"),
            "client line should keep the session name: {client_line}"
        );
        assert!(
            client_line.contains(&format!("· {}", client_version)),
            "client line should carry the client version: {client_line}"
        );
    }

    #[test]
    fn persistent_header_keeps_git_hash_when_semvers_match_but_builds_differ() {
        let mut app = create_test_app();
        let client_semver = compact_version_label(jcode_build_meta::version());
        let fake_server_version = format!("{} (0000000)", client_semver);
        app.set_remote_server_identity_for_tests(
            Some("blazing"),
            None,
            Some(&fake_server_version),
            Some("session_fox_1705012345678"),
        );

        let lines = rendered_header_lines(&app, 160);
        let server_line = lines
            .iter()
            .find(|line| line.contains("server:"))
            .expect("server line");
        let client_line = lines
            .iter()
            .find(|line| line.contains("client:"))
            .expect("client line");

        assert!(
            server_line.contains("(0000000)"),
            "same-semver mismatch should keep the server git hash: {server_line}"
        );
        assert!(
            client_line.contains(&format!("· {}", jcode_build_meta::version())),
            "same-semver mismatch should keep the client git hash: {client_line}"
        );
    }

    #[test]
    fn persistent_header_omits_version_suffix_when_too_narrow() {
        let mut app = create_test_app();
        app.set_remote_server_identity_for_tests(
            Some("blazing"),
            Some("🔥"),
            Some("v0.14.2-dev (old1234)"),
            Some("session_fox_1705012345678"),
        );

        let lines = rendered_header_lines(&app, 18);
        let server_line = lines
            .iter()
            .find(|line| line.contains("server:"))
            .expect("server line");
        assert!(
            !server_line.contains("v0.14.2"),
            "narrow widths should drop the version suffix: {server_line}"
        );
    }

    #[test]
    fn persistent_header_local_mode_has_no_version_labels() {
        let app = create_test_app();
        let lines = rendered_header_lines(&app, 120);
        assert!(
            !lines.iter().any(|line| line.contains("server:")),
            "local mode should not render a server line: {lines:?}"
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("client:") && line.contains(" · v")),
            "local mode client line should not carry a version label: {lines:?}"
        );
    }

    #[test]
    fn persistent_header_client_line_shows_name_icon_with_connection_hint() {
        let mut app = create_test_app();
        app.set_remote_server_identity_for_tests(
            Some("blazing"),
            Some("🔥"),
            Some("v0.14.2-dev (old1234)"),
            Some("session_ram_1705012345678"),
        );
        app.set_connection_type_for_tests(Some("https/sse"));

        let lines = rendered_header_lines(&app, 120);
        let client_line = lines
            .iter()
            .find(|line| line.contains("client:"))
            .expect("client line");

        // The session name's own icon (ram -> 🐏) must be present rather than
        // being replaced by the connection icon.
        assert!(
            client_line.contains("client: Ram 🐏"),
            "client line should show the name icon: {client_line}"
        );
        // The connection icon is kept as a trailing hint, not a replacement.
        assert!(
            client_line.contains('🌐'),
            "client line should keep the connection hint icon: {client_line}"
        );
    }

    #[test]
    fn persistent_header_client_line_has_no_connection_hint_when_unknown() {
        let mut app = create_test_app();
        app.set_remote_server_identity_for_tests(
            Some("blazing"),
            Some("🔥"),
            Some("v0.14.2-dev (old1234)"),
            Some("session_fox_1705012345678"),
        );
        app.set_connection_type_for_tests(None);

        let lines = rendered_header_lines(&app, 120);
        let client_line = lines
            .iter()
            .find(|line| line.contains("client:"))
            .expect("client line");

        assert!(
            client_line.contains("client: Fox 🦊"),
            "client line should show the name icon: {client_line}"
        );
        assert!(
            !client_line.contains('🌐') && !client_line.contains('🔌'),
            "client line should not carry a connection hint when unknown: {client_line}"
        );
    }

    #[test]
    fn prettify_model_id_title_cases_unknown_models() {
        assert_eq!(prettify_model_id("claude-fable-5"), "Claude Fable 5");
        assert_eq!(prettify_model_id("grok-code-fast-1"), "Grok Code Fast 1");
        assert_eq!(prettify_model_id("kimi_k2"), "Kimi K2");
        assert_eq!(
            prettify_model_id("gemini-3-pro-preview"),
            "Gemini 3 Pro Preview"
        );
        assert_eq!(prettify_model_id("deepseek-chat"), "Deepseek Chat");
        assert_eq!(
            prettify_model_id("mistral-large-2411"),
            "Mistral Large 2411"
        );
        assert_eq!(prettify_model_id("o3-mini"), "O3 Mini");
        // Vowel-less short segments read as acronyms.
        assert_eq!(prettify_model_id("glm-4.6"), "GLM 4.6");
        assert_eq!(prettify_model_id("qwq-32b"), "QWQ 32B");
        // Parameter sizes are uppercased.
        assert_eq!(prettify_model_id("llama-3.3-70b"), "Llama 3.3 70B");
        assert_eq!(prettify_model_id("mixtral-8x7b"), "Mixtral 8X7B");
        // Long digit runs (snapshot dates) are dropped.
        assert_eq!(
            prettify_model_id("claude-fable-5-20260101"),
            "Claude Fable 5"
        );
        // Placeholders and slashed ids pass through untouched.
        assert_eq!(prettify_model_id("loading session…"), "loading session…");
        assert_eq!(
            prettify_model_id("deepseek/deepseek-chat"),
            "deepseek/deepseek-chat"
        );
        // Degenerate inputs survive.
        assert_eq!(prettify_model_id(""), "");
        assert_eq!(prettify_model_id("-"), "-");
    }

    #[test]
    fn header_model_display_name_sweeps_real_model_catalog() {
        // End-to-end through shorten_model_name + format_model_name +
        // prettify_model_id, over the model ids jcode actually routes.
        let cases = [
            // Anthropic
            ("claude-opus-4-5-20251101", "Claude 4.5 Opus"),
            ("claude-opus-4.6", "Claude 4.6 Opus"),
            ("claude-opus-4-8", "Claude 4.8 Opus"),
            ("claude-sonnet-4-5", "Claude 4.5 Sonnet"),
            ("claude-sonnet-4", "Claude 4 Sonnet"),
            ("claude-3-5-sonnet-latest", "Claude 3.5 Sonnet"),
            ("claude-haiku-4-5", "Claude 4.5 Haiku"),
            ("claude-fable-5", "Claude Fable 5"),
            // OpenAI
            ("gpt-5.2-codex", "GPT-5.2 Codex"),
            ("gpt-5.1-codex-max", "GPT-5.1 Codex Max"),
            ("gpt-5.3-codex-spark", "GPT-5.3 Codex Spark"),
            ("gpt-5-mini", "GPT-5 Mini"),
            ("gpt-5.1-chat-latest", "GPT-5.1 Chat Latest"),
            ("gpt-4o", "GPT-4o"),
            ("gpt-4o-mini", "GPT-4o Mini"),
            ("gpt-oss-120b", "GPT OSS 120B"),
            ("o3-mini", "O3 Mini"),
            ("o4-mini", "O4 Mini"),
            // Google
            ("gemini-3-pro-preview", "Gemini 3 Pro Preview"),
            ("gemini-2.5-flash", "Gemini 2.5 Flash"),
            // xAI / Moonshot / Zhipu / DeepSeek / Minimax
            ("grok-code-fast-1", "Grok Code Fast 1"),
            ("kimi-k2.5", "Kimi K2.5"),
            ("kimi-k2p5-turbo", "Kimi K2p5 Turbo"),
            ("glm-4.6", "GLM 4.6"),
            ("deepseek-v4-flash", "Deepseek V4 Flash"),
            ("minimax-m2.7", "Minimax M2.7"),
            // Meta / Mistral / Qwen / community
            ("llama-3.3-70b", "Llama 3.3 70B"),
            ("mixtral-8x7b", "Mixtral 8X7B"),
            ("devstral-medium-2507", "Devstral Medium 2507"),
            ("qwen3-coder-plus", "Qwen3 Coder Plus"),
            ("composer-1.5", "Composer 1.5"),
            ("llama-3.1-8b-instant", "Llama 3.1 8B Instant"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                header_model_display_name(input, ""),
                expected,
                "model id {input:?}"
            );
        }

        // Slashed ids keep the provider label form.
        assert_eq!(
            header_model_display_name("deepseek/deepseek-chat", "OpenRouter"),
            "OpenRouter: deepseek/deepseek-chat"
        );
        // Placeholders pass through untouched.
        assert_eq!(
            header_model_display_name("loading session…", ""),
            "loading session…"
        );
        assert_eq!(header_model_display_name("connected", ""), "Connected");
    }

    #[test]
    fn standalone_header_says_omnis_key_not_jcode() {
        let app = create_test_app();
        let rendered = rendered_header_lines(&app, 80).join("\n");
        assert!(
            rendered.contains(jcode_build_meta::PRODUCT_NAME),
            "header must name the product: {rendered}"
        );
        assert!(
            !rendered.contains("JCode") && !rendered.to_ascii_lowercase().contains("jcode"),
            "inherited chassis name must stay off glass: {rendered}"
        );
    }

    #[test]
    fn compact_version_label_strips_hash_suffix() {
        assert_eq!(
            compact_version_label("v0.25.19-dev (7e261bcc, dirty)"),
            "v0.25.19-dev"
        );
        assert_eq!(compact_version_label("v0.25.19 (abc1234)"), "v0.25.19");
        assert_eq!(compact_version_label(" v0.25.19 "), "v0.25.19");
    }

    #[test]
    fn build_persistent_header_prefers_configured_model_during_remote_connect() {
        let _guard = crate::storage::lock_test_env();
        let prev_model = std::env::var_os("JCODE_MODEL");
        let prev_provider = std::env::var_os("JCODE_PROVIDER");
        crate::env::set_var("JCODE_MODEL", "gpt-5.4");
        crate::env::set_var("JCODE_PROVIDER", "openai");

        let app = crate::tui::app::App::new_for_remote(None);
        let lines = build_persistent_header(&app, 80);
        let rendered = lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(rendered.contains("GPT-5.4"));
        assert!(!rendered.contains("connecting to server…"));

        if let Some(prev_model) = prev_model {
            crate::env::set_var("JCODE_MODEL", prev_model);
        } else {
            crate::env::remove_var("JCODE_MODEL");
        }
        if let Some(prev_provider) = prev_provider {
            crate::env::set_var("JCODE_PROVIDER", prev_provider);
        } else {
            crate::env::remove_var("JCODE_PROVIDER");
        }
    }

    #[test]
    fn build_header_lines_omits_placeholder_provider_label_when_unknown() {
        // Reads model/provider env-derived state: without the env lock, the
        // sibling test that sets JCODE_MODEL=gpt-5.4 mid-flight leaks into this
        // render and the "loading session…" placeholder never appears. The
        // startup-phase label is also only rendered when no model hint is
        // known, so neutralize JCODE_MODEL/JCODE_PROVIDER for the duration
        // ("unknown" also suppresses the shared test home's config
        // default_model fallback, which another test may have persisted).
        let _guard = crate::storage::lock_test_env();
        let prev_model = std::env::var_os("JCODE_MODEL");
        let prev_provider = std::env::var_os("JCODE_PROVIDER");
        crate::env::set_var("JCODE_MODEL", "unknown");
        crate::env::remove_var("JCODE_PROVIDER");

        let mut app = crate::tui::app::App::new_for_remote(None);
        app.set_remote_startup_phase(crate::tui::app::RemoteStartupPhase::LoadingSession);

        // The model line lives in the persistent header now; the startup phase
        // label renders there without a bogus "(unknown)" provider tag.
        let lines = build_persistent_header(&app, 80);
        let rendered = lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();

        if let Some(prev_model) = prev_model {
            crate::env::set_var("JCODE_MODEL", prev_model);
        } else {
            crate::env::remove_var("JCODE_MODEL");
        }
        if let Some(prev_provider) = prev_provider {
            crate::env::set_var("JCODE_PROVIDER", prev_provider);
        } else {
            crate::env::remove_var("JCODE_PROVIDER");
        }

        assert!(rendered.contains("loading session…"), "{rendered}");
        assert!(!rendered.contains("(unknown)"));
        assert!(!rendered.contains("(remote)"));
    }

    #[test]
    fn build_header_lines_hides_secondary_placeholder_during_brief_connecting_phase() {
        // Same env sensitivity as the placeholder test above: JCODE_MODEL /
        // JCODE_PROVIDER mutations from sibling tests change what renders.
        let _guard = crate::storage::lock_test_env();
        let app = crate::tui::app::App::new_for_remote(None);

        let lines = build_header_lines(&app, 80);
        let rendered = lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(
            !rendered.contains("connecting to server…"),
            "brief connecting placeholder should not render the secondary detail line"
        );
        assert!(!rendered.contains("(remote)"));
    }

    #[test]
    fn format_model_name_labels_slashed_models_with_active_provider() {
        // Regression for issue #329: a NVIDIA NIM model must be labeled with the
        // active provider's display name, not the fixed "OpenRouter" aggregator.
        assert_eq!(
            format_model_name("nvidia/nemotron-3-super-120b-a12b", "NVIDIA NIM"),
            "NVIDIA NIM: nvidia/nemotron-3-super-120b-a12b"
        );
        // The public aggregator still reads "OpenRouter".
        assert_eq!(
            format_model_name("anthropic/claude-sonnet-4", "OpenRouter"),
            "OpenRouter: anthropic/claude-sonnet-4"
        );
        // Missing provider name falls back to "OpenRouter" rather than an empty label.
        assert_eq!(
            format_model_name("deepseek/deepseek-chat", ""),
            "OpenRouter: deepseek/deepseek-chat"
        );
        // Non-slashed models are unaffected by the provider label.
        assert_eq!(
            format_model_name("claude-opus-4-6", "OpenRouter"),
            "Claude Opus"
        );
    }
}
