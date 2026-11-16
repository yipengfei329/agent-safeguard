use crate::backend::{Manager, Result, safe_label};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    time::{SystemTime, UNIX_EPOCH},
};
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub fn updated_label(updated_at: u64, time: u64) -> String {
    let seconds = time.saturating_sub(updated_at) / 1000;
    match seconds {
        0..=59 => format!("{seconds} 秒前更新"),
        60..=3599 => format!("{} 分钟前更新", seconds / 60),
        3600..=86399 => format!("{} 小时前更新", seconds / 3600),
        _ => format!("{} 天前更新", seconds / 86400),
    }
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Identity {
    pub agent: Option<String>,
    pub host_session_id: Option<String>,
    pub title: Option<String>,
    pub project: Option<String>,
    pub model: Option<String>,
    pub agent_type: Option<String>,
}
impl Identity {
    fn valid(&self) -> bool {
        self.agent.as_deref().is_none_or(|s| s == "Claude Code")
            && [
                &self.host_session_id,
                &self.title,
                &self.model,
                &self.agent_type,
            ]
            .iter()
            .all(|s| valid_text(s, 160))
            && valid_text(&self.project, 512)
    }
    pub fn title(&self) -> &str {
        self.title
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("未命名会话")
    }
    pub fn project_name(&self) -> &str {
        self.project
            .as_deref()
            .and_then(|s| s.trim_end_matches(['/', '\\']).rsplit(['/', '\\']).next())
            .filter(|s| !s.is_empty())
            .unwrap_or("项目未提供")
    }
    pub fn agent_name(&self) -> String {
        match self.agent_type.as_deref().filter(|s| !s.is_empty()) {
            Some(kind) => format!("Claude Code · {kind}"),
            None => "Claude Code".into(),
        }
    }
}
fn valid_text(value: &Option<String>, max: usize) -> bool {
    value.as_ref().is_none_or(|s| {
        s.chars().count() <= max
            && !s.chars().any(|c| {
                c.is_control()
                    || ('\u{202a}'..='\u{202e}').contains(&c)
                    || ('\u{2066}'..='\u{2069}').contains(&c)
            })
    })
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Interception {
    #[serde(default)]
    pub record_id: Option<String>,
    pub at: u64,
    pub rule_id: Option<String>,
    pub event: String,
    pub tool: Option<String>,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    pub identity: Identity,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Recovery {
    pub state: String,
    pub epoch: u64,
    pub in_flight: u64,
    pub can_resume: bool,
    pub pauses: u64,
    pub resumes: u64,
    pub redacted_results: u64,
    pub replacements: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Session {
    pub schema: u8,
    #[serde(default)]
    pub recovery: Option<Recovery>,
    #[serde(default)]
    pub identity: Identity,
    #[serde(default)]
    pub interception: Option<Interception>,
    pub session: String,
    pub sequence: u64,
    pub updated_at: u64,
    pub plugin_version: String,
    pub rule_version: String,
    pub ready: bool,
    pub blocked: bool,
    pub ended: bool,
    pub last_event: Option<String>,
    pub last_rule: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Connected,
    Attention,
    Initializing,
    Unconfirmed,
    Ended,
}
impl ConnectionState {
    fn priority(self) -> u8 {
        match self {
            Self::Attention => 0,
            Self::Initializing => 1,
            Self::Connected => 2,
            Self::Unconfirmed => 3,
            Self::Ended => 4,
        }
    }
}
/// Counts are disjoint: stale unresolved failures stay actionable, while stale
/// ordinary reports are history without being declared ended.
#[derive(Default)]
pub struct Dashboard<'a> {
    pub current: Vec<&'a Session>,
    pub history: Vec<&'a Session>,
    pub connected: usize,
    pub attention: usize,
    pub initializing: usize,
    pub unconfirmed: usize,
}
impl<'a> Dashboard<'a> {
    pub fn new(rows: impl IntoIterator<Item = &'a Session>, time: u64) -> Self {
        let mut dashboard = Self::default();
        for row in rows {
            let state = row.connection_state(time);
            match state {
                ConnectionState::Connected => dashboard.connected += 1,
                ConnectionState::Attention => dashboard.attention += 1,
                ConnectionState::Initializing => dashboard.initializing += 1,
                ConnectionState::Unconfirmed => dashboard.unconfirmed += 1,
                ConnectionState::Ended => {}
            }
            if matches!(state, ConnectionState::Ended | ConnectionState::Unconfirmed) {
                dashboard.history.push(row);
            } else {
                dashboard.current.push(row);
            }
        }
        dashboard.current.sort_by_key(|row| {
            (
                row.connection_state(time).priority(),
                std::cmp::Reverse(row.updated_at),
                &row.session,
            )
        });
        dashboard
            .history
            .sort_by_key(|row| (std::cmp::Reverse(row.updated_at), &row.session));
        dashboard
    }
}
impl Session {
    pub fn has_interception(&self) -> bool {
        self.interception.is_some()
            || self
                .last_rule
                .as_deref()
                .is_some_and(|r| r != "session.ended")
                && self.blocked
    }
    pub fn blocked_at(&self) -> u64 {
        self.interception.as_ref().map(|e| e.at).unwrap_or(0)
    }
    pub fn display_identity(&self, history: bool) -> &Identity {
        if history {
            self.interception
                .as_ref()
                .map(|e| &e.identity)
                .unwrap_or(&self.identity)
        } else {
            &self.identity
        }
    }
    pub fn matched_rule(&self) -> Option<&str> {
        self.interception
            .as_ref()
            .and_then(|e| e.rule_id.as_deref())
            .or(self.last_rule.as_deref())
    }
    pub fn event_name(&self) -> &str {
        self.interception
            .as_ref()
            .map(|e| e.event.as_str())
            .or(self.last_event.as_deref())
            .unwrap_or("")
    }
    pub fn history_key(&self) -> String {
        self.interception
            .as_ref()
            .and_then(|e| e.record_id.clone())
            .unwrap_or_else(|| self.session.clone())
    }
    pub fn recovery_label(&self) -> String {
        self.recovery
            .as_ref()
            .map(|r| {
                format!(
                    "已脱敏 {} 次 · 已替换 {} 处 · 暂停 {} 次 · 恢复 {} 次{}",
                    r.redacted_results,
                    r.replacements,
                    r.pauses,
                    r.resumes,
                    if r.can_resume {
                        " · 可发送新的安全指令"
                    } else {
                        ""
                    }
                )
            })
            .unwrap_or_default()
    }
    pub fn action_label(&self) -> &'static str {
        if self.matched_rule().is_some_and(|r| {
            matches!(
                r,
                "inspection.failed"
                    | "initialization.failed"
                    | "tool.hook.failed"
                    | "prompt.hook.failed"
                    | "context.hook.failed"
            )
        }) {
            return "检查异常，已停止继续处理";
        }
        match self.event_name() {
            "tool.input" => "已拒绝工具调用",
            "tool.result" => "已扣留工具结果",
            "user.prompt" | "prompt.submit" => "已阻止输入提交",
            "prompt.context" | "prompt.section" | "prompt.attachment" => "已扣留上下文",
            _ => "插件已阻断",
        }
    }

    pub fn connection_state(&self, time: u64) -> ConnectionState {
        if self.ended {
            ConnectionState::Ended
        } else if self.blocked
            || self
                .last_rule
                .as_deref()
                .is_some_and(|r| r.ends_with(".failed"))
        {
            ConnectionState::Attention
        } else if !self.fresh(time) {
            ConnectionState::Unconfirmed
        } else if self.ready {
            ConnectionState::Connected
        } else {
            ConnectionState::Initializing
        }
    }
    pub fn connection_label(&self, time: u64) -> &'static str {
        if self.connection_state(time) == ConnectionState::Attention && !self.fresh(time) {
            if self
                .last_rule
                .as_deref()
                .is_some_and(|r| r.ends_with(".failed"))
            {
                "异常待核实"
            } else {
                "阻断待核实"
            }
        } else {
            self.state(time)
        }
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 8192 {
            return Err("STATUS_INPUT_LIMIT");
        }
        let s: Self = serde_json::from_slice(bytes).map_err(|_| "STATUS_FORMAT_REJECTED")?;
        if ![1, 2, 3].contains(&s.schema)
            || s.recovery.as_ref().is_some_and(|r| {
                s.schema != 3
                    || !["active", "pausing", "paused", "faulted", "ended"]
                        .contains(&r.state.as_str())
                    || r.epoch == 0
            })
            || !s.identity.valid()
            || s.interception.as_ref().is_some_and(|e| {
                !e.identity.valid()
                    || e.record_id.as_ref().is_some_and(|id| {
                        id.len() != 36 || !id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
                    })
                    || e.at == 0
                    || e.at > now() + 5000
                    || !valid_text(&e.tool, 80)
                    || !valid_text(&e.agent_id, 80)
                    || !valid_text(&e.agent_type, 80)
                    || e.rule_id.as_ref().is_some_and(|r| {
                        r.is_empty()
                            || r.len() > 80
                            || !r.chars().all(|c| {
                                c.is_ascii_lowercase() || c.is_ascii_digit() || "_.-".contains(c)
                            })
                    })
                    || ![
                        "tool.input",
                        "tool.result",
                        "tool.call",
                        "user.prompt",
                        "session.start",
                        "prompt.submit",
                        "prompt.section",
                        "prompt.context",
                        "prompt.attachment",
                        "agent.spawn",
                        "session.compact",
                    ]
                    .contains(&e.event.as_str())
            })
            || s.session.len() != 36
            || !s.session.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
            || s.updated_at > now() + 5000
            || s.sequence == 0
            || safe_label(&s.plugin_version) != s.plugin_version
            || safe_label(&s.rule_version) != s.rule_version
        {
            return Err("STATUS_FORMAT_REJECTED");
        }
        if s.last_event.as_deref().is_some_and(|x| {
            ![
                "tool.input",
                "tool.result",
                "tool.call",
                "user.prompt",
                "session.start",
                "session.end",
                "prompt.submit",
                "prompt.section",
                "prompt.context",
                "prompt.attachment",
                "agent.spawn",
                "session.compact",
            ]
            .contains(&x)
        }) {
            return Err("STATUS_FORMAT_REJECTED");
        }
        if s.last_rule.as_deref().is_some_and(|x| {
            ![
                "network.address",
                "identity.device",
                "identity.environment",
                "security.credentials",
                "custom.rule",
                "inspection.failed",
                "initialization.failed",
                "prompt.hook.failed",
                "context.hook.failed",
                "tool.hook.failed",
                "session.ended",
            ]
            .contains(&x)
        }) {
            return Err("STATUS_FORMAT_REJECTED");
        }
        Ok(s)
    }
    pub fn fresh(&self, time: u64) -> bool {
        self.updated_at <= time + 5000 && time.saturating_sub(self.updated_at) <= 45000
    }
    pub fn state(&self, time: u64) -> &'static str {
        if self.ended {
            "已结束"
        } else if !self.fresh(time) {
            "状态待确认"
        } else if self
            .last_rule
            .as_deref()
            .is_some_and(|r| r.ends_with(".failed"))
        {
            "检查异常"
        } else if self.blocked {
            if self.recovery.as_ref().is_some_and(|r| r.can_resume) {
                "已暂停，可继续"
            } else {
                "已阻断"
            }
        } else if self.ready {
            "已连接"
        } else {
            "初始化中"
        }
    }
    fn event_key(&self) -> String {
        format!(
            "{}:{}:{}:{:?}:{:?}:{}",
            self.ready,
            self.blocked,
            self.ended,
            self.last_event,
            self.last_rule,
            self.rule_version
        )
    }
}
#[derive(Default)]
pub struct Feed {
    pub sessions: BTreeMap<String, Session>,
    pub interceptions: BTreeMap<String, Session>,
    pub history_warning: Option<&'static str>,
    pub events: VecDeque<Session>,
    pub warning: Option<&'static str>,
}
impl Feed {
    pub fn update_history(&mut self, result: Result<(Vec<Session>, bool)>) {
        match result {
            Err(e) => self.history_warning = Some(e),
            Ok((rows, invalid)) => {
                self.history_warning = invalid.then_some("部分拦截记录暂时无法读取");
                for row in rows {
                    if row.has_interception() {
                        self.interceptions.insert(row.history_key(), row);
                    }
                }
                if self.interceptions.len() > 500 {
                    let mut ordered: Vec<_> = self
                        .interceptions
                        .values()
                        .map(|r| (r.blocked_at(), r.history_key()))
                        .collect();
                    ordered.sort();
                    for (_, id) in ordered.into_iter().take(self.interceptions.len() - 500) {
                        self.interceptions.remove(&id);
                    }
                }
            }
        }
    }

    pub fn update(&mut self, result: Result<(Vec<Session>, bool)>) {
        match result {
            Err(e) => self.warning = Some(e),
            Ok((rows, invalid)) => {
                self.warning = invalid.then_some("部分状态正在写入或格式异常，保留上次有效记录");
                for row in rows {
                    if let Some(old) = self.sessions.get(&row.session) {
                        if row.sequence <= old.sequence {
                            continue;
                        }
                        if row.event_key() != old.event_key() {
                            self.events.push_front(row.clone());
                        }
                    } else {
                        self.events.push_front(row.clone());
                    }
                    self.sessions.insert(row.session.clone(), row);
                }
                while self.events.len() > 100 {
                    self.events.pop_back();
                }
                if self.sessions.len() > 100 {
                    let mut rows: Vec<_> = self
                        .sessions
                        .values()
                        .map(|s| (s.updated_at, s.session.clone()))
                        .collect();
                    rows.sort();
                    for (_, id) in rows.into_iter().take(self.sessions.len() - 100) {
                        self.sessions.remove(&id);
                    }
                }
            }
        }
    }
}
type ReportCache = BTreeMap<std::path::PathBuf, (SystemTime, u64, Session)>;
#[derive(Default)]
pub struct Observer {
    cache: ReportCache,
}
impl Observer {
    pub fn poll(
        &mut self,
        manager: &Manager,
    ) -> (Result<(Vec<Session>, bool)>, Result<(Vec<Session>, bool)>) {
        let current = read_reports(&manager.status_dir(), 100, &mut self.cache);
        let history = read_reports(
            &manager.status_dir().join("interceptions"),
            500,
            &mut self.cache,
        );
        if self.cache.len() > 700 {
            self.cache.clear();
        }
        (current, history)
    }
}
fn read_reports(
    dir: &std::path::Path,
    limit: usize,
    cache: &mut ReportCache,
) -> Result<(Vec<Session>, bool)> {
    if !dir.exists() {
        return Ok((vec![], false));
    }
    let entries = fs::read_dir(dir).map_err(|_| "STATUS_READ_FAILED")?;
    let mut files = vec![];
    for entry in entries.take(10001) {
        let e = entry.map_err(|_| "STATUS_READ_FAILED")?;
        let ty = e.file_type().map_err(|_| "STATUS_READ_FAILED")?;
        if ty.is_symlink() || !ty.is_file() || e.path().extension().is_none_or(|s| s != "json") {
            continue;
        }
        let metadata = e.metadata().map_err(|_| "STATUS_READ_FAILED")?;
        files.push((
            metadata.modified().unwrap_or(UNIX_EPOCH),
            metadata.len(),
            e.path(),
        ));
    }
    if files.len() > 10000 {
        return Err("STATUS_DIRECTORY_LIMIT");
    }
    files.sort_by(|a, b| b.0.cmp(&a.0));
    for (modified, _, path) in files.iter().skip(limit) {
        let owned = path
            .file_stem()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.len() == 36 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        if owned
            && SystemTime::now()
                .duration_since(*modified)
                .is_ok_and(|d| d.as_secs() > 45)
        {
            let _ = fs::remove_file(path);
            cache.remove(path);
        }
    }
    let mut rows = vec![];
    let mut invalid = false;
    for (mtime, len, path) in files.into_iter().take(limit) {
        if let Some((old_time, old_len, row)) = cache.get(&path) {
            if *old_time == mtime && *old_len == len {
                rows.push(row.clone());
                continue;
            }
        }
        use std::io::Read;
        let parsed = (|| {
            if len > 8192 {
                return Err("STATUS_INPUT_LIMIT");
            }
            let mut bytes = Vec::new();
            fs::File::open(&path)
                .map_err(|_| "STATUS_READ_FAILED")?
                .take(8193)
                .read_to_end(&mut bytes)
                .map_err(|_| "STATUS_READ_FAILED")?;
            Session::parse(&bytes)
        })();
        match parsed {
            Ok(s) if path.file_stem().is_some_and(|n| n == s.session.as_str()) => {
                cache.insert(path, (mtime, len, s.clone()));
                rows.push(s);
            }
            _ => {
                invalid = true;
                if let Some((_, _, old)) = cache.get(&path) {
                    rows.push(old.clone());
                }
            }
        }
    }
    Ok((rows, invalid))
}
impl Manager {
    pub fn sessions(&self) -> Result<(Vec<Session>, bool)> {
        read_reports(&self.status_dir(), 100, &mut BTreeMap::new())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn session() -> Session {
        Session {
            recovery: None,
            schema: 1,
            identity: Identity::default(),
            interception: None,
            session: "00000000-0000-4000-8000-000000000001".into(),
            sequence: 1,
            updated_at: now(),
            plugin_version: "0.1.7".into(),
            rule_version: "test".into(),
            ready: true,
            blocked: false,
            ended: false,
            last_event: None,
            last_rule: None,
        }
    }
    #[test]
    fn schema_three_preserves_multiple_events_from_one_instance() {
        let mut row = session();
        row.schema = 3;
        row.recovery = Some(Recovery {
            state: "paused".into(),
            epoch: 2,
            in_flight: 0,
            can_resume: true,
            pauses: 2,
            resumes: 1,
            redacted_results: 3,
            replacements: 6,
        });
        row.blocked = true;
        assert_eq!(row.state(now()), "已暂停，可继续");
        let mut rows = Vec::new();
        for i in 1..=2 {
            row.interception = Some(Interception {
                record_id: Some(format!("00000000-0000-4000-9000-{i:012}")),
                at: now(),
                rule_id: Some("custom.rule".into()),
                event: "tool.result".into(),
                tool: Some("Bash".into()),
                agent_id: None,
                agent_type: None,
                identity: Identity::default(),
            });
            rows.push(Session::parse(&serde_json::to_vec(&row).unwrap()).unwrap());
        }
        let mut feed = Feed::default();
        feed.update_history(Ok((rows, false)));
        assert_eq!(feed.interceptions.len(), 2);
        let mut unsafe_row = serde_json::to_value(&row).unwrap();
        unsafe_row["recovery"]["rawAddress"] = serde_json::json!("SYNTHETIC_VALUE");
        assert!(Session::parse(&serde_json::to_vec(&unsafe_row).unwrap()).is_err());
        row.recovery.as_mut().unwrap().state = "unknown".into();
        assert!(Session::parse(&serde_json::to_vec(&row).unwrap()).is_err());
    }
    #[test]
    fn stale_or_failed_is_never_connected() {
        let mut s = session();
        assert_eq!(s.state(now()), "已连接");
        assert_eq!(s.state(s.updated_at + 45001), "状态待确认");
        s.blocked = true;
        s.last_rule = Some("inspection.failed".into());
        assert_eq!(s.state(now()), "检查异常");
        s.ended = true;
        assert_eq!(s.state(now()), "已结束");
    }
    #[test]
    fn out_of_order_reports_and_heartbeats_do_not_duplicate_events() {
        let mut f = Feed::default();
        let s = session();
        f.update(Ok((vec![s.clone()], false)));
        let mut next = s.clone();
        next.sequence = 2;
        f.update(Ok((vec![next], false)));
        assert_eq!(f.events.len(), 1);
        let mut old = s;
        old.blocked = true;
        f.update(Ok((vec![old], false)));
        assert!(!f.sessions.values().next().unwrap().blocked);
    }
    #[test]
    fn rejects_extra_payload() {
        let mut v = serde_json::to_value(session()).unwrap();
        v["stdout"] = serde_json::json!("SYNTHETIC_SECRET");
        assert!(Session::parse(v.to_string().as_bytes()).is_err());
    }
    #[test]
    fn archive_survives_restart_and_rejects_payloads() {
        let tmp = tempfile::tempdir().unwrap();
        let manager = Manager::new(true, Some(tmp.path().to_owned())).unwrap();
        let mut row = session();
        row.schema = 2;
        row.blocked = true;
        row.ended = true;
        row.identity = Identity {
            agent: Some("Claude Code".into()),
            title: Some("修复搜索排序".into()),
            project: Some("/synthetic/catalog".into()),
            ..Default::default()
        };
        row.interception = Some(Interception {
            record_id: None,
            at: now(),
            rule_id: Some("custom.fixture".into()),
            event: "tool.result".into(),
            tool: Some("Bash".into()),
            agent_id: None,
            agent_type: None,
            identity: row.identity.clone(),
        });
        let dir = manager.status_dir().join("interceptions");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{}.json", row.session));
        fs::write(&path, serde_json::to_vec(&row).unwrap()).unwrap();
        let mut observer = Observer::default();
        let (current, history) = observer.poll(&manager);
        assert!(current.unwrap().0.is_empty());
        let mut feed = Feed::default();
        feed.update_history(history);
        assert_eq!(feed.interceptions.len(), 1);
        assert_eq!(
            feed.interceptions
                .values()
                .next()
                .unwrap()
                .display_identity(true)
                .project_name(),
            "catalog"
        );
        assert_eq!(Observer::default().poll(&manager).1.unwrap().0.len(), 1);
        // A partially rewritten report preserves the last valid cached row.
        fs::write(&path, b"{").unwrap();
        let (cached, invalid) = observer.poll(&manager).1.unwrap();
        assert!(invalid);
        assert_eq!(cached.len(), 1);
        let mut payload = serde_json::to_value(&row).unwrap();
        payload["interception"]["rawOutput"] = serde_json::json!("SYNTHETIC_SECRET");
        assert!(Session::parse(&serde_json::to_vec(&payload).unwrap()).is_err());
        payload = serde_json::to_value(&row).unwrap();
        payload["identity"]["title"] = serde_json::json!("a\nspoofed");
        assert!(Session::parse(&serde_json::to_vec(&payload).unwrap()).is_err());
    }
    #[test]
    fn dashboard_separates_history_and_keeps_stale_failures_actionable() {
        let time = now();
        let mut rows = vec![session(); 6];
        for (i, row) in rows.iter_mut().enumerate() {
            row.session = format!("00000000-0000-4000-8000-{i:012}");
            row.updated_at = time;
        }
        rows[1].updated_at = time - 45001; // Ordinary stale report is not ended.
        rows[2].blocked = true;
        rows[2].updated_at = time - 60000; // Unresolved block must remain visible.
        rows[3].last_rule = Some("inspection.failed".into()); // Error without blocked bit.
        rows[4].ready = false;
        rows[5].ended = true;
        rows[5].blocked = true; // Ending normally also sets blocked in the adapter.
        let d = Dashboard::new(&rows, time);
        assert_eq!(
            (d.connected, d.attention, d.initializing, d.unconfirmed),
            (1, 2, 1, 1)
        );
        assert_eq!((d.current.len(), d.history.len()), (4, 2));
        assert_eq!(d.current[0].session, rows[3].session);
        assert_eq!(d.current[1].session, rows[2].session);
        assert_eq!(rows[1].connection_label(time), "状态待确认");
        assert_eq!(rows[2].connection_label(time), "阻断待核实");
        assert_eq!(rows[5].connection_state(time), ConnectionState::Ended);
        assert_eq!(d.history[0].session, rows[5].session);
    }
    #[test]
    fn connection_moves_to_history_on_timeout_and_returns_on_heartbeat() {
        let mut row = session();
        let time = row.updated_at;
        assert_eq!(Dashboard::new([&row], time + 45000).connected, 1);
        let expired = Dashboard::new([&row], time + 45001);
        assert!(expired.current.is_empty());
        assert_eq!(expired.unconfirmed, 1);
        row.updated_at = time + 45001;
        assert_eq!(Dashboard::new([&row], time + 45001).connected, 1);
        row.ended = true;
        let ended = Dashboard::new([&row], time + 45001);
        assert_eq!(
            ended.connected + ended.attention + ended.initializing + ended.unconfirmed,
            0
        );
        assert_eq!(ended.history.len(), 1);
    }
}
