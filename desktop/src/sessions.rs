use crate::backend::{Manager, Result, read_limited, safe_label};
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
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Session {
    pub schema: u8,
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
impl Session {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 8192 {
            return Err("STATUS_INPUT_LIMIT");
        }
        let s: Self = serde_json::from_slice(bytes).map_err(|_| "STATUS_FORMAT_REJECTED")?;
        if s.schema != 1
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
            "已阻断"
        } else if self.ready {
            "已连接"
        } else {
            "初始化中"
        }
    }
    pub fn reason(&self) -> &'static str {
        match self.last_rule.as_deref() {
            Some("inspection.failed") => {
                "检测器未完成检查；当前接口未区分超时、内容限制与其他扫描错误"
            }
            Some("initialization.failed") => "规则或插件初始化失败",
            Some("tool.hook.failed") => "工具调用处理异常",
            Some("prompt.hook.failed" | "context.hook.failed") => "输入或上下文处理异常",
            Some("security.credentials") => "凭据规则",
            Some("network.address") => "IP 地址规则",
            Some("identity.device") => "设备标识规则",
            Some("identity.environment") => "主机名规则",
            Some("custom.rule") => "自定义规则",
            _ => "会话状态",
        }
    }
    pub fn outcome(&self) -> &'static str {
        if self.ended {
            "会话已经结束"
        } else if !self.blocked {
            "已收到状态报告；仅代表此插件实例"
        } else {
            match self.last_event.as_deref() {
                Some("tool.result") => {
                    "已扣留工具结果；会话锁定，后续推理被阻止。已执行操作没有撤销。"
                }
                Some("tool.input") => "已拒绝工具调用；会话锁定。",
                Some("user.prompt" | "prompt.submit") => "输入未提交；会话锁定。",
                _ => "插件已锁定；宿主最终处理结果需核对。",
            }
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
    pub events: VecDeque<Session>,
    pub warning: Option<&'static str>,
}
impl Feed {
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
impl Manager {
    pub fn sessions(&self) -> Result<(Vec<Session>, bool)> {
        if !self.status_dir().exists() {
            return Ok((vec![], false));
        }
        let entries = fs::read_dir(self.status_dir()).map_err(|_| "STATUS_READ_FAILED")?;
        let mut files = vec![];
        let mut invalid = false;
        for entry in entries.take(10001) {
            let e = entry.map_err(|_| "STATUS_READ_FAILED")?;
            let ty = e.file_type().map_err(|_| "STATUS_READ_FAILED")?;
            if ty.is_symlink() || !ty.is_file() || e.path().extension().is_none_or(|s| s != "json")
            {
                continue;
            }
            let time = e
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .unwrap_or(UNIX_EPOCH);
            files.push((time, e.path()));
        }
        if files.len() > 10000 {
            return Err("STATUS_DIRECTORY_LIMIT");
        }
        files.sort_by(|a, b| b.0.cmp(&a.0));
        // Prune old bridge-owned snapshots while the manager is open. Never
        // remove fresh files or other names, and never follow symlinks.
        for (modified, path) in files.iter().skip(100) {
            let owned = path.file_stem().and_then(|s| s.to_str()).is_some_and(|s| {
                s.len() == 36 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
            });
            if owned
                && SystemTime::now()
                    .duration_since(*modified)
                    .is_ok_and(|d| d.as_secs() > 45)
            {
                let _ = fs::remove_file(path);
            }
        }
        let mut rows = vec![];
        for (_, path) in files.into_iter().take(100) {
            match read_limited(&path).and_then(|b| Session::parse(&b)) {
                Ok(s) if path.file_stem().is_some_and(|n| n == s.session.as_str()) => rows.push(s),
                _ => invalid = true,
            }
        }
        Ok((rows, invalid))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn session() -> Session {
        Session {
            schema: 1,
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
}
