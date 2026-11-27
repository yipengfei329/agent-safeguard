use crate::backend::{Manager, Result, atomic_write, read_limited};
use crate::validator::SandboxResult;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Document {
    pub config: Value,
    pub names: BTreeMap<String, String>,
    #[serde(skip)]
    pub baseline: String,
}
impl Document {
    pub fn version(&self) -> String {
        self.config["ruleSetVersion"]
            .as_str()
            .unwrap_or("未知")
            .into()
    }
    pub fn is_modern(&self) -> bool {
        self.config["schemaVersion"] == 2
            && self.config["policy"]["recovery"] == "next-safe-user-prompt"
    }
    pub fn rows(&self) -> &Vec<Value> {
        self.config["rules"].as_array().expect("validated rules")
    }
    pub fn rows_mut(&mut self) -> &mut Vec<Value> {
        self.config["rules"]
            .as_array_mut()
            .expect("validated rules")
    }
    pub fn name(&self, r: &Value) -> String {
        let id = r["id"].as_str().unwrap_or("");
        if id == "personal.local-identity" {
            return "本机设备与主机标识".into();
        }
        builtin(r)
            .map(|v| v.0.to_owned())
            .or_else(|| self.names.get(id).cloned())
            .unwrap_or_else(|| crate::backend::safe_label(id))
    }
    pub fn dirty(&self, other: &Self) -> bool {
        self.config != other.config || self.names != other.names
    }
    pub fn local_identity_status(&self) -> Option<(usize, usize, bool)> {
        self.rows()
            .iter()
            .enumerate()
            .find(|(_, r)| r["id"] == "personal.local-identity" && r["detector"]["kind"] == "exact")
            .map(|(idx, r)| {
                let count = r["detector"]["values"]
                    .as_array()
                    .map(|v| v.len())
                    .unwrap_or(0);
                (idx, count, r["enabled"] == true)
            })
    }
    pub fn sync_local_identity(&mut self, values: Vec<String>) -> Result<usize> {
        if values.is_empty() {
            return Err("LOCAL_IDENTITY_EMPTY");
        }
        let count = values.len();
        let rule = json!({
            "id": "personal.local-identity",
            "enabled": true,
            "sources": ["tool.input", "tool.result", "user.prompt"],
            "action": "block",
            "detector": {
                "kind": "exact",
                "values": values,
                "caseSensitive": false
            }
        });
        if let Some(pos) = self
            .rows()
            .iter()
            .position(|r| r["id"] == "personal.local-identity")
        {
            self.rows_mut()[pos] = rule;
        } else {
            self.rows_mut().insert(0, rule);
        }
        if let Some(env_rule) = self
            .rows_mut()
            .iter_mut()
            .find(|r| r["id"] == "identity.environment" && r["detector"]["kind"] == "builtin")
        {
            env_rule["enabled"] = json!(false);
        }
        self.names
            .insert("personal.local-identity".into(), "本机设备与主机标识".into());
        Ok(count)
    }
    pub fn ip_output_redacted(&self) -> Option<bool> {
        if !self.is_modern() {
            return None;
        }
        if self.rows().iter().any(|r| {
            r["detector"]["kind"] == "ip"
                && r["action"] == "redact"
                && r["sources"] == json!(["tool.result"])
        }) {
            return Some(true);
        }
        if self.rows().iter().any(|r| {
            r["id"] == "network.address"
                && r["detector"]["kind"] == "ip"
                && r["action"] == "block"
        }) {
            return Some(false);
        }
        None
    }
    pub fn set_ip_output_redaction(&mut self, redact: bool) -> Result<()> {
        if !self.is_modern() {
            return Err("RECOVERY_REQUIRES_UPDATE");
        }
        if redact {
            if self.ip_output_redacted() == Some(true) {
                return Ok(());
            }
            let Some(pos) = self
                .rows()
                .iter()
                .position(|r| r["id"] == "network.address" && r["detector"]["kind"] == "ip")
            else {
                return Ok(());
            };
            let detector = self.rows()[pos]["detector"].clone();
            let enabled = self.rows()[pos]["enabled"].clone();
            self.rows_mut()[pos]["sources"] = json!(["user.prompt"]);
            self.rows_mut()[pos]["action"] = json!("block");
            let out_rule = json!({
                "id": "network.address.output",
                "enabled": enabled,
                "sources": ["tool.result"],
                "action": "redact",
                "detector": detector
            });
            if let Some(out_pos) = self
                .rows()
                .iter()
                .position(|r| r["id"] == "network.address.output")
            {
                self.rows_mut()[out_pos] = out_rule;
            } else {
                self.rows_mut().insert(pos + 1, out_rule);
            }
        } else {
            let enabled = self
                .rows()
                .iter()
                .find(|r| r["id"] == "network.address.output")
                .map(|r| r["enabled"] == true)
                .unwrap_or(true);
            self.rows_mut()
                .retain(|r| r["id"] != "network.address.output");
            if let Some(base) = self
                .rows_mut()
                .iter_mut()
                .find(|r| r["id"] == "network.address" && r["detector"]["kind"] == "ip")
            {
                base["sources"] = json!(["tool.result", "user.prompt"]);
                base["action"] = json!("block");
                base["enabled"] = json!(base["enabled"] == true || enabled);
            }
        }
        Ok(())
    }
    pub fn toggle(&mut self, i: usize) {
        if editable(&self.rows()[i]) || self.rows()[i]["id"] == "personal.local-identity" {
            let next = !self.rows()[i]["enabled"].as_bool().unwrap_or(false);
            let is_ip = self.rows()[i]["id"] == "network.address"
                || self.rows()[i]["id"] == "network.address.output";
            self.rows_mut()[i]["enabled"] = json!(next);
            if is_ip {
                for r in self.rows_mut().iter_mut() {
                    if r["id"] == "network.address" || r["id"] == "network.address.output" {
                        r["enabled"] = json!(next);
                    }
                }
            }
        }
    }
    #[cfg(test)]
    pub fn edit(&mut self, index: Option<usize>, name: String, value: String) -> Result<()> {
        self.edit_custom(index, name, value, false, true)
    }
    pub fn edit_custom(
        &mut self,
        index: Option<usize>,
        name: String,
        value: String,
        is_domain: bool,
        case_sensitive: bool,
    ) -> Result<()> {
        let clean_value = if is_domain {
            let trimmed = value
                .trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split(['/', ':', '?'])
                .next()
                .unwrap_or("")
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if trimmed.is_empty() {
                return Err("RULE_FIELDS_REQUIRED");
            }
            if !trimmed.contains('.')
                || trimmed.split('.').any(|label| {
                    label.is_empty()
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-')
                })
            {
                return Err("INVALID_DOMAIN");
            }
            trimmed
        } else {
            value.clone()
        };
        if name.trim().is_empty()
            || name.chars().count() > 60
            || clean_value.trim().is_empty()
            || clean_value.len() > 4096
        {
            return Err("RULE_FIELDS_REQUIRED");
        }
        if let Some(i) = index {
            if self.rows().get(i).is_none_or(|r| !custom_editable(r)) {
                return Err("ADVANCED_RULE_READ_ONLY");
            }
        }
        let id = index
            .map(|i| self.rows()[i]["id"].as_str().unwrap().to_string())
            .unwrap_or_else(|| {
                format!(
                    "custom.{}",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                )
            });
        let detector = if is_domain {
            json!({"kind": "domain", "suffixes": [clean_value]})
        } else {
            json!({"kind": "exact", "values": [clean_value], "caseSensitive": case_sensitive})
        };
        let rule = json!({
            "id": id,
            "enabled": index.and_then(|i| self.rows().get(i)).and_then(|r| r["enabled"].as_bool()).unwrap_or(true),
            "sources": ["tool.input", "tool.result", "user.prompt"],
            "action": "block",
            "detector": detector
        });
        if let Some(i) = index {
            self.rows_mut()[i] = rule;
        } else {
            self.rows_mut().push(rule);
        }
        self.names.insert(id, name.trim().into());
        Ok(())
    }
    pub fn remove(&mut self, i: usize) {
        if custom_editable(&self.rows()[i]) {
            let r = self.rows_mut().remove(i);
            self.names.remove(r["id"].as_str().unwrap());
        }
    }
}
pub fn builtin(r: &Value) -> Option<(&'static str, &'static str)> {
    if r["detector"]["kind"] == "ip"
        && r["sources"] == json!(["tool.result"])
        && r["action"] == "redact"
    {
        return Some(("IP 结果自动脱敏", "将诊断输出中的受保护 IP 替换为 [IP_1] 代号继续运行"));
    }
    if r["action"] != "block" && r["action"] != "observe" {
        return None;
    }
    match (r["id"].as_str()?, r["detector"]["kind"].as_str()?) {
        ("security.credentials", "builtin") if r["detector"]["name"] == "credentials" => {
            Some(("密钥与凭据", "拦截私钥、16 类主流平台 Token、连接串密码与高强度随机密钥"))
        }
        ("identity.device", "builtin") if r["detector"]["name"] == "device-identifiers" => {
            Some(("设备硬件标识", "检查序列号、UDID 与物理网卡 MAC（自动豁免已标记模拟器）"))
        }
        ("identity.environment", "builtin") if r["detector"]["name"] == "personal-environment" => {
            Some(("通用主机名字段", "检查配置中的 hostname 字段（已导入本机标识时建议关闭以防误报）"))
        }
        ("network.address", "ip") if r["detector"]["mode"] == "country" => {
            Some(("中国境内公网 IP", "离线归属地查询，仅保护 CN 公网地址（内网与海外地址放行）"))
        }
        ("network.address", "ip") if r["detector"]["mode"] == "any" => {
            Some(("公网 IP 地址", "检查所有未豁免的公网地址（保留本机与内网豁免）"))
        }
        _ => None,
    }
}
pub fn simple_exact(r: &Value) -> bool {
    if r["id"] == "personal.local-identity" {
        return false;
    }
    let mut sources = r["sources"].as_array().cloned().unwrap_or_default();
    sources.sort_by_key(|v| v.as_str().unwrap_or("").to_owned());
    r["action"] == "block"
        && r.get("tools").is_none()
        && sources
            == json!(["tool.input", "tool.result", "user.prompt"])
                .as_array()
                .unwrap()
                .clone()
        && r["detector"]["kind"] == "exact"
        && r["detector"]["caseSensitive"].is_boolean()
        && r["detector"]["values"]
            .as_array()
            .is_some_and(|v| v.len() == 1)
}
pub fn simple_domain(r: &Value) -> bool {
    let mut sources = r["sources"].as_array().cloned().unwrap_or_default();
    sources.sort_by_key(|v| v.as_str().unwrap_or("").to_owned());
    r["action"] == "block"
        && r.get("tools").is_none()
        && (sources
            == json!(["tool.input", "tool.result", "user.prompt"])
                .as_array()
                .unwrap()
                .clone()
            || sources
                == json!(["tool.result", "user.prompt"])
                    .as_array()
                    .unwrap()
                    .clone())
        && r["detector"]["kind"] == "domain"
        && r["detector"]["suffixes"]
            .as_array()
            .is_some_and(|v| v.len() == 1)
}
pub fn custom_editable(r: &Value) -> bool {
    simple_exact(r) || simple_domain(r)
}
pub fn editable(r: &Value) -> bool {
    builtin(r).is_some() || custom_editable(r)
}
impl Manager {
    pub fn recovery_draft(&self, redact: bool) -> Result<Document> {
        let mut doc = self.document()?;
        let text = serde_json::to_string(&doc.config).map_err(|_| "RULE_CONFIG_REJECTED")?;
        doc.config = serde_json::from_str(&crate::validator::migrate(&text, redact)?)
            .map_err(|_| "RULE_CONFIG_REJECTED")?;
        Ok(doc)
    }
    pub fn preview_sample(&self, doc: &Document, sample: &str) -> Result<SandboxResult> {
        let text = serde_json::to_string(&doc.config).map_err(|_| "RULE_CONFIG_REJECTED")?;
        crate::validator::preview(&text, sample)
    }
    fn rule_bytes(&self) -> Result<Vec<u8>> {
        if self.rules_path().exists() {
            read_limited(&self.rules_path())
        } else {
            Ok(crate::backend::fresh_rules().into_bytes())
        }
    }
    pub fn document(&self) -> Result<Document> {
        let bytes = self.rule_bytes()?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "RULE_CONFIG_REJECTED")?;
        self.validate(text)?;
        let config = serde_json::from_slice(&bytes).map_err(|_| "RULE_CONFIG_REJECTED")?;
        let baseline = digest(&bytes);
        let names = read_limited(&self.rules_path().with_file_name("rule-names.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .filter(|v| v["digest"] == baseline)
            .and_then(|v| serde_json::from_value(v["names"].clone()).ok())
            .unwrap_or_default();
        Ok(Document {
            config,
            names,
            baseline,
        })
    }
    pub fn commit_document(&self, mut draft: Document) -> Result<Document> {
        let _lock = self.lock()?;
        if draft.config["schemaVersion"] == 2 && !self.demo {
            let plugin_manifest = self
                .market
                .join("plugins/agent-safeguard/.claude-plugin/plugin.json");
            if plugin_manifest.exists() {
                let bytes =
                    read_limited(&plugin_manifest).map_err(|_| "RECOVERY_REQUIRES_UPDATE")?;
                let manifest: Value =
                    serde_json::from_slice(&bytes).map_err(|_| "RECOVERY_REQUIRES_UPDATE")?;
                if crate::backend::version(manifest["version"].as_str().unwrap_or(""))?
                    < vec![0, 2, 0]
                {
                    return Err("RECOVERY_REQUIRES_UPDATE");
                }
            }
        }
        if digest(&self.rule_bytes()?) != draft.baseline {
            return Err("RULES_CHANGED_EXTERNALLY");
        }
        let old = self.document()?;
        draft.config["ruleSetVersion"] = json!(format!(
            "desktop-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let text =
            serde_json::to_string_pretty(&draft.config).map_err(|_| "RULE_CONFIG_REJECTED")?;
        self.validate(&text)?;
        // Compare again after validation: never knowingly overwrite an external edit.
        if digest(&self.rule_bytes()?) != draft.baseline {
            return Err("RULES_CHANGED_EXTERNALLY");
        }
        atomic_write(
            &self.rules_path().with_file_name("desktop.previous.json"),
            &serde_json::to_vec(&old).map_err(|_| "WRITE_FAILED")?,
        )?;
        atomic_write(
            &self.rules_path().with_file_name("rules.previous.json"),
            &serde_json::to_vec_pretty(&old.config).map_err(|_| "WRITE_FAILED")?,
        )?;
        let hash = digest(text.as_bytes());
        atomic_write(
            &self.rules_path().with_file_name("rule-names.json"),
            json!({"digest":hash,"names":draft.names})
                .to_string()
                .as_bytes(),
        )?;
        atomic_write(&self.rules_path(), text.as_bytes())?;
        draft.baseline = hash;
        Ok(draft)
    }
    pub fn previous_document(&self, baseline: String) -> Result<Document> {
        let mut doc: Document = serde_json::from_slice(&read_limited(
            &self.rules_path().with_file_name("desktop.previous.json"),
        )?)
        .map_err(|_| "NO_PREVIOUS_RULES")?;
        self.validate(&doc.config.to_string())?;
        doc.baseline = baseline;
        Ok(doc)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_migration_is_a_reviewable_draft_and_preserves_custom_rules() {
        let temp = tempfile::tempdir().unwrap();
        let m = Manager::new(true, Some(temp.path().into())).unwrap();
        let mut original = m.document().unwrap();
        original
            .edit(None, "虚构规则".into(), "SYNTHETIC_MIGRATION".into())
            .unwrap();
        let original = m.commit_document(original).unwrap();
        let before = std::fs::read(m.rules_path()).unwrap();
        let draft = m.recovery_draft(true).unwrap();
        assert_eq!(std::fs::read(m.rules_path()).unwrap(), before);
        assert_eq!(draft.names, original.names);
        assert_eq!(draft.config["schemaVersion"], 2);
        assert!(draft.rows().iter().any(|r| r["action"] == "redact"));
        for rule in original
            .rows()
            .iter()
            .filter(|r| r["detector"]["kind"] != "ip")
        {
            assert!(draft.rows().contains(rule));
        }
        let saved = m.commit_document(draft).unwrap();
        assert_eq!(
            m.previous_document(saved.baseline).unwrap().config,
            original.config
        );
    }
    #[test]
    fn old_installation_cannot_save_v2() {
        let temp = tempfile::tempdir().unwrap();
        let m = Manager::new(false, Some(temp.path().into())).unwrap();
        let manifest = m
            .market
            .join("plugins/agent-safeguard/.claude-plugin/plugin.json");
        atomic_write(&manifest, br#"{"version":"0.1.25"}"#).unwrap();
        assert!(matches!(
            m.commit_document(m.recovery_draft(false).unwrap()),
            Err("RECOVERY_REQUIRES_UPDATE")
        ));
        assert!(!m.rules_path().exists());
    }
    #[test]
    fn management_lock_and_private_file_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let m = Manager::new(false, Some(temp.path().into())).unwrap();
        let lock = m.lock().unwrap();
        assert!(matches!(
            m.commit_document(m.document().unwrap()),
            Err("ANOTHER_OPERATION_RUNNING")
        ));
        drop(lock);
        m.commit_document(m.document().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(m.rules_path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn stale_draft_cannot_overwrite_external_edit() {
        let d = tempfile::tempdir().unwrap();
        let m = Manager::new(false, Some(d.path().into())).unwrap();
        let a = m.document().unwrap();
        let b = a.clone();
        m.commit_document(a).unwrap();
        assert!(matches!(
            m.commit_document(b),
            Err("RULES_CHANGED_EXTERNALLY")
        ));
    }
    #[test]
    fn advanced_rules_round_trip_and_restore() {
        let d = tempfile::tempdir().unwrap();
        let m = Manager::new(false, Some(d.path().into())).unwrap();
        let mut a = m.document().unwrap();
        let advanced = json!({"id":"custom.advanced","enabled":true,"sources":["tool.result"],"action":"observe","tools":["Bash"],"detector":{"kind":"exact","values":["A","B"],"caseSensitive":false}});
        a.rows_mut().push(advanced.clone());
        let a = m.commit_document(a).unwrap();
        let mut b = a.clone();
        b.edit(None, "虚构规则".into(), "SYNTHETIC_MARKER".into())
            .unwrap();
        let b = m.commit_document(b).unwrap();
        assert_eq!(
            b.rows()
                .iter()
                .find(|r| r["id"] == "custom.advanced")
                .unwrap(),
            &advanced
        );
        let prev = m.previous_document(b.baseline.clone()).unwrap();
        assert_eq!(prev.config, a.config);
        assert_eq!(m.document().unwrap().names, b.names);
    }
    #[test]
    fn invalid_draft_leaves_config_and_backup_untouched() {
        let d = tempfile::tempdir().unwrap();
        let m = Manager::new(false, Some(d.path().into())).unwrap();
        let a = m.commit_document(m.document().unwrap()).unwrap();
        let before = std::fs::read(m.rules_path()).unwrap();
        let mut bad = a;
        bad.config["rules"][0]["detector"]["excludeCidrs"] = json!(["bad"]);
        assert!(m.commit_document(bad).is_err());
        assert_eq!(std::fs::read(m.rules_path()).unwrap(), before);
    }
    #[test]
    fn local_identity_sync_domain_rules_ip_mode_and_sandbox_preview() {
        let d = tempfile::tempdir().unwrap();
        let m = Manager::new(true, Some(d.path().into())).unwrap();
        let mut doc = m.document().unwrap();
        assert!(doc.is_modern());
        assert_eq!(doc.ip_output_redacted(), Some(true));

        let synced = doc
            .sync_local_identity(vec!["Synthetic-Host.local".into(), "SYNTH_SN_01".into()])
            .unwrap();
        assert_eq!(synced, 2);
        assert_eq!(doc.local_identity_status(), Some((0, 2, true)));

        doc.edit_custom(None, "内网域名".into(), "*.corp.example.invalid".into(), true, false)
            .unwrap();
        let saved = m.commit_document(doc).unwrap();

        let pass = m.preview_sample(&saved, "const token = \"USER_PROFILE\";").unwrap();
        assert_eq!(pass.kind, "pass");

        let hit_host = m.preview_sample(&saved, "Darwin synthetic-host.local").unwrap();
        assert_eq!(hit_host.kind, "withhold");
        assert_eq!(hit_host.rule.as_deref(), Some("personal.local-identity"));

        let hit_domain = m.preview_sample(&saved, "https://git.corp.example.invalid/repo").unwrap();
        assert_eq!(hit_domain.kind, "withhold");

        let hit_ip = m.preview_sample(&saved, "2026/01/15 12:00:00 dial tcp 1.0.1.7:443: timeout").unwrap();
        assert_eq!(hit_ip.kind, "redacted");
        assert_eq!(hit_ip.count, 1);

        let mut block_ip = saved.clone();
        block_ip.set_ip_output_redaction(false).unwrap();
        let block_ip = m.commit_document(block_ip).unwrap();
        assert_eq!(block_ip.ip_output_redacted(), Some(false));
        let blocked_ip = m.preview_sample(&block_ip, "peer=1.0.1.7").unwrap();
        assert_eq!(blocked_ip.kind, "withhold");
        assert_eq!(blocked_ip.rule.as_deref(), Some("network.address"));
    }
}
