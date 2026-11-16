use crate::backend::{Manager, Result, atomic_write, read_limited};
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
        builtin(r)
            .map(|v| v.0.to_owned())
            .or_else(|| self.names.get(id).cloned())
            .unwrap_or_else(|| crate::backend::safe_label(id))
    }
    pub fn dirty(&self, other: &Self) -> bool {
        self.config != other.config || self.names != other.names
    }
    pub fn toggle(&mut self, i: usize) {
        if editable(&self.rows()[i]) {
            let r = &mut self.rows_mut()[i];
            r["enabled"] = json!(!r["enabled"].as_bool().unwrap_or(false));
        }
    }
    pub fn edit(&mut self, index: Option<usize>, name: String, value: String) -> Result<()> {
        if name.trim().is_empty()
            || name.chars().count() > 60
            || value.trim().is_empty()
            || value.len() > 8192
        {
            return Err("RULE_FIELDS_REQUIRED");
        }
        if let Some(i) = index {
            if self.rows().get(i).is_none_or(|r| !simple_exact(r)) {
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
        if let Some(i) = index {
            self.rows_mut()[i]["detector"]["values"] = json!([value]);
        } else {
            self.rows_mut().push(json!({"id":id,"enabled":true,"sources":["tool.input","tool.result","user.prompt"],"action":"block","detector":{"kind":"exact","values":[value],"caseSensitive":true}}));
        }
        self.names.insert(id, name.trim().into());
        Ok(())
    }
    pub fn remove(&mut self, i: usize) {
        if simple_exact(&self.rows()[i]) {
            let r = self.rows_mut().remove(i);
            self.names.remove(r["id"].as_str().unwrap());
        }
    }
    pub fn summary(&self, old: &Self) -> String {
        let disabled = self
            .rows()
            .iter()
            .filter(|r| {
                r["enabled"] == false
                    && old
                        .rows()
                        .iter()
                        .any(|x| x["id"] == r["id"] && x["enabled"] == true)
            })
            .count();
        let removed = old
            .rows()
            .iter()
            .filter(|r| !self.rows().iter().any(|x| x["id"] == r["id"]))
            .count();
        format!(
            "将关闭 {disabled} 条 · 删除 {removed} 条 · 脱敏 {} 条 · 恢复策略 {} · 保存后新会话生效",
            self.rows()
                .iter()
                .filter(|r| r["action"] == "redact")
                .count(),
            self.config["policy"]["recovery"]
                .as_str()
                .unwrap_or("session-lock")
        )
    }
}
pub fn builtin(r: &Value) -> Option<(&'static str, &'static str)> {
    if r["detector"]["kind"] == "ip"
        && r["sources"] == json!(["tool.result"])
        && r["action"] == "redact"
    {
        return Some(("IP 结果脱敏", "支持的诊断文本替换为代号；其余结果扣留"));
    }
    if r["action"] != "block" {
        return None;
    }
    match (r["id"].as_str()?, r["detector"]["kind"].as_str()?) {
        ("security.credentials", "builtin") if r["detector"]["name"] == "credentials" => {
            Some(("凭据", "检查已支持的密钥与凭据格式"))
        }
        ("identity.device", "builtin") if r["detector"]["name"] == "device-identifiers" => {
            Some(("设备标识", "检查设备标识类字段"))
        }
        ("identity.environment", "builtin") if r["detector"]["name"] == "personal-environment" => {
            Some(("主机名字段", "检查主机名与本机环境标识"))
        }
        ("network.address", "ip") if r["detector"]["mode"] == "country" => {
            Some(("中国 IP", "离线查询，仅拦截 CN；其他地区和未知地址放行"))
        }
        ("network.address", "ip") if r["detector"]["mode"] == "any" => {
            Some(("IP 地址", "检查未豁免地址；保留当前网段豁免设置"))
        }
        _ => None,
    }
}
pub fn simple_exact(r: &Value) -> bool {
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
        && r["detector"]["caseSensitive"] == true
        && r["detector"]["values"]
            .as_array()
            .is_some_and(|v| v.len() == 1)
}
pub fn editable(r: &Value) -> bool {
    builtin(r).is_some() || simple_exact(r)
}
impl Manager {
    pub fn recovery_draft(&self, redact: bool) -> Result<Document> {
        let mut doc = self.document()?;
        let text = serde_json::to_string(&doc.config).map_err(|_| "RULE_CONFIG_REJECTED")?;
        doc.config = serde_json::from_str(&crate::validator::migrate(&text, redact)?)
            .map_err(|_| "RULE_CONFIG_REJECTED")?;
        Ok(doc)
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
            let bytes = read_limited(
                &self
                    .market
                    .join("plugins/agent-safeguard/.claude-plugin/plugin.json"),
            )
            .map_err(|_| "RECOVERY_REQUIRES_UPDATE")?;
            let manifest: Value =
                serde_json::from_slice(&bytes).map_err(|_| "RECOVERY_REQUIRES_UPDATE")?;
            if crate::backend::version(manifest["version"].as_str().unwrap_or(""))? < vec![0, 2, 0]
            {
                return Err("RECOVERY_REQUIRES_UPDATE");
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
        // Names are accepted only for the exact matching config digest. A crash here
        // can lose display labels, never attach them to a different rule snapshot.
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
}
