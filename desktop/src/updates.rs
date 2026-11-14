//! Only the project's HTTPS release feed is trusted; user data is never sent.
use crate::backend::{Result, version};
use crate::rules::digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, time::Duration};
const FEED: &str = "https://api.github.com/repos/yipengfei329/agent-safeguard/releases/latest";
const ASSET: &str = "agent-safeguard-plugin.json";
const PREFIX: &str = "https://github.com/yipengfei329/agent-safeguard/releases/download/";
const MAX: u64 = 4 * 1024 * 1024;
#[derive(Clone)]
pub struct Release {
    pub version: String,
    url: String,
    sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub schema: u8,
    pub version: String,
    pub files: BTreeMap<String, String>,
}
fn get(url: &str, limit: u64) -> Result<Vec<u8>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .https_only(true)
        .build()
        .into();
    let mut response = agent
        .get(url)
        .header("User-Agent", "Agent-Safeguard-Desktop")
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|_| "UPDATE_FEED_UNAVAILABLE")?;
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|_| "UPDATE_DOWNLOAD_FAILED")
}
impl Release {
    pub fn parse(v: Value) -> Result<Self> {
        if v["draft"] != false || v["prerelease"] != false {
            return Err("UPDATE_FEED_INVALID");
        }
        let tag = v["tag_name"].as_str().ok_or("UPDATE_FEED_INVALID")?;
        let name = tag.strip_prefix('v').unwrap_or(tag);
        version(name).map_err(|_| "UPDATE_FEED_INVALID")?;
        let asset = v["assets"]
            .as_array()
            .and_then(|a| a.iter().find(|a| a["name"] == ASSET))
            .ok_or("UPDATE_PACKAGE_UNPUBLISHED")?;
        let url = asset["browser_download_url"]
            .as_str()
            .ok_or("UPDATE_FEED_INVALID")?;
        if url != format!("{PREFIX}{tag}/{ASSET}") || asset["size"].as_u64().is_none_or(|n| n > MAX)
        {
            return Err("UPDATE_FEED_INVALID");
        }
        let hash = asset["digest"]
            .as_str()
            .and_then(|s| s.strip_prefix("sha256:"))
            .filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
            .ok_or("UPDATE_DIGEST_REQUIRED")?;
        Ok(Self {
            version: name.into(),
            url: url.into(),
            sha256: hash.to_ascii_lowercase(),
        })
    }
    pub fn check() -> Result<Self> {
        let b = get(FEED, 256 * 1024)?;
        Self::parse(serde_json::from_slice(&b).map_err(|_| "UPDATE_FEED_INVALID")?)
    }
    pub fn download(&self) -> Result<Package> {
        self.verify(&get(&self.url, MAX)?)
    }
    fn verify(&self, bytes: &[u8]) -> Result<Package> {
        if bytes.len() as u64 > MAX || digest(bytes) != self.sha256 {
            return Err("UPDATE_DIGEST_MISMATCH");
        }
        let p: Package = serde_json::from_slice(bytes).map_err(|_| "UPDATE_PACKAGE_INVALID")?;
        const FILES: [&str; 6] = [
            ".claude-plugin/plugin.json",
            "hooks/register.js",
            "hooks/hooks.json",
            "dist/core.js",
            "README.md",
            "LICENSE",
        ];
        if p.schema != 1
            || p.version != self.version
            || p.files.len() != FILES.len()
            || !FILES.iter().all(|n| p.files.contains_key(*n))
            || p.files.values().any(|s| s.len() > 1_048_576)
        {
            return Err("UPDATE_PACKAGE_INVALID");
        }
        let manifest: Value = serde_json::from_str(&p.files[".claude-plugin/plugin.json"])
            .map_err(|_| "UPDATE_PACKAGE_INVALID")?;
        if manifest["name"] != "agent-safeguard" || manifest["version"] != self.version {
            return Err("UPDATE_PACKAGE_INVALID");
        }
        // Updating the engine requires a matching desktop validator. Do not validate
        // a new plugin's rules with an older embedded engine and report success.
        if p.files["dist/core.js"].as_bytes() != include_bytes!("../../dist/core.js") {
            return Err("DESKTOP_UPDATE_REQUIRED");
        }
        Ok(p)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn rejects_wrong_origin_or_missing_digest() {
        let v = json!({"draft":false,"prerelease":false,"tag_name":"v0.1.8","assets":[{"name":ASSET,"browser_download_url":"https://example.invalid/plugin.json","size":100,"digest":format!("sha256:{}","0".repeat(64))}]});
        assert!(Release::parse(v).is_err());
    }
    #[test]
    fn tampering_never_reaches_installer() {
        let r = Release {
            version: "0.1.8".into(),
            url: String::new(),
            sha256: "0".repeat(64),
        };
        assert!(matches!(r.verify(b"{}"), Err("UPDATE_DIGEST_MISMATCH")));
    }
}
