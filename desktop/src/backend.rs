//! Local management only. Never emits child stderr or private rule contents.
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const PLUGIN_ID: &str = "agent-safeguard@agent-safeguard-local";
pub const BUNDLED_VERSION: &str = "0.2.2";
pub const DEFAULT_RULES: &str = include_str!("../../config/tool-results.json");
const MAX_BYTES: usize = 1_048_576;
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone)]
pub struct Manager {
    pub market: PathBuf,
    pub demo: bool,
    pub claude: Option<PathBuf>,
}
#[derive(Clone, Default)]
pub struct Harness {
    pub found: bool,
    pub version: String,
    pub plugin: String,
    pub enabled: Option<bool>,
    pub installed: bool,
    pub query_ok: bool,
}

pub fn executable(name: &str) -> Option<PathBuf> {
    let mut paths: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if let Some(home) = dirs::home_dir() {
        paths.extend([
            home.join(".local/bin"),
            home.join(".volta/bin"),
            home.join(".cargo/bin"),
        ]);
    }
    paths.extend([
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
    ]);
    let names = if cfg!(windows) {
        vec![format!("{name}.exe"), name.into()]
    } else {
        vec![name.into()]
    };
    paths
        .into_iter()
        .flat_map(|p| names.iter().map(move |n| p.join(n)))
        .find(|p| p.is_file())
}

// Bounded stdout, discarded stderr, no shell interpolation. The caller runs off the UI thread.
pub fn run(
    program: &Path,
    args: &[&str],
    input: Option<Vec<u8>>,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().map_err(|_| "COMMAND_UNAVAILABLE")?;
    if let Some(bytes) = input {
        let mut stdin = child.stdin.take().ok_or("COMMAND_FAILED")?;
        thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
    }
    let stdout = child.stdout.take().ok_or("COMMAND_FAILED")?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Descendant processes inheriting stdout must not keep the UI waiting.
                while !reader.is_finished() {
                    if start.elapsed() >= timeout {
                        return Err("COMMAND_TIMEOUT");
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                let bytes = reader
                    .join()
                    .map_err(|_| "COMMAND_FAILED")?
                    .map_err(|_| "COMMAND_FAILED")?;
                if bytes.len() > MAX_BYTES {
                    return Err("OUTPUT_LIMIT");
                }
                return if status.success() {
                    Ok(bytes)
                } else {
                    Err("COMMAND_FAILED")
                };
            }
            Ok(None) if start.elapsed() < timeout => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("COMMAND_TIMEOUT");
            }
        }
    }
}

pub(crate) fn read_limited(path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|_| "FILE_UNAVAILABLE")?;
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "FILE_UNAVAILABLE")?;
    if bytes.len() > MAX_BYTES {
        return Err("INPUT_LIMIT");
    }
    Ok(bytes)
}
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("INVALID_DESTINATION")?;
    fs::create_dir_all(parent).map_err(|_| "WRITE_FAILED")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| "WRITE_FAILED")?;
    }
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|_| "WRITE_FAILED")?;
    temp.write_all(bytes)
        .and_then(|_| temp.as_file().sync_all())
        .map_err(|_| "WRITE_FAILED")?;
    temp.persist(path).map_err(|_| "WRITE_FAILED")?;
    Ok(())
}

impl Manager {
    pub fn new(demo: bool, base: Option<PathBuf>) -> Result<Self> {
        let market = if let Some(base) = base {
            base.join("marketplace")
        } else {
            dirs::home_dir()
                .ok_or("HOME_UNAVAILABLE")?
                .join(".local/share/agent-safeguard/marketplace")
        };
        let preferences = market
            .parent()
            .ok_or("INVALID_DESTINATION")?
            .join("desktop-preferences.json");
        let claude = read_limited(&preferences)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v["claude"].as_str().map(PathBuf::from));
        Ok(Self {
            market,
            demo,
            claude,
        })
    }
    pub fn rules_path(&self) -> PathBuf {
        self.market.join("plugins/agent-safeguard/local/rules.json")
    }
    pub fn detect(&self) -> Vec<Harness> {
        ["claude"]
            .into_iter()
            .map(|name| {
                if self.demo {
                    return Harness {
                        found: name != "gemini",
                        version: "演示环境".into(),
                        plugin: if name == "claude" {
                            BUNDLED_VERSION.into()
                        } else {
                            "尚未适配".into()
                        },
                        enabled: (name == "claude").then_some(true),
                        installed: true,
                        query_ok: true,
                    };
                }
                let Some(path) = self.claude.clone().or_else(|| executable(name)) else {
                    return Harness {
                        plugin: "未检测到程序".into(),
                        ..Default::default()
                    };
                };
                // Only Claude's known CLI contract is invoked. Other harnesses are executable discovery only.
                let mut h = Harness {
                    found: true,
                    version: "已发现可执行文件".into(),
                    plugin: "尚未适配".into(),
                    enabled: None,
                    installed: false,
                    query_ok: false,
                };
                if name == "claude" {
                    h.version = run(&path, &["--version"], None, Duration::from_secs(5))
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok())
                        .and_then(|s| s.split_whitespace().next().map(str::to_owned))
                        .filter(|s| {
                            s.len() < 40 && s.chars().all(|c| c.is_ascii_digit() || c == '.')
                        })
                        .unwrap_or("版本未知".into());
                    h.plugin = "查询失败".into();
                    if let Ok(bytes) = run(
                        &path,
                        &["plugin", "list", "--json"],
                        None,
                        Duration::from_secs(10),
                    ) {
                        if let Ok(rows) = serde_json::from_slice::<Vec<Value>>(&bytes) {
                            h.plugin = "未安装（用户范围）".into();
                            h.query_ok = true;
                            if let Some(p) = rows
                                .iter()
                                .find(|p| p["id"] == PLUGIN_ID && p["scope"] == "user")
                            {
                                h.installed = true;
                                h.plugin = safe_label(p["version"].as_str().unwrap_or("unknown"));
                                h.enabled = p["enabled"].as_bool();
                            }
                        }
                    }
                }
                h
            })
            .collect()
    }
    pub fn validate(&self, text: &str) -> Result<()> {
        crate::validator::validate(text)
    }
    pub fn base(&self) -> PathBuf {
        self.market.parent().unwrap().to_path_buf()
    }
    pub fn status_dir(&self) -> PathBuf {
        self.base().join("sessions")
    }
    pub fn select_program(&mut self, path: PathBuf) -> Result<()> {
        if !path.is_file() {
            return Err("CLAUDE_NOT_FOUND");
        }
        let version = run(&path, &["--version"], None, Duration::from_secs(5))?;
        if !String::from_utf8_lossy(&version).contains("Claude Code") {
            return Err("NOT_CLAUDE_CODE");
        }
        atomic_write(
            &self.base().join("desktop-preferences.json"),
            json!({"claude":path}).to_string().as_bytes(),
        )?;
        self.claude = Some(path);
        Ok(())
    }
    pub fn lock(&self) -> Result<fs::File> {
        fs::create_dir_all(self.base()).map_err(|_| "WRITE_FAILED")?;
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.base().join("management.lock"))
            .map_err(|_| "WRITE_FAILED")?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|_| "ANOTHER_OPERATION_RUNNING")?;
        Ok(file)
    }
    pub fn plugin_action(&self, action: &str) -> Result<()> {
        self.deploy(action, None)
    }
    pub fn update_release(&self, release: crate::updates::Release) -> Result<()> {
        let package = release.download()?;
        self.deploy("update", Some(&package))
    }
    fn deploy(&self, action: &str, package: Option<&crate::updates::Package>) -> Result<()> {
        let target_version = package
            .map(|p| p.version.as_str())
            .unwrap_or(BUNDLED_VERSION);
        if self.demo {
            return Err("DEMO_MODE_NO_HARNESS_CHANGES");
        }
        if !["install", "update", "enable", "disable", "uninstall"].contains(&action) {
            return Err("UNSUPPORTED_ACTION");
        }
        let _lock = self.lock()?;
        let claude = self
            .claude
            .clone()
            .or_else(|| executable("claude"))
            .ok_or("CLAUDE_NOT_FOUND")?;
        if ["enable", "disable", "uninstall"].contains(&action) {
            run(
                &claude,
                &["plugin", action, PLUGIN_ID, "--scope", "user"],
                None,
                Duration::from_secs(30),
            )?;
            return self.verify_action(action, target_version);
        }
        let root = self.market.join("plugins/agent-safeguard");
        let files: Vec<(&str, &[u8])> = vec![
            (
                "hooks/register.js",
                include_bytes!("../../hooks/register.js"),
            ),
            ("hooks/hooks.json", include_bytes!("../../hooks/hooks.json")),
            ("dist/core.js", include_bytes!("../../dist/core.js")),
            (
                ".claude-plugin/plugin.json",
                include_bytes!("../../.claude-plugin/plugin.json"),
            ),
            ("README.md", include_bytes!("../../README.md")),
            ("LICENSE", include_bytes!("../../LICENSE")),
        ];
        let files = package
            .map(|p| {
                p.files
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_bytes()))
                    .collect()
            })
            .unwrap_or(files);
        // Refuse downgrades and unknown version formats instead of overwriting a newer source.
        if let Ok(bytes) = read_limited(&root.join(".claude-plugin/plugin.json")) {
            let v: Value =
                serde_json::from_slice(&bytes).map_err(|_| "INVALID_INSTALLED_MANIFEST")?;
            let installed = version(v["version"].as_str().ok_or("INVALID_INSTALLED_MANIFEST")?)?;
            if installed > version(target_version)? {
                return Err("BUNDLED_VERSION_OLDER");
            }
        }
        let marketplace = json!({"name":"agent-safeguard-local","owner":{"name":"Local Agent Safeguard"},"plugins":[{"name":"agent-safeguard","source":"./plugins/agent-safeguard","description":"Local tool result privacy guard"}]}).to_string();
        let mut changes: Vec<(PathBuf, Vec<u8>)> = files
            .into_iter()
            .map(|(name, bytes)| (root.join(name), bytes.to_vec()))
            .collect();
        changes.push((
            self.market.join(".claude-plugin/marketplace.json"),
            marketplace.into_bytes(),
        ));
        if !self.rules_path().exists() {
            changes.push((self.rules_path(), fresh_rules().into_bytes()));
        }
        fs::create_dir_all(self.status_dir()).map_err(|_| "WRITE_FAILED")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.status_dir(), fs::Permissions::from_mode(0o700))
                .map_err(|_| "WRITE_FAILED")?;
        }
        changes.push((
            root.join("local/desktop.json"),
            json!({"schema":1,"rulesPath":self.rules_path(),"statusDir":self.status_dir()})
                .to_string()
                .into_bytes(),
        ));
        let backups: Vec<_> = changes
            .iter()
            .map(|(p, _)| {
                if p.exists() {
                    read_limited(p).map(Some)
                } else {
                    Ok(None)
                }
            })
            .collect::<Result<_>>()?;
        let result = (|| {
            for (path, bytes) in &changes {
                atomic_write(path, bytes)?;
            }
            let market = self.market.to_str().ok_or("INVALID_PATH")?;
            let args = if action == "install" {
                vec![
                    "plugin",
                    "install",
                    "agent-safeguard",
                    "--marketplace",
                    market,
                    "--scope",
                    "user",
                    "--json",
                ]
            } else {
                vec!["plugin", "update", PLUGIN_ID, "--scope", "user", "--json"]
            };
            run(&claude, &args, None, Duration::from_secs(60))?;
            self.verify_action(action, target_version)
        })();
        if result.is_err() {
            for ((path, _), backup) in changes.iter().zip(backups) {
                match backup {
                    Some(bytes) => {
                        atomic_write(path, &bytes)?;
                    }
                    None => {
                        let _ = fs::remove_file(path);
                    }
                }
            }
        }
        result
    }
    fn verify_action(&self, action: &str, target_version: &str) -> Result<()> {
        let h = self
            .detect()
            .into_iter()
            .next()
            .ok_or("INSTALL_VERIFICATION_FAILED")?;
        if !h.query_ok {
            return Err("INSTALL_VERIFICATION_FAILED");
        }
        let ok = match action {
            "uninstall" => !h.installed,
            "disable" => h.installed && h.enabled == Some(false),
            "enable" => h.installed && h.enabled == Some(true),
            _ => h.installed && h.plugin == target_version,
        };
        if ok {
            Ok(())
        } else {
            Err("INSTALL_VERIFICATION_FAILED")
        }
    }
}
pub fn version(s: &str) -> Result<Vec<u64>> {
    let v: Vec<u64> = s
        .split('.')
        .map(|v| v.parse().map_err(|_| "INVALID_INSTALLED_MANIFEST"))
        .collect::<Result<_>>()?;
    if v.len() == 3 {
        Ok(v)
    } else {
        Err("INVALID_INSTALLED_MANIFEST")
    }
}
pub fn safe_label(s: &str) -> String {
    if s.len() <= 80
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    {
        s.into()
    } else {
        "已隐藏".into()
    }
}

pub fn fresh_rules() -> String {
    let mut v: Value = serde_json::from_str(DEFAULT_RULES).expect("bundled rules");
    v["rules"].as_array_mut().unwrap().retain(|r| {
        !r["id"]
            .as_str()
            .unwrap_or("")
            .starts_with("personal.synthetic-")
    });
    serde_json::to_string_pretty(&v).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn demo_never_changes_harness() {
        let m = Manager::new(true, Some(PathBuf::from("unused"))).unwrap();
        assert!(m.plugin_action("install").is_err());
    }
    #[test]
    fn child_error_does_not_expose_output() {
        let node = executable("node").unwrap();
        assert_eq!(
            run(
                &node,
                &["-e", "console.error('SYNTHETIC_SECRET');process.exit(1)"],
                None,
                Duration::from_secs(2)
            ),
            Err("COMMAND_FAILED")
        );
        assert_eq!(
            run(
                &node,
                &["-e", "setTimeout(()=>{},10000)"],
                None,
                Duration::from_millis(100)
            ),
            Err("COMMAND_TIMEOUT")
        );
    }
}
