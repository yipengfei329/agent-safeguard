//! Execute the original bundled engine in a bounded, offline JS runtime.
use crate::backend::Result;
use rquickjs::{Context, Runtime};
use serde::Deserialize;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SandboxResult {
    pub kind: String,
    pub rule: Option<String>,
    pub reason: Option<String>,
    pub count: usize,
    pub line: Option<u64>,
    pub field: Option<String>,
}

fn execute_with_arg(text: &str, arg: Option<&str>, expression: &str) -> Result<String> {
    if text.len() > 1_048_576 || arg.is_some_and(|s| s.len() > 65_536) {
        return Err("INPUT_LIMIT");
    }
    let rt = Runtime::new().map_err(|_| "VALIDATOR_UNAVAILABLE")?;
    rt.set_memory_limit(64 * 1024 * 1024);
    rt.set_max_stack_size(512 * 1024);
    let started = Instant::now();
    rt.set_interrupt_handler(Some(Box::new(move || {
        started.elapsed() > Duration::from_secs(2)
    })));
    let context = Context::full(&rt).map_err(|_| "VALIDATOR_UNAVAILABLE")?;
    context
        .with(|ctx| {
            // WHATWG UTF-8 encoding, including replacement of unpaired surrogates.
            ctx.eval::<(), _>(
                r#"globalThis.TextEncoder=class { encode(value=''){const out=[];for(const c of String(value)){let n=c.codePointAt(0);if(n>=0xD800&&n<=0xDFFF)n=0xFFFD;if(n<128)out.push(n);else if(n<2048)out.push(192|(n>>6),128|(n&63));else if(n<65536)out.push(224|(n>>12),128|((n>>6)&63),128|(n&63));else out.push(240|(n>>18),128|((n>>12)&63),128|((n>>6)&63),128|(n&63));}return new Uint8Array(out)}};"#,
            )?;
            ctx.eval::<(), _>(include_str!("../../dist/core.desktop.js"))?;
            ctx.globals().set("configText", text)?;
            if let Some(s) = arg {
                ctx.globals().set("sampleText", s)?;
            }
            ctx.eval::<String, _>(expression)
        })
        .map_err(|_| "RULE_CONFIG_REJECTED")
}

pub fn validate(text: &str) -> Result<()> {
    execute_with_arg(text, None, "SafeguardCore.compile(JSON.parse(configText)); 'ok'").map(|_| ())
}

pub fn migrate(text: &str, redact: bool) -> Result<String> {
    execute_with_arg(
        text,
        None,
        if redact {
            "const c=JSON.parse(configText); SafeguardCore.compile(c); const ids=c.rules.filter(r=>r.action==='block'&&r.detector.kind==='ip'&&r.sources.includes('tool.result')).map(r=>r.id); const m=SafeguardCore.migrateRules(c,{redactIds:ids}); SafeguardCore.compile(m); JSON.stringify(m)"
        } else {
            "const c=JSON.parse(configText); SafeguardCore.compile(c); const m=SafeguardCore.migrateRules(c); SafeguardCore.compile(m); JSON.stringify(m)"
        },
    )
}

pub fn preview(config_text: &str, sample: &str) -> Result<SandboxResult> {
    let raw = execute_with_arg(
        config_text,
        Some(sample),
        r#"(() => {
            const e = SafeguardCore.compile(JSON.parse(configText), {diagnostics: true});
            const d = e.inspectAndTransform({result: {stdout: sampleText, stderr: '', interrupted: false}}, 'tool.result', 'Bash');
            if (d.kind === 'pass') return JSON.stringify({kind: 'pass', rule: null, reason: null, count: 0, line: null, field: null});
            if (d.kind === 'redacted') return JSON.stringify({kind: 'redacted', rule: 'network.address', reason: null, count: d.count || 1, line: null, field: null});
            const direct = e.scan(sampleText, 'tool.result', 'Bash');
            const loc = d.location || direct.location || null;
            return JSON.stringify({
                kind: 'withhold',
                rule: d.rule || direct.rule || null,
                reason: d.reason || direct.reason || null,
                count: 0,
                line: loc ? loc.line : null,
                field: loc ? loc.field : null
            });
        })()"#,
    )?;
    serde_json::from_str(&raw).map_err(|_| "RULE_CONFIG_REJECTED")
}
