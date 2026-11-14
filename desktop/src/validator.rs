//! Execute the original bundled engine in a bounded, offline JS runtime.
use crate::backend::Result;
use rquickjs::{Context, Runtime};
use std::time::{Duration, Instant};
pub fn validate(text: &str) -> Result<()> {
    if text.len() > 1_048_576 {
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
    context.with(|ctx| {
        // WHATWG UTF-8 encoding, including replacement of unpaired surrogates.
        ctx.eval::<(), _>(r#"globalThis.TextEncoder=class { encode(value=''){const out=[];for(const c of String(value)){let n=c.codePointAt(0);if(n>=0xD800&&n<=0xDFFF)n=0xFFFD;if(n<128)out.push(n);else if(n<2048)out.push(192|(n>>6),128|(n&63));else if(n<65536)out.push(224|(n>>12),128|((n>>6)&63),128|(n&63));else out.push(240|(n>>18),128|((n>>12)&63),128|((n>>6)&63),128|(n&63));}return new Uint8Array(out)}};"#)?;
        ctx.eval::<(), _>(include_str!("../../dist/core.desktop.js"))?;
        ctx.globals().set("configText", text)?;
        ctx.eval::<(), _>("SafeguardCore.compile(JSON.parse(configText)); void 0")
    }).map_err(|_| "RULE_CONFIG_REJECTED")
}
