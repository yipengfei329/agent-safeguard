mod appearance;
mod backend;
mod rules;
mod sessions;
mod updates;
mod validator;

use appearance::Tone;
use backend::{Harness, Manager};
use gpui_kit::component::{
    button::*,
    input::{Input, InputState},
    switch::Switch,
    *,
};
use gpui_kit::prelude::FluentBuilder;
use gpui_kit::*;
use rules::Document;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Rules,
    Tools,
}

enum Outcome {
    UpdateChecked(updates::Release),
    Initial(Vec<Harness>, backend::Result<Document>),
    Detected(Vec<Harness>),
    Installed(Vec<Harness>),
    Saved(Document, &'static str),
    Undone(Document),
    SyncedIdentity(Document, usize),
    Program(Manager, Vec<Harness>),
}

struct Desktop {
    manager: Manager,
    scroll: ScrollHandle,
    release: Option<updates::Release>,
    page: Page,
    harnesses: Vec<Harness>,
    busy: bool,
    notice: String,
    saved: Option<Document>,
    draft: Option<Document>,
    feed: sessions::Feed,
    connections_page: usize,
    edit: bool,
    edit_index: Option<usize>,
    edit_is_domain: bool,
    edit_case_sensitive: bool,
    name: Entity<InputState>,
    value: Entity<InputState>,
    sandbox: Entity<InputState>,
    sandbox_running: bool,
    sandbox_result: Option<backend::Result<validator::SandboxResult>>,
    reveal: bool,
    confirm_uninstall: bool,
    close_pending: bool,
    about: bool,
    started: Instant,
    measure: bool,
    measured: bool,
}

impl Desktop {
    fn new(
        manager: Manager,
        started: Instant,
        measure: bool,
        page: Page,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let name = cx.new(|cx| InputState::new(window, cx).placeholder("备注名称（例如：公司内网域名）"));
        let value = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("需要保护的敏感词或域名后缀")
                .masked(true)
        });
        let sandbox = cx.new(|cx| {
            InputState::new(window, cx).placeholder("输入任意文本，离线测试当前规则是否放行、脱敏或拦截…")
        });
        let mut s = Self {
            manager,
            scroll: ScrollHandle::new(),
            release: None,
            page,
            harnesses: vec![],
            busy: false,
            notice: "本地离线防护运行中".into(),
            saved: None,
            draft: None,
            feed: Default::default(),
            connections_page: 0,
            edit: false,
            edit_index: None,
            edit_is_domain: false,
            edit_case_sensitive: true,
            name,
            value,
            sandbox,
            sandbox_running: false,
            sandbox_result: None,
            reveal: false,
            confirm_uninstall: false,
            close_pending: false,
            about: false,
            started,
            measure,
            measured: false,
        };
        s.work(window, cx, |m| {
            Ok(Outcome::Initial(m.detect(), m.document()))
        });
        let manager = s.manager.clone();
        cx.spawn_in(window, async move |view, cx| {
            let mut observer = sessions::Observer::default();
            loop {
                let m = manager.clone();
                let (next_observer, reports) = cx
                    .background_executor()
                    .spawn(async move {
                        let reports = observer.poll(&m);
                        (observer, reports)
                    })
                    .await;
                observer = next_observer;
                if view
                    .update_in(cx, |s, _, cx| {
                        s.feed.update(reports.0);
                        s.feed.update_history(reports.1);
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
                cx.background_executor().timer(Duration::from_secs(2)).await;
            }
        })
        .detach();
        let weak = cx.entity().downgrade();
        window.on_window_should_close(cx, move |_, cx| {
            weak.update(cx, |s, cx| {
                if s.busy || s.dirty() || s.edit {
                    s.scroll.set_offset(point(px(0.), px(0.)));
                    s.close_pending = true;
                    cx.notify();
                    false
                } else {
                    true
                }
            })
            .unwrap_or(true)
        });
        s
    }

    fn dirty(&self) -> bool {
        self.draft
            .as_ref()
            .zip(self.saved.as_ref())
            .is_some_and(|(d, s)| d.dirty(s))
    }

    fn work(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
        job: impl FnOnce(Manager) -> backend::Result<Outcome> + Send + 'static,
    ) {
        if self.busy {
            return;
        }
        self.busy = true;
        cx.notify();
        let m = self.manager.clone();
        let task = cx.background_executor().spawn(async move { job(m) });
        cx.spawn_in(window, async move |view, cx| {
            let result = task.await;
            let _ = view.update_in(cx, |s, w, cx| {
                s.busy = false;
                let mut rerun_sandbox = false;
                match result {
                    Ok(Outcome::UpdateChecked(r)) => {
                        let current = s
                            .harnesses
                            .first()
                            .filter(|h| h.installed)
                            .map(|h| h.plugin.as_str())
                            .unwrap_or(backend::BUNDLED_VERSION);
                        if backend::version(&r.version).ok() > backend::version(current).ok() {
                            s.notice = format!("发现新版本插件 v{}", r.version);
                            s.release = Some(r);
                        } else {
                            s.release = None;
                            s.notice = "当前已是最新版本".into();
                        }
                    }
                    Ok(Outcome::Initial(h, d)) => {
                        s.harnesses = h;
                        match d {
                            Ok(d) => {
                                s.saved = Some(d.clone());
                                s.draft = Some(d);
                                s.notice = "本地离线防护运行中".into();
                            }
                            Err(e) => s.notice = error_text(e).into(),
                        }
                    }
                    Ok(Outcome::Detected(h)) => {
                        s.harnesses = h;
                        s.notice = "环境状态已更新".into();
                    }
                    Ok(Outcome::Installed(h)) => {
                        s.harnesses = h;
                        s.notice = "插件状态已更新（新会话生效）".into();
                    }
                    Ok(Outcome::Saved(d, msg)) => {
                        s.saved = Some(d.clone());
                        s.draft = Some(d);
                        s.notice = msg.into();
                        rerun_sandbox = true;
                    }
                    Ok(Outcome::Undone(d)) => {
                        s.saved = Some(d.clone());
                        s.draft = Some(d);
                        s.notice = "已撤销上次规则修改".into();
                        rerun_sandbox = true;
                    }
                    Ok(Outcome::SyncedIdentity(d, count)) => {
                        s.saved = Some(d.clone());
                        s.draft = Some(d);
                        s.notice = format!("已同步 {count} 项本机设备标识（新会话生效）");
                        rerun_sandbox = true;
                    }
                    Ok(Outcome::Program(m, h)) => {
                        s.manager = m;
                        s.harnesses = h;
                        s.notice = "已更新 Claude Code 程序路径".into();
                    }
                    Err(e) => {
                        if e == "RULES_CHANGED_EXTERNALLY" {
                            if let Ok(fresh) = s.manager.document() {
                                s.saved = Some(fresh.clone());
                                s.draft = Some(fresh);
                            }
                        } else if let Some(saved) = s.saved.clone() {
                            if !s.edit {
                                s.draft = Some(saved);
                            }
                        }
                        s.notice = error_text(e).into();
                    }
                }
                if rerun_sandbox && !s.sandbox.read(cx).value().trim().is_empty() {
                    s.run_sandbox(w, cx);
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn commit_next(
        &mut self,
        next: Document,
        msg: &'static str,
        w: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.draft = Some(next.clone());
        self.work(w, cx, move |m| {
            m.commit_document(next).map(|d| Outcome::Saved(d, msg))
        });
    }

    fn sync_identity(&mut self, w: &mut Window, cx: &mut Context<Self>) {
        let Some(base_doc) = self.draft.clone() else {
            return;
        };
        let demo = self.manager.demo;
        self.work(w, cx, move |m| {
            let values = backend::collect_local_identity(demo);
            let mut doc = base_doc;
            let count = doc.sync_local_identity(values)?;
            let saved = m.commit_document(doc)?;
            Ok(Outcome::SyncedIdentity(saved, count))
        });
    }

    fn run_sandbox(&mut self, w: &mut Window, cx: &mut Context<Self>) {
        let sample = self.sandbox.read(cx).value().to_string();
        if sample.trim().is_empty() {
            self.sandbox_result = None;
            self.sandbox_running = false;
            cx.notify();
            return;
        }
        let Some(doc) = self.draft.clone() else {
            return;
        };
        let m = self.manager.clone();
        self.sandbox_running = true;
        cx.notify();
        let task = cx
            .background_executor()
            .spawn(async move { m.preview_sample(&doc, &sample) });
        cx.spawn_in(w, async move |view, cx| {
            let res = task.await;
            let _ = view.update_in(cx, |s, _, cx| {
                s.sandbox_running = false;
                s.sandbox_result = Some(res);
                cx.notify();
            });
        })
        .detach();
    }

    fn action(&mut self, action: &'static str, w: &mut Window, cx: &mut Context<Self>) {
        self.confirm_uninstall = false;
        self.work(w, cx, move |m| {
            m.plugin_action(action)?;
            Ok(Outcome::Installed(m.detect()))
        });
    }

    fn select_program(&mut self, w: &mut Window, cx: &mut Context<Self>) {
        let picker = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("选择 Claude Code 可执行程序".into()),
        });
        cx.spawn_in(w, async move |view, cx| {
            if let Ok(Ok(Some(paths))) = picker.await {
                if let Some(path) = paths.into_iter().next() {
                    let _ = view.update_in(cx, |s, w, cx| {
                        s.work(w, cx, move |mut m| {
                            m.select_program(path)?;
                            let h = m.detect();
                            Ok(Outcome::Program(m, h))
                        })
                    });
                }
            }
        })
        .detach();
    }

    fn panel(
        &self,
        title: impl Into<SharedString>,
        detail: impl Into<SharedString>,
        cx: &App,
    ) -> Div {
        div()
            .v_flex()
            .gap_2()
            .p_4()
            .rounded_lg()
            .bg(rgb(appearance::SURFACE))
            .border_1()
            .border_color(cx.theme().border)
            .child(
                div()
                    .text_size(px(14.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(appearance::TEXT))
                    .child(title.into()),
            )
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(cx.theme().muted_foreground)
                    .child(detail.into()),
            )
    }

    fn anomaly_category(&self, row: &sessions::Session) -> String {
        if row
            .reason_code()
            .is_some_and(|r| r.starts_with("redaction."))
        {
            return "中国境内公网 IP".into();
        }
        let id = row.matched_rule().unwrap_or("");
        match id {
            "personal.local-identity" => "本机设备标识".into(),
            "network.address" | "network.address.output" => "中国境内公网 IP".into(),
            "identity.device" => "设备硬件标识".into(),
            "identity.environment" => "主机名字段".into(),
            "security.credentials" => "密钥与凭据".into(),
            "inspection.failed" => {
                if row.reason_code() == Some("inspection.timeout") {
                    "大输出扫描超时".into()
                } else {
                    "扫描内容超限".into()
                }
            }
            "initialization.failed" => "插件初始化异常".into(),
            "context.hook.failed" => "上下文检查异常".into(),
            "tool.hook.failed" | "prompt.hook.failed" => "插件运行异常".into(),
            "custom.rule" | "" => "自定义敏感词".into(),
            _ => self
                .saved
                .as_ref()
                .filter(|d| d.version() == row.rule_version)
                .or(self.draft.as_ref())
                .and_then(|d| {
                    d.rows()
                        .iter()
                        .find(|r| r["id"].as_str() == Some(id))
                        .map(|r| d.name(r))
                })
                .unwrap_or_else(|| "自定义敏感词".into()),
        }
    }

    fn anomaly_headline(&self, row: &sessions::Session) -> String {
        let cat = self.anomaly_category(row);
        let eff = row.effect_summary();
        match row.concise_reason() {
            Some(reason) if !cat.contains("超时") => format!("{cat} · {eff}（{reason}）"),
            _ => format!("{cat} · {eff}"),
        }
    }

    fn rule_id_label(&self, id: &str) -> String {
        match id {
            "personal.local-identity" => "本机设备标识".into(),
            "network.address" | "network.address.output" => "中国境内公网 IP".into(),
            "identity.device" => "设备硬件标识".into(),
            "identity.environment" => "主机名字段".into(),
            "security.credentials" => "密钥与凭据".into(),
            _ => self
                .draft
                .as_ref()
                .and_then(|d| {
                    d.rows()
                        .iter()
                        .find(|r| r["id"].as_str() == Some(id))
                        .map(|r| d.name(r))
                })
                .unwrap_or_else(|| "自定义规则".into()),
        }
    }

    fn overview(&self, cx: &mut Context<Self>) -> AnyElement {
        let now = sessions::now();
        let dashboard = sessions::Dashboard::new(self.feed.sessions.values(), now);

        // Deduplicate live sessions by host_session_id, keeping paused/attention state first.
        let mut live_by_host = BTreeMap::<String, &sessions::Session>::new();
        for row in &dashboard.current {
            let key = row
                .identity
                .host_session_id
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| row.session.clone());
            let replace = live_by_host.get(&key).is_none_or(|old| {
                let old_prio = old.connection_state(now) == sessions::ConnectionState::Attention;
                let new_prio = row.connection_state(now) == sessions::ConnectionState::Attention;
                (new_prio && !old_prio) || (new_prio == old_prio && old.updated_at < row.updated_at)
            });
            if replace {
                live_by_host.insert(key, *row);
            }
        }
        let mut live_sessions: Vec<_> = live_by_host.into_values().collect();
        live_sessions.sort_by_key(|s| {
            let prio = if s.connection_state(now) == sessions::ConnectionState::Attention {
                0u8
            } else {
                1u8
            };
            (prio, std::cmp::Reverse(s.updated_at))
        });

        let mut project_counts = BTreeMap::<&str, usize>::new();
        for row in &live_sessions {
            if row.identity.raw_title().is_none() {
                if let Some(proj) = row.identity.raw_project_name() {
                    *project_counts.entry(proj).or_insert(0) += 1;
                }
            }
        }

        let mut logs: BTreeMap<_, _> = self
            .feed
            .interceptions
            .iter()
            .map(|(id, r)| (id.clone(), r))
            .collect();
        for row in self.feed.sessions.values().filter(|r| r.has_interception()) {
            logs.entry(row.history_key()).or_insert(row);
        }
        let mut logs: Vec<_> = logs.into_values().collect();
        logs.sort_by_key(|r| (std::cmp::Reverse(r.effective_time()), &r.session));

        let mut content = div().v_flex().gap_5();

        // Only surface an install banner when protection is NOT currently installed & enabled!
        if let Some(h) = self.harnesses.first() {
            if !h.found {
                content = content.child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .p_4()
                        .rounded_lg()
                        .bg(rgb(appearance::SURFACE))
                        .border_1()
                        .border_color(rgb(appearance::BORDER_WARN))
                        .child(
                            div()
                                .text_size(px(13.))
                                .text_color(rgb(appearance::TEXT))
                                .child("未检测到 Claude Code 可执行程序，请手动指定位置。"),
                        )
                        .child(
                            Button::new("hero-choose-program")
                                .primary()
                                .small()
                                .label("选择程序")
                                .disabled(self.busy)
                                .on_click(cx.listener(|s, _, w, cx| s.select_program(w, cx))),
                        ),
                );
            } else if !h.installed || h.enabled == Some(false) {
                let (msg, btn_label, cmd) = if !h.installed {
                    ("本地隐私防护插件尚未安装", "一键安装并启用", "install")
                } else {
                    ("本地隐私防护当前已暂停（插件已禁用）", "立即启用", "enable")
                };
                content = content.child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .p_4()
                        .rounded_lg()
                        .bg(rgb(appearance::SURFACE))
                        .border_1()
                        .border_color(rgb(appearance::BORDER_WARN))
                        .child(
                            div()
                                .text_size(px(13.))
                                .text_color(rgb(appearance::TEXT))
                                .child(msg),
                        )
                        .child(
                            Button::new("hero-enable")
                                .primary()
                                .small()
                                .label(btn_label)
                                .disabled(self.busy || self.manager.demo || !h.query_ok)
                                .on_click(cx.listener(move |s, _, w, cx| s.action(cmd, w, cx))),
                        ),
                );
            }
        }

        // Core Question 1: Active Protected Sessions
        let mut active_section = div().v_flex().gap_2().child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .text_size(px(15.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(appearance::TEXT))
                        .child("正在保护的会话"),
                )
                .child(appearance::pill(
                    live_sessions.len().to_string(),
                    if live_sessions.is_empty() {
                        Tone::Neutral
                    } else {
                        Tone::Success
                    },
                )),
        );

        if live_sessions.is_empty() {
            active_section = active_section.child(
                div()
                    .p_4()
                    .rounded_lg()
                    .bg(rgb(appearance::SURFACE_SUBTLE))
                    .border_1()
                    .border_color(rgb(appearance::BORDER))
                    .text_size(px(12.))
                    .text_color(rgb(appearance::MUTED))
                    .child("当前没有正在运行的 Claude Code 会话。启动新会话后会自动显示在这里。"),
            );
        } else {
            for row in live_sessions {
                let state = row.connection_state(now);
                let is_attention = state == sessions::ConnectionState::Attention;
                let dup = row
                    .identity
                    .raw_project_name()
                    .is_some_and(|p| project_counts.get(p).copied().unwrap_or(0) > 1);
                let headline = row.identity.active_headline(dup);
                let subline = row.identity.active_subline();
                let replacements = row.recovery.as_ref().map(|r| r.replacements).unwrap_or(0);
                let status_pill = match state {
                    sessions::ConnectionState::Attention => appearance::pill("已暂停", Tone::Warning),
                    sessions::ConnectionState::Connected => appearance::pill("保护中", Tone::Success),
                    _ => appearance::pill("接入中", Tone::Neutral),
                };

                let mut card = div()
                    .v_flex()
                    .p_4()
                    .rounded_lg()
                    .bg(rgb(appearance::SURFACE))
                    .border_1()
                    .border_color(rgb(if is_attention {
                        appearance::BORDER_WARN
                    } else {
                        appearance::BORDER
                    }))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .v_flex()
                                    .gap_1()
                                    .child(
                                        div()
                                            .text_size(px(14.))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(rgb(appearance::TEXT))
                                            .child(headline),
                                    )
                                    .when(!subline.is_empty(), |this| {
                                        this.child(
                                            div()
                                                .text_size(px(12.))
                                                .text_color(rgb(appearance::MUTED))
                                                .child(subline),
                                        )
                                    }),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .when(!is_attention && replacements > 0, |this| {
                                        this.child(appearance::pill(
                                            format!("已脱敏 {replacements} 处 IP"),
                                            Tone::Accent,
                                        ))
                                    })
                                    .child(status_pill),
                            ),
                    );

                if is_attention {
                    card = card.child(
                        div()
                            .mt_2()
                            .pt_2()
                            .border_t_1()
                            .border_color(rgb(appearance::BORDER))
                            .text_size(px(12.))
                            .text_color(rgb(0xF5C97B))
                            .child(format!(
                                "{}  ·  {}",
                                self.anomaly_headline(row),
                                row.concise_next_step(now)
                            )),
                    );
                }
                active_section = active_section.child(card);
            }
        }
        content = content.child(active_section);

        // Core Question 2: Past Anomalies
        const PAGE_SIZE: usize = 12;
        let pages = logs.len().div_ceil(PAGE_SIZE).max(1);
        let page = self.connections_page.min(pages - 1);

        let mut history_section = div().v_flex().gap_2().mt_2().child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .text_size(px(15.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(appearance::TEXT))
                        .child("过去的异常"),
                )
                .child(appearance::pill(logs.len().to_string(), Tone::Neutral)),
        );

        if logs.is_empty() {
            history_section = history_section.child(
                div()
                    .p_4()
                    .rounded_lg()
                    .bg(rgb(appearance::SURFACE_SUBTLE))
                    .border_1()
                    .border_color(rgb(appearance::BORDER))
                    .text_size(px(12.))
                    .text_color(rgb(appearance::MUTED))
                    .child("暂无异常记录。发生密钥、设备标识拦截或扫描异常时会显示在这里。"),
            );
        } else {
            let mut list_box = div()
                .v_flex()
                .rounded_lg()
                .bg(rgb(appearance::SURFACE))
                .border_1()
                .border_color(rgb(appearance::BORDER))
                .px_4();

            let slice: Vec<_> = logs.iter().skip(page * PAGE_SIZE).take(PAGE_SIZE).collect();
            let slice_len = slice.len();
            for (idx, row) in slice.into_iter().enumerate() {
                let when = sessions::format_timestamp(row.effective_time(), now);
                let headline = self.anomaly_headline(row);
                let context = row.anomaly_context();

                list_box = list_box.child(
                    div()
                        .flex()
                        .items_start()
                        .gap_4()
                        .py_3()
                        .when(idx + 1 < slice_len, |this| {
                            this.border_b_1().border_color(rgb(appearance::BORDER))
                        })
                        .child(
                            div()
                                .w(px(100.))
                                .flex_shrink_0()
                                .pt(px(2.))
                                .text_size(px(12.))
                                .text_color(rgb(appearance::MUTED))
                                .child(when),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .v_flex()
                                .gap_1()
                                .child(
                                    div()
                                        .text_size(px(13.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(appearance::TEXT))
                                        .child(headline),
                                )
                                .when(!context.is_empty(), |this| {
                                    this.child(
                                        div()
                                            .text_size(px(12.))
                                            .text_color(rgb(appearance::MUTED))
                                            .child(context),
                                    )
                                }),
                        ),
                );
            }
            history_section = history_section.child(list_box);

            if pages > 1 {
                history_section = history_section.child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .pt_1()
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(rgb(appearance::MUTED))
                                .child(format!("第 {} / {} 页", page + 1, pages)),
                        )
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .child(
                                    Button::new("log-prev")
                                        .small()
                                        .label("上一页")
                                        .disabled(page == 0)
                                        .on_click(cx.listener(move |s, _, _, cx| {
                                            s.connections_page = page.saturating_sub(1);
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new("log-next")
                                        .small()
                                        .label("下一页")
                                        .disabled(page + 1 == pages)
                                        .on_click(cx.listener(move |s, _, _, cx| {
                                            s.connections_page = page + 1;
                                            cx.notify();
                                        })),
                                ),
                        ),
                );
            }
        }
        content = content.child(history_section);
        content.into_any_element()
    }

    fn begin_edit(
        &mut self,
        index: Option<usize>,
        default_domain: bool,
        w: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.edit = true;
        self.edit_index = index;
        let (name, value, is_domain, case_sensitive) = if let Some(i) = index {
            let d = self.draft.as_ref().unwrap();
            let r = &d.rows()[i];
            if rules::simple_domain(r) {
                (
                    d.name(r),
                    r["detector"]["suffixes"][0]
                        .as_str()
                        .unwrap_or("")
                        .to_owned(),
                    true,
                    false,
                )
            } else {
                (
                    d.name(r),
                    r["detector"]["values"][0].as_str().unwrap_or("").to_owned(),
                    false,
                    r["detector"]["caseSensitive"].as_bool().unwrap_or(true),
                )
            }
        } else {
            (String::new(), String::new(), default_domain, true)
        };
        self.edit_is_domain = is_domain;
        self.edit_case_sensitive = case_sensitive;
        self.reveal = is_domain;
        self.name.update(cx, |s, cx| {
            s.set_value(name, w, cx);
            s.focus(w, cx);
        });
        self.value.update(cx, |s, cx| {
            s.set_value(value, w, cx);
            s.set_masked(!is_domain, w, cx);
        });
        cx.notify();
    }

    fn clear_editor(&mut self, w: &mut Window, cx: &mut Context<Self>) {
        self.edit = false;
        self.edit_index = None;
        self.name.update(cx, |s, cx| s.set_value("", w, cx));
        self.value.update(cx, |s, cx| s.set_value("", w, cx));
    }

    fn rules_page(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut content = div().v_flex().gap_4();

        let Some(d) = &self.draft else {
            return content
                .child(self.panel(
                    "规则文件无法加载",
                    "当前规则 JSON 校验未通过，原文件已保留。",
                    cx,
                ))
                .into_any_element();
        };

        if !d.is_modern() {
            content = content.child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .p_4()
                    .rounded_lg()
                    .bg(rgb(appearance::SURFACE))
                    .border_1()
                    .border_color(rgb(appearance::ACCENT))
                    .child(
                        div()
                            .text_size(px(13.))
                            .text_color(rgb(appearance::TEXT))
                            .child("当前规则为旧版格式，升级后支持暂停后发新消息恢复与公网 IP 自动脱敏。"),
                    )
                    .child(
                        Button::new("upgrade-modern-redact")
                            .primary()
                            .small()
                            .label("一键升级")
                            .disabled(self.busy || self.edit)
                            .on_click(cx.listener(|s, _, w, cx| {
                                s.work(w, cx, |m| {
                                    let upgraded = m.recovery_draft(true)?;
                                    m.commit_document(upgraded)
                                        .map(|doc| Outcome::Saved(doc, "已升级规则格式（新会话生效）"))
                                });
                            })),
                    ),
            );
        }

        // Built-in & Local Identity Section
        let local_status = d.local_identity_status();
        content = content.child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .text_size(px(15.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(appearance::TEXT))
                        .child("防护策略"),
                )
                .child(
                    Button::new("undo-rules")
                        .ghost()
                        .icon(IconName::Undo2)
                        .small()
                        .label("撤销上次修改")
                        .disabled(self.busy || self.edit)
                        .on_click(cx.listener(|s, _, w, cx| {
                            let baseline = s.draft.as_ref().unwrap().baseline.clone();
                            s.work(w, cx, move |m| {
                                let prev = m.previous_document(baseline)?;
                                m.commit_document(prev).map(Outcome::Undone)
                            });
                        })),
                ),
        );

        let mut policy_list = div()
            .v_flex()
            .rounded_lg()
            .bg(rgb(appearance::SURFACE))
            .border_1()
            .border_color(rgb(appearance::BORDER))
            .px_4();

        // Row 1: Local Machine Identity
        policy_list = policy_list.child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap_3()
                .py_3()
                .border_b_1()
                .border_color(rgb(appearance::BORDER))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .v_flex()
                        .gap_1()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(
                                    div()
                                        .text_size(px(14.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(appearance::TEXT))
                                        .child("本机设备与主机名"),
                                )
                                .child(match local_status {
                                    Some((_, count, true)) => {
                                        appearance::pill(format!("已同步 {count} 项"), Tone::Success)
                                    }
                                    Some((_, count, false)) => {
                                        appearance::pill(format!("已关闭 ({count} 项)"), Tone::Neutral)
                                    }
                                    None => appearance::pill("未同步", Tone::Warning),
                                }),
                        )
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(rgb(appearance::MUTED))
                                .child("精确保护本机真实计算机名、序列号与网卡 MAC，不误报代码变量"),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            Button::new("sync-local-identity")
                                .small()
                                .when(local_status.is_none(), |b| b.primary())
                                .when(local_status.is_some(), |b| b.ghost())
                                .label(if local_status.is_some() {
                                    "重新同步"
                                } else {
                                    "同步本机标识"
                                })
                                .disabled(self.busy || self.edit)
                                .on_click(cx.listener(|s, _, w, cx| s.sync_identity(w, cx))),
                        )
                        .when_some(local_status, |this, (idx, _, enabled)| {
                            this.child(
                                Switch::new("toggle-local-identity")
                                    .accessibility_label("本机设备与主机名")
                                    .small()
                                    .checked(enabled)
                                    .disabled(self.busy || self.edit)
                                    .on_change(cx.listener(move |s, _, w, cx| {
                                        if let Some(mut next) = s.draft.clone() {
                                            next.toggle(idx);
                                            s.commit_next(next, "已保存（新会话生效）", w, cx);
                                        }
                                    })),
                            )
                        }),
                ),
        );

        let ip_redacted = d.ip_output_redacted();
        let mut rendered_ip = false;
        let builtin_rows: Vec<_> = d
            .rows()
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                let id = r["id"].as_str().unwrap_or("");
                if id == "identity.environment"
                    && r["enabled"] == false
                    && local_status.is_some_and(|(_, c, en)| c > 0 && en)
                {
                    return false;
                }
                rules::builtin(r).is_some()
            })
            .collect();

        for (pos, (i, r)) in builtin_rows.iter().copied().enumerate() {
            let (title, desc) = rules::builtin(r).unwrap();
            let id = r["id"].as_str().unwrap_or("");
            let is_last = pos + 1 == builtin_rows.len();

            if id == "network.address" || id == "network.address.output" {
                if rendered_ip {
                    continue;
                }
                rendered_ip = true;
                let enabled = r["enabled"] == true;
                let ip_title = if r["detector"]["mode"] == "country" {
                    "中国境内公网 IP"
                } else {
                    "公网 IP 地址"
                };
                policy_list = policy_list.child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .py_3()
                        .border_b_1()
                        .border_color(rgb(appearance::BORDER))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .v_flex()
                                .gap_1()
                                .child(
                                    div()
                                        .text_size(px(14.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(appearance::TEXT))
                                        .child(ip_title),
                                )
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .text_color(rgb(appearance::MUTED))
                                        .child("内网与海外地址自动放行；日志输出默认替换为 [IP_1] 代号"),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .when_some(ip_redacted, |this, is_redacted| {
                                    this.child(
                                        Button::new("ip-mode-toggle")
                                            .ghost()
                                            .small()
                                            .label(if is_redacted {
                                                "当前：自动脱敏"
                                            } else {
                                                "当前：直接拦截"
                                            })
                                            .disabled(self.busy || self.edit || !enabled)
                                            .on_click(cx.listener(move |s, _, w, cx| {
                                                if let Some(mut next) = s.draft.clone() {
                                                    if next
                                                        .set_ip_output_redaction(!is_redacted)
                                                        .is_ok()
                                                    {
                                                        s.commit_next(
                                                            next,
                                                            "已切换公网 IP 处理方式（新会话生效）",
                                                            w,
                                                            cx,
                                                        );
                                                    }
                                                }
                                            })),
                                    )
                                })
                                .child(
                                    Switch::new(("rule-toggle", i))
                                        .accessibility_label(ip_title)
                                        .small()
                                        .checked(enabled)
                                        .disabled(self.busy || self.edit)
                                        .on_change(cx.listener(move |s, _, w, cx| {
                                            if let Some(mut next) = s.draft.clone() {
                                                next.toggle(i);
                                                s.commit_next(next, "已保存（新会话生效）", w, cx);
                                            }
                                        })),
                                ),
                        ),
                );
                continue;
            }

            policy_list = policy_list.child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .py_3()
                    .when(!is_last, |this| {
                        this.border_b_1().border_color(rgb(appearance::BORDER))
                    })
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .v_flex()
                            .gap_1()
                            .child(
                                div()
                                    .text_size(px(14.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(appearance::TEXT))
                                    .child(title),
                            )
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .text_color(rgb(appearance::MUTED))
                                    .child(desc),
                            ),
                    )
                    .child(
                        Switch::new(("rule-toggle", i))
                            .accessibility_label(title)
                            .small()
                            .checked(r["enabled"] == true)
                            .disabled(self.busy || self.edit)
                            .on_change(cx.listener(move |s, _, w, cx| {
                                if let Some(mut next) = s.draft.clone() {
                                    next.toggle(i);
                                    s.commit_next(next, "已保存（新会话生效）", w, cx);
                                }
                            })),
                    ),
            );
        }
        content = content.child(policy_list);

        // Custom Terms & Domains Section
        let custom_rows: Vec<_> = d
            .rows()
            .iter()
            .enumerate()
            .filter(|(_, r)| rules::custom_editable(r))
            .collect();

        content = content.child(
            div()
                .flex()
                .justify_between()
                .items_center()
                .mt_2()
                .child(
                    div()
                        .text_size(px(15.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(appearance::TEXT))
                        .child("自定义词条与域名"),
                )
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(
                            Button::new("add-exact-rule")
                                .small()
                                .icon(IconName::Plus)
                                .label("添加敏感词")
                                .disabled(self.busy || self.edit)
                                .on_click(
                                    cx.listener(|s, _, w, cx| s.begin_edit(None, false, w, cx)),
                                ),
                        )
                        .child(
                            Button::new("add-domain-rule")
                                .small()
                                .icon(IconName::Plus)
                                .label("添加域名后缀")
                                .disabled(self.busy || self.edit)
                                .on_click(
                                    cx.listener(|s, _, w, cx| s.begin_edit(None, true, w, cx)),
                                ),
                        ),
                ),
        );

        if self.edit {
            content = content.child(
                div()
                    .v_flex()
                    .gap_3()
                    .p_4()
                    .rounded_lg()
                    .bg(rgb(appearance::SURFACE))
                    .border_1()
                    .border_color(rgb(appearance::ACCENT))
                    .child(Input::new(&self.name))
                    .child(Input::new(&self.value))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_3()
                                    .when(!self.edit_is_domain, |this| {
                                        this.child(
                                            Button::new("reveal-value")
                                                .ghost()
                                                .small()
                                                .label(if self.reveal {
                                                    "隐藏内容"
                                                } else {
                                                    "显示内容"
                                                })
                                                .on_click(cx.listener(|s, _, w, cx| {
                                                    s.reveal = !s.reveal;
                                                    s.value.update(cx, |v, cx| {
                                                        v.set_masked(!s.reveal, w, cx)
                                                    });
                                                    cx.notify();
                                                })),
                                        )
                                        .child(
                                            div()
                                                .flex()
                                                .items_center()
                                                .gap_2()
                                                .child(
                                                    div()
                                                        .text_size(px(12.))
                                                        .text_color(rgb(appearance::MUTED))
                                                        .child("区分大小写"),
                                                )
                                                .child(
                                                    Switch::new("edit-case-sensitive")
                                                        .small()
                                                        .checked(self.edit_case_sensitive)
                                                        .on_change(cx.listener(|s, _, _, cx| {
                                                            s.edit_case_sensitive =
                                                                !s.edit_case_sensitive;
                                                            cx.notify();
                                                        })),
                                                ),
                                        )
                                    })
                                    .when(self.edit_is_domain, |this| {
                                        this.child(
                                            div()
                                                .text_size(px(12.))
                                                .text_color(rgb(appearance::MUTED))
                                                .child("如 corp.example.com（自动匹配所有子域名）"),
                                        )
                                    }),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap_2()
                                    .child(
                                        Button::new("cancel-editor")
                                            .ghost()
                                            .small()
                                            .label("取消")
                                            .on_click(cx.listener(|s, _, w, cx| {
                                                s.clear_editor(w, cx);
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        Button::new("save-custom-rule")
                                            .primary()
                                            .small()
                                            .label("保存")
                                            .disabled(self.busy)
                                            .on_click(cx.listener(|s, _, w, cx| {
                                                let Some(mut next) = s.draft.clone() else {
                                                    return;
                                                };
                                                let res = next.edit_custom(
                                                    s.edit_index,
                                                    s.name.read(cx).value().to_string(),
                                                    s.value.read(cx).value().to_string(),
                                                    s.edit_is_domain,
                                                    s.edit_case_sensitive,
                                                );
                                                match res {
                                                    Ok(()) => {
                                                        s.clear_editor(w, cx);
                                                        s.commit_next(
                                                            next,
                                                            "已保存自定义规则（新会话生效）",
                                                            w,
                                                            cx,
                                                        );
                                                    }
                                                    Err(e) => {
                                                        s.notice = error_text(e).into();
                                                        cx.notify();
                                                    }
                                                }
                                            })),
                                    ),
                            ),
                    ),
            );
        }

        if custom_rows.is_empty() && !self.edit {
            content = content.child(
                div()
                    .p_4()
                    .rounded_lg()
                    .bg(rgb(appearance::SURFACE_SUBTLE))
                    .border_1()
                    .border_color(rgb(appearance::BORDER))
                    .text_size(px(12.))
                    .text_color(rgb(appearance::MUTED))
                    .child("暂未添加自定义词条或内网域名。"),
            );
        } else if !custom_rows.is_empty() {
            let mut custom_box = div()
                .v_flex()
                .rounded_lg()
                .bg(rgb(appearance::SURFACE))
                .border_1()
                .border_color(rgb(appearance::BORDER))
                .px_4();
            let count = custom_rows.len();
            for (pos, (i, r)) in custom_rows.into_iter().enumerate() {
                let is_domain = rules::simple_domain(r);
                let rule_title = d.name(r);
                let subtitle = if is_domain {
                    format!(
                        "域名后缀：{}",
                        r["detector"]["suffixes"][0].as_str().unwrap_or("")
                    )
                } else {
                    "精确敏感词（内容已隐藏）".into()
                };
                custom_box = custom_box.child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .py_3()
                        .when(pos + 1 < count, |this| {
                            this.border_b_1().border_color(rgb(appearance::BORDER))
                        })
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .v_flex()
                                .gap_1()
                                .child(
                                    div()
                                        .text_size(px(14.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(appearance::TEXT))
                                        .child(rule_title.clone()),
                                )
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .text_color(rgb(appearance::MUTED))
                                        .child(subtitle),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(
                                    Switch::new(("custom-toggle", i))
                                        .accessibility_label(rule_title)
                                        .small()
                                        .checked(r["enabled"] == true)
                                        .disabled(self.busy || self.edit)
                                        .on_change(cx.listener(move |s, _, w, cx| {
                                            if let Some(mut next) = s.draft.clone() {
                                                next.toggle(i);
                                                s.commit_next(next, "已保存（新会话生效）", w, cx);
                                            }
                                        })),
                                )
                                .child(
                                    Button::new(("rule-edit", i))
                                        .ghost()
                                        .small()
                                        .label("编辑")
                                        .disabled(self.busy || self.edit)
                                        .on_click(cx.listener(move |s, _, w, cx| {
                                            s.begin_edit(Some(i), is_domain, w, cx)
                                        })),
                                )
                                .child(
                                    Button::new(("rule-delete", i))
                                        .ghost()
                                        .small()
                                        .label("删除")
                                        .disabled(self.busy || self.edit)
                                        .on_click(cx.listener(move |s, _, w, cx| {
                                            if let Some(mut next) = s.draft.clone() {
                                                next.remove(i);
                                                s.commit_next(
                                                    next,
                                                    "已删除（可点击右上角撤销）",
                                                    w,
                                                    cx,
                                                );
                                            }
                                        })),
                                ),
                        ),
                );
            }
            content = content.child(custom_box);
        }

        // Compact bottom rule tester (1 clean row)
        let has_input = !self.sandbox.read(cx).value().trim().is_empty();
        let mut tester = div()
            .v_flex()
            .gap_2()
            .mt_2()
            .p_4()
            .rounded_lg()
            .bg(rgb(appearance::SURFACE))
            .border_1()
            .border_color(rgb(appearance::BORDER))
            .child(
                div()
                    .text_size(px(13.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(appearance::TEXT))
                    .child("测试规则"),
            )
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(div().flex_1().child(Input::new(&self.sandbox)))
                    .child(
                        Button::new("sandbox-run")
                            .primary()
                            .small()
                            .label(if self.sandbox_running { "检测中" } else { "检测" })
                            .disabled(self.sandbox_running)
                            .on_click(cx.listener(|s, _, w, cx| s.run_sandbox(w, cx))),
                    )
                    .when(has_input, |this| {
                        this.child(
                            Button::new("sandbox-clear")
                                .ghost()
                                .small()
                                .label("清空")
                                .on_click(cx.listener(|s, _, w, cx| {
                                    s.sandbox.update(cx, |input, cx| input.set_value("", w, cx));
                                    s.sandbox_result = None;
                                    cx.notify();
                                })),
                        )
                    }),
            );

        if let Some(result) = &self.sandbox_result {
            let row = match result {
                Ok(res) if res.kind == "pass" => div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .pt_1()
                    .child(appearance::pill("放行", Tone::Success))
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(rgb(appearance::MUTED))
                            .child("未命中任何规则"),
                    ),
                Ok(res) if res.kind == "redacted" => div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .pt_1()
                    .child(appearance::pill("自动脱敏", Tone::Accent))
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(rgb(appearance::MUTED))
                            .child(format!("将替换 {} 处公网 IP 为 [IP_1] 后放行", res.count)),
                    ),
                Ok(res) => {
                    let rule_name = self.rule_id_label(res.rule.as_deref().unwrap_or(""));
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .pt_1()
                        .child(appearance::pill("拦截", Tone::Warning))
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(rgb(appearance::TEXT))
                                .child(format!("命中「{rule_name}」，结果将扣留在本机")),
                        )
                }
                Err(code) => div()
                    .pt_1()
                    .text_size(px(12.))
                    .text_color(rgb(0xF5C97B))
                    .child(error_text(code)),
            };
            tester = tester.child(row);
        }

        content.child(tester).into_any_element()
    }

    fn tools(&self, cx: &mut Context<Self>) -> AnyElement {
        let h = self.harnesses.first();
        let installed = h.is_some_and(|h| h.installed);
        let enabled = h.and_then(|h| h.enabled);
        let disabled = self.busy || self.manager.demo || !h.is_some_and(|h| h.found && h.query_ok);
        let needs_upgrade = installed
            && h.is_some_and(|h| {
                backend::version(&h.plugin).ok() < backend::version(backend::BUNDLED_VERSION).ok()
            });

        let (state_label, state_tone) = if !installed {
            ("未安装", Tone::Warning)
        } else if enabled == Some(false) {
            ("已禁用", Tone::Warning)
        } else if needs_upgrade {
            ("可升级", Tone::Accent)
        } else {
            ("已启用", Tone::Success)
        };

        let primary_button = if !installed {
            Button::new("install-primary")
                .primary()
                .small()
                .label("安装并启用")
                .disabled(disabled)
                .on_click(cx.listener(|s, _, w, cx| s.action("install", w, cx)))
        } else if enabled == Some(false) {
            Button::new("install-primary")
                .primary()
                .small()
                .label("启用插件")
                .disabled(disabled)
                .on_click(cx.listener(|s, _, w, cx| s.action("enable", w, cx)))
        } else if needs_upgrade {
            Button::new("install-primary")
                .primary()
                .small()
                .label(format!("升级至 v{}", backend::BUNDLED_VERSION))
                .disabled(disabled)
                .on_click(cx.listener(|s, _, w, cx| s.action("update", w, cx)))
        } else {
            Button::new("install-primary")
                .small()
                .label("重新同步")
                .disabled(disabled)
                .on_click(cx.listener(|s, _, w, cx| s.action("update", w, cx)))
        };

        let mut content = div()
            .v_flex()
            .gap_4()
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(
                        Button::new("choose-program")
                            .ghost()
                            .small()
                            .icon(IconName::FolderOpen)
                            .label("选择程序")
                            .disabled(self.busy)
                            .on_click(cx.listener(|s, _, w, cx| s.select_program(w, cx))),
                    )
                    .child(
                        Button::new("detect")
                            .small()
                            .icon(IconName::RefreshCw)
                            .label("重新检测")
                            .disabled(self.busy)
                            .on_click(cx.listener(|s, _, w, cx| {
                                s.work(w, cx, |m| Ok(Outcome::Detected(m.detect())))
                            })),
                    ),
            )
            .child(
                div()
                    .v_flex()
                    .rounded_lg()
                    .border_1()
                    .border_color(rgb(appearance::BORDER))
                    .bg(rgb(appearance::SURFACE))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .p_5()
                            .child(
                                div()
                                    .v_flex()
                                    .gap_1()
                                    .child(
                                        div()
                                            .text_size(px(15.))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(rgb(appearance::TEXT))
                                            .child("Claude Code"),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(12.))
                                            .text_color(rgb(appearance::MUTED))
                                            .child(format!(
                                                "CLI {}  ·  插件 v{}",
                                                h.map(|h| h.version.as_str()).unwrap_or("检测中"),
                                                h.map(|h| h.plugin.as_str()).unwrap_or("检测中")
                                            )),
                                    ),
                            )
                            .child(appearance::pill(state_label, state_tone)),
                    )
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .items_center()
                            .px_5()
                            .py_3()
                            .border_t_1()
                            .border_color(rgb(appearance::BORDER))
                            .child(primary_button)
                            .child(
                                div()
                                    .flex()
                                    .gap_2()
                                    .child(
                                        Button::new("check-update")
                                            .ghost()
                                            .small()
                                            .label("检查更新")
                                            .disabled(self.busy || self.manager.demo)
                                            .on_click(cx.listener(|s, _, w, cx| {
                                                s.work(w, cx, |_| {
                                                    updates::Release::check()
                                                        .map(Outcome::UpdateChecked)
                                                })
                                            })),
                                    )
                                    .child(
                                        Button::new("disable")
                                            .ghost()
                                            .small()
                                            .label("禁用")
                                            .disabled(
                                                disabled || !installed || enabled == Some(false),
                                            )
                                            .on_click(cx.listener(|s, _, w, cx| {
                                                s.action("disable", w, cx)
                                            })),
                                    )
                                    .child(
                                        Button::new("uninstall")
                                            .ghost()
                                            .small()
                                            .label("卸载…")
                                            .disabled(disabled || !installed)
                                            .on_click(cx.listener(|s, _, _, cx| {
                                                s.confirm_uninstall = true;
                                                cx.notify();
                                            })),
                                    ),
                            ),
                    ),
            );

        if let Some(release) = self.release.clone() {
            content = content.child(
                Button::new("apply-update")
                    .primary()
                    .small()
                    .label(format!("下载并更新至 v{}", release.version))
                    .disabled(disabled || !installed)
                    .on_click(cx.listener(move |s, _, w, cx| {
                        let release = release.clone();
                        s.work(w, cx, move |m| {
                            m.update_release(release)?;
                            Ok(Outcome::Installed(m.detect()))
                        });
                    })),
            );
        }
        if self.confirm_uninstall {
            content = content.child(
                self.panel("确认卸载插件？", "移除插件注册，保留本地规则文件。", cx)
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                Button::new("confirm-uninstall")
                                    .small()
                                    .label("确认卸载")
                                    .on_click(
                                        cx.listener(|s, _, w, cx| s.action("uninstall", w, cx)),
                                    ),
                            )
                            .child(
                                Button::new("cancel-uninstall")
                                    .ghost()
                                    .small()
                                    .label("取消")
                                    .on_click(cx.listener(|s, _, _, cx| {
                                        s.confirm_uninstall = false;
                                        cx.notify();
                                    })),
                            ),
                    ),
            );
        }
        content.into_any_element()
    }
}

fn error_text(code: &str) -> &'static str {
    match code {
        "UPDATE_FEED_UNAVAILABLE" => "无法连接发布源，请检查网络后重试",
        "UPDATE_PACKAGE_UNPUBLISHED" => "发布源暂无可用插件包",
        "UPDATE_DIGEST_REQUIRED"
        | "UPDATE_DIGEST_MISMATCH"
        | "UPDATE_PACKAGE_INVALID"
        | "UPDATE_FEED_INVALID" => "更新包完整性校验未通过",
        "DESKTOP_UPDATE_REQUIRED" => "请先升级桌面应用版本",
        "UPDATE_DOWNLOAD_FAILED" => "更新包下载未完成",
        "RULES_CHANGED_EXTERNALLY" => "规则文件在外部被修改，正在重新同步",
        "RECOVERY_REQUIRES_UPDATE" => "请先在「安装」页更新插件版本",
        "ANOTHER_OPERATION_RUNNING" => "另一个操作正在进行中",
        "RULE_FIELDS_REQUIRED" => "请填写备注名称和需要保护的内容",
        "INVALID_DOMAIN" => "请输入有效的域名后缀，例如 corp.example.com",
        "LOCAL_IDENTITY_EMPTY" => "未读取到本机设备标识",
        "RULE_CONFIG_REJECTED" => "规则校验未通过，原配置未变",
        "NO_PREVIOUS_RULES" | "FILE_UNAVAILABLE" => "没有可撤销的上一版修改",
        "CLAUDE_NOT_FOUND" | "COMMAND_UNAVAILABLE" => "未找到 Claude Code 可执行程序",
        "NOT_CLAUDE_CODE" => "所选文件不是 Claude Code 程序",
        "INSTALL_VERIFICATION_FAILED" => "未能确认插件状态，请点击重新检测",
        "BUNDLED_VERSION_OLDER" => "已安装版本高于内置版本，未降级",
        "COMMAND_TIMEOUT" => "命令执行超时，请重试",
        "COMMAND_FAILED" => "命令执行失败，已回滚源文件",
        "DEMO_MODE_NO_HARNESS_CHANGES" => "演示模式不修改本机插件",
        _ => "操作未完成，请重试",
    }
}

impl Render for Desktop {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.measure && !self.measured {
            self.measured = true;
            let t = self.started;
            window.on_next_frame(move |_, _| {
                println!(
                    "{{\"first_frame_callback_ms\":{:.3}}}",
                    t.elapsed().as_secs_f64() * 1000.
                )
            });
        }
        let mut nav = div().v_flex().gap_1();
        for (id, label, page, glyph) in [
            (
                "nav-overview",
                "概览",
                Page::Overview,
                IconName::LayoutDashboard,
            ),
            ("nav-rules", "规则", Page::Rules, IconName::Settings2),
            ("nav-tools", "安装", Page::Tools, IconName::SquareTerminal),
        ] {
            let active = self.page == page;
            nav = nav.child(
                appearance::navigation_item(id, label, glyph, active).on_click(cx.listener(
                    move |s, _, _, cx| {
                        s.page = page;
                        if page == Page::Overview {
                            s.connections_page = 0;
                        }
                        s.scroll.set_offset(point(px(0.), px(0.)));
                        cx.notify();
                    },
                )),
            );
        }
        let (title, glyph) = match self.page {
            Page::Overview => ("概览", IconName::LayoutDashboard),
            Page::Rules => ("规则", IconName::Settings2),
            Page::Tools => ("安装", IconName::SquareTerminal),
        };
        let page = match self.page {
            Page::Overview => self.overview(cx),
            Page::Rules => self.rules_page(cx),
            Page::Tools => self.tools(cx),
        };
        let mut body = div().v_flex().gap_4();
        if self.about {
            body = body.child(
                self.panel(
                    "Agent Safeguard",
                    format!(
                        "桌面 v{} · 插件 v{} · 所有检测均在本机离线完成，关闭窗口不影响后台防护。",
                        env!("CARGO_PKG_VERSION"),
                        backend::BUNDLED_VERSION
                    ),
                    cx,
                )
                .child(
                    Button::new("open-data")
                        .small()
                        .label("打开本地数据目录")
                        .on_click(cx.listener(|s, _, _, cx| cx.reveal_path(&s.manager.base()))),
                ),
            );
        }
        if self.close_pending {
            body = body.child(
                self.panel("正在编辑的内容尚未保存", "可返回保存，或放弃输入并关闭窗口。", cx)
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                Button::new("cancel-close")
                                    .small()
                                    .label("返回")
                                    .on_click(cx.listener(|s, _, _, cx| {
                                        s.close_pending = false;
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new("discard-close")
                                    .ghost()
                                    .small()
                                    .label("放弃并关闭")
                                    .disabled(self.busy)
                                    .on_click(cx.listener(|_, _, w, _| w.remove_window())),
                            ),
                    ),
            );
        }
        body = body.child(page);
        let content = div()
            .w_full()
            .flex_1()
            .min_h_0()
            .flex()
            .bg(rgb(appearance::BG))
            .text_color(rgb(appearance::TEXT))
            .text_size(px(13.))
            .child(
                div()
                    .w(px(208.))
                    .h_full()
                    .flex_shrink_0()
                    .v_flex()
                    .px_3()
                    .pt_2()
                    .pb_5()
                    .bg(rgb(appearance::SIDEBAR))
                    .border_r_1()
                    .border_color(rgb(appearance::BORDER))
                    .child(nav)
                    .child(div().flex_1())
                    .child(
                        div()
                            .border_t_1()
                            .border_color(rgb(appearance::BORDER))
                            .pt_3()
                            .child(
                                appearance::navigation_item(
                                    "about",
                                    "关于",
                                    IconName::Info,
                                    self.about,
                                )
                                .on_click(cx.listener(
                                    |s, _, _, cx| {
                                        s.about = !s.about;
                                        s.scroll.set_offset(point(px(0.), px(0.)));
                                        cx.notify();
                                    },
                                )),
                            ),
                    ),
            )
            .child(
                div()
                    .v_flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .child(
                        div()
                            .id("page-scroll")
                            .track_scroll(&self.scroll)
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scroll()
                            .px_8()
                            .pt_6()
                            .pb_6()
                            .child(body),
                    )
                    .child(
                        div()
                            .id("operation-notice")
                            .role(Role::Status)
                            .aria_label(self.notice.clone())
                            .flex()
                            .items_center()
                            .gap_2()
                            .px_8()
                            .py_2()
                            .border_t_1()
                            .border_color(rgb(appearance::BORDER))
                            .text_size(px(11.))
                            .text_color(rgb(appearance::MUTED))
                            .child(appearance::icon(if self.busy {
                                IconName::LoaderCircle
                            } else {
                                IconName::Info
                            }))
                            .child(self.notice.clone()),
                    ),
            );
        div()
            .size_full()
            .v_flex()
            .bg(rgb(appearance::BG))
            .text_color(rgb(appearance::TEXT))
            .child(
                TitleBar::new()
                    .h(px(48.))
                    .pl_0()
                    .border_b_0()
                    .bg(rgb(appearance::BG))
                    .on_close_window(cx.listener(|s, _, w, cx| {
                        if s.busy || s.dirty() || s.edit {
                            s.close_pending = true;
                            s.scroll.set_offset(point(px(0.), px(0.)));
                            cx.notify();
                        } else {
                            w.remove_window();
                        }
                    }))
                    .child(
                        div()
                            .size_full()
                            .flex()
                            .child(
                                div()
                                    .w(px(208.))
                                    .h_full()
                                    .flex_shrink_0()
                                    .bg(rgb(appearance::SIDEBAR))
                                    .border_r_1()
                                    .border_color(rgb(appearance::BORDER)),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .h_full()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .px_8()
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_2()
                                            .child(appearance::icon(glyph))
                                            .child(
                                                div()
                                                    .text_size(px(14.))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(rgb(appearance::TEXT))
                                                    .child(title),
                                            ),
                                    )
                                    .when(self.manager.demo, |this| {
                                        this.child(appearance::pill("演示环境", Tone::Accent))
                                    }),
                            ),
                    ),
            )
            .child(content)
    }
}

fn option(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() {
    let started = Instant::now();
    let args: Vec<String> = std::env::args().collect();
    let demo = args.iter().any(|a| a == "--demo");
    let temp = demo.then(|| tempfile::tempdir().expect("temporary directory unavailable"));
    let base = temp
        .as_ref()
        .map(|d| d.path().to_owned())
        .or_else(|| option(&args, "--data-dir").map(PathBuf::from));
    let manager = Manager::new(demo, base).expect("local data directory unavailable");
    if let Some(action) = option(&args, "--backend") {
        let result: backend::Result<serde_json::Value> = match action.as_str() {
            "install" | "update" | "enable" | "disable" | "uninstall" => manager
                .plugin_action(&action)
                .map(|_| serde_json::json!(null)),
            "sessions" => manager
                .sessions()
                .map(|(s, invalid)| serde_json::json!({"sessions":s,"invalid":invalid})),
            "apply" => {
                use std::io::Read;
                let mut text = String::new();
                let _ = std::io::stdin().take(1_048_577).read_to_string(&mut text);
                (move || {
                    let mut d = manager.document()?;
                    if option(&args, "--expected-digest").as_deref() != Some(d.baseline.as_str()) {
                        return Err("RULES_CHANGED_EXTERNALLY");
                    }
                    d.config = serde_json::from_str(&text).map_err(|_| "RULE_CONFIG_REJECTED")?;
                    manager
                        .commit_document(d)
                        .map(|d| serde_json::json!({"version":d.version()}))
                })()
            }
            "validate" => {
                use std::io::Read;
                let mut text = String::new();
                let _ = std::io::stdin().take(1_048_577).read_to_string(&mut text);
                manager.validate(&text).map(|_| serde_json::json!(null))
            }
            _ => Err("UNSUPPORTED_ACTION"),
        };
        println!(
            "{}",
            match &result {
                Ok(value) => serde_json::json!({"ok":true,"data":value}),
                Err(code) => serde_json::json!({"ok":false,"code":code}),
            }
        );
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }
    let page = match option(&args, "--page").as_deref() {
        Some("install" | "tools") => Page::Tools,
        Some("rules") => Page::Rules,
        _ => Page::Overview,
    };
    let measure = args.iter().any(|a| a == "--measure");
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(move |cx| {
            gpui_kit::init(cx);
            appearance::init(cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::centered(size(px(960.), px(720.)), cx)),
                window_min_size: Some(size(px(760.), px(560.))),
                titlebar: Some(TitlebarOptions {
                    title: Some("Agent Safeguard".into()),
                    traffic_light_position: Some(point(px(16.), px(17.))),
                    ..TitleBar::title_bar_options()
                }),
                ..TitleBar::window_options()
            };
            gpui_kit::open_window(options, cx, |w, cx| {
                cx.new(|cx| Desktop::new(manager, started, measure, page, w, cx))
            })
            .expect("window initialization failed");
            cx.on_window_closed(|cx, _| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();
            cx.activate(true);
        });
    drop(temp);
}
