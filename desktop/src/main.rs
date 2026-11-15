mod appearance;
mod backend;
mod rules;
mod sessions;
mod updates;
mod validator;
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
    path::PathBuf,
    time::{Duration, Instant},
};
#[derive(Clone, Copy, PartialEq)]
enum Page {
    Overview,
    Tools,
    Rules,
}
enum Outcome {
    UpdateChecked(updates::Release),
    Initial(Vec<Harness>, backend::Result<Document>),
    Detected(Vec<Harness>),
    Installed(Vec<Harness>),
    Loaded(Document),
    Saved(Document),
    Previous(Document),
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
    detail: Option<sessions::Session>,
    connections_page: usize,
    edit: bool,
    edit_index: Option<usize>,
    name: Entity<InputState>,
    value: Entity<InputState>,
    reveal: bool,
    confirm_uninstall: bool,
    confirm_discard: bool,
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
        let name = cx.new(|cx| InputState::new(window, cx).placeholder("规则名称"));
        let value = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("需要匹配的精确文本")
                .masked(true)
        });
        let mut s = Self {
            manager,
            scroll: ScrollHandle::new(),
            release: None,
            page,
            harnesses: vec![],
            busy: false,
            notice: "正在读取本机配置…".into(),
            saved: None,
            draft: None,
            feed: Default::default(),
            detail: None,
            connections_page: 0,
            edit: false,
            edit_index: None,
            name,
            value,
            reveal: false,
            confirm_uninstall: false,
            confirm_discard: false,
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
                cx.background_executor().timer(Duration::from_secs(2)).await;
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
            }
        })
        .detach();
        let weak = cx.entity().downgrade();
        window.on_window_should_close(cx, move |_, cx| {
            weak.update(cx, |s, cx| {
                if s.busy || s.dirty() || s.edit {
                    s.scroll.set_offset(point(px(0.), px(0.)));
                    s.close_pending = true;
                    s.notice = "还有操作或未保存更改，请保存、放弃或取消关闭。".into();
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
        self.notice = "正在本机处理…".into();
        cx.notify();
        let m = self.manager.clone();
        let task = cx.background_executor().spawn(async move { job(m) });
        cx.spawn_in(window, async move |view, cx| {
            let result = task.await;
            let _ = view.update_in(cx, |s, _, cx| {
                s.busy = false;
                match result {
                    Ok(Outcome::UpdateChecked(r)) => {
                        let current = s
                            .harnesses
                            .first()
                            .filter(|h| h.installed)
                            .map(|h| h.plugin.as_str())
                            .unwrap_or(backend::BUNDLED_VERSION);
                        if backend::version(&r.version).ok() > backend::version(current).ok() {
                            s.notice = format!("发现插件 {}，可以下载并更新。", r.version);
                            s.release = Some(r);
                        } else {
                            s.release = None;
                            s.notice = "发布源没有比当前版本更新的插件。".into();
                        }
                    }
                    Ok(Outcome::Initial(h, d)) => {
                        s.harnesses = h;
                        match d {
                            Ok(d) => {
                                s.saved = Some(d.clone());
                                s.draft = Some(d);
                                s.notice = "本机配置已读取。安装状态与会话接入分别显示。".into();
                            }
                            Err(e) => s.notice = error_text(e).into(),
                        }
                    }
                    Ok(Outcome::Detected(h)) => {
                        s.harnesses = h;
                        s.notice = "环境检测完成。".into();
                    }
                    Ok(Outcome::Installed(h)) => {
                        s.harnesses = h;
                        s.notice =
                            "已重新核对安装配置。安装、启用或更新后，请新建 Claude 会话确认接入。"
                                .into();
                    }
                    Ok(Outcome::Loaded(d)) => {
                        s.saved = Some(d.clone());
                        s.draft = Some(d);
                        s.edit = false;
                        s.notice = "已读取规则。".into();
                    }
                    Ok(Outcome::Saved(d)) => {
                        s.saved = Some(d.clone());
                        s.draft = Some(d);
                        s.notice = "已保存，新会话生效。已有会话仍使用各自加载的版本。".into();
                    }
                    Ok(Outcome::Previous(d)) => {
                        s.draft = Some(d);
                        s.notice = "上一版已载入草稿，请检查变化后保存。".into();
                    }
                    Ok(Outcome::Program(m, h)) => {
                        s.manager = m;
                        s.harnesses = h;
                        s.notice = "已保存程序位置并重新检测。".into();
                    }
                    Err(e) => s.notice = error_text(e).into(),
                }
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
                    .child(title.into()),
            )
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(cx.theme().muted_foreground)
                    .child(detail.into()),
            )
    }
    fn rule_label(&self, row: &sessions::Session) -> String {
        let id = row.matched_rule().unwrap_or("");
        match id {
            "network.address" => "IP 地址规则".into(),
            "identity.device" => "设备标识规则".into(),
            "identity.environment" => "主机名规则".into(),
            "security.credentials" => "凭据规则".into(),
            "inspection.failed" => "检查未完成（非规则命中）".into(),
            "initialization.failed" => "初始化失败（非规则命中）".into(),
            "tool.hook.failed" | "prompt.hook.failed" | "context.hook.failed" => {
                "插件处理异常（非规则命中）".into()
            }
            "custom.rule" | "" => "自定义规则（旧版未记录具体规则）".into(),
            _ => self
                .saved
                .as_ref()
                .filter(|d| d.version() == row.rule_version)
                .and_then(|d| {
                    d.rows()
                        .iter()
                        .find(|r| r["id"].as_str() == Some(id))
                        .map(|r| d.name(r))
                })
                .unwrap_or_else(|| format!("规则 {id}")),
        }
    }
    fn overview(&self, cx: &mut Context<Self>) -> AnyElement {
        let now = sessions::now();
        let dashboard = sessions::Dashboard::new(self.feed.sessions.values(), now);
        let mut protected = std::collections::BTreeMap::<String, &sessions::Session>::new();
        for row in dashboard
            .current
            .iter()
            .filter(|r| r.connection_state(now) == sessions::ConnectionState::Connected)
        {
            let key = row
                .identity
                .host_session_id
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| row.session.clone());
            if protected
                .get(&key)
                .is_none_or(|old| old.updated_at < row.updated_at)
            {
                protected.insert(key, *row);
            }
        }
        let mut active: Vec<_> = protected.values().copied().collect();
        active.sort_by_key(|s| (s.identity.project_name(), s.identity.title()));
        let mut logs: std::collections::BTreeMap<_, _> = self
            .feed
            .interceptions
            .iter()
            .map(|(id, r)| (id.clone(), r))
            .collect();
        for row in self.feed.sessions.values().filter(|r| r.has_interception()) {
            logs.entry(row.session.clone()).or_insert(row);
        }
        let mut logs: Vec<_> = logs.into_values().collect();
        logs.sort_by_key(|r| (std::cmp::Reverse(r.blocked_at()), &r.session));
        let mut content = div().v_flex().gap_4();
        if let Some(warning) = self.feed.warning.or(self.feed.history_warning) {
            content = content.child(self.panel("状态读取提醒", warning, cx));
        }
        content = content.child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .text_size(px(16.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("正在保护的会话"),
                )
                .child(appearance::badge(active.len().to_string(), false)),
        );
        if active.is_empty() {
            content = content.child(
                self.panel(
                    "暂无已确认接入防护的会话",
                    "在 Claude Code 中加载插件并新建会话后，项目和会话会自动出现在这里。",
                    cx,
                )
                .child(
                    Button::new("overview-install")
                        .small()
                        .label("打开安装管理")
                        .on_click(cx.listener(|s, _, _, cx| {
                            s.page = Page::Tools;
                            cx.notify();
                        })),
                ),
            );
        }
        for row in active {
            let identity = &row.identity;
            let record = row.clone();
            content = content.child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .p_4()
                    .rounded_md()
                    .bg(rgb(appearance::SURFACE))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .v_flex()
                            .gap_2()
                            .child(
                                div()
                                    .text_size(px(15.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(identity.title().to_owned()),
                            )
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .text_color(rgb(appearance::MUTED))
                                    .child(format!(
                                        "{}  ·  {}{}",
                                        identity.project_name(),
                                        identity.agent_name(),
                                        identity
                                            .model
                                            .as_ref()
                                            .map(|m| format!("  ·  {m}"))
                                            .unwrap_or_default()
                                    )),
                            )
                            .when(row.schema == 1, |this| {
                                this.child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(appearance::MUTED))
                                        .child("旧版插件未提供会话信息，更新后新建会话可显示。"),
                                )
                            }),
                    )
                    .child(appearance::badge("防护已接入", true))
                    .child(
                        Button::new(SharedString::from(format!("protected-{}", row.session)))
                            .ghost()
                            .small()
                            .label("详情")
                            .on_click(cx.listener(move |s, _, _, cx| {
                                s.detail = Some(record.clone());
                                cx.notify();
                            })),
                    ),
            );
        }
        if dashboard.unconfirmed + dashboard.attention + dashboard.initializing > 0 {
            content = content.child(
                div()
                    .text_size(px(11.))
                    .text_color(rgb(appearance::MUTED))
                    .child(format!(
                        "未计入正在保护：{} 个已阻断或异常 · {} 个连接失去更新 · {} 个初始化中。",
                        dashboard.attention, dashboard.unconfirmed, dashboard.initializing
                    )),
            );
        }
        if let Some(d) = &self.detail {
            let d = self.feed.sessions.get(&d.session).unwrap_or(d);
            let identity = d.display_identity(d.has_interception());
            content = content.child(
                self.panel(
                    identity.title().to_owned(),
                    format!(
                        "{} · {}",
                        identity.agent_name(),
                        identity.project.as_deref().unwrap_or("项目未提供")
                    ),
                    cx,
                )
                .child(div().text_size(px(12.)).child(format!(
                    "{} · 插件 {} · 规则版本 {} · {}",
                    d.connection_label(now),
                    d.plugin_version,
                    d.rule_version,
                    sessions::updated_label(d.updated_at, now)
                )))
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(appearance::MUTED))
                        .child(format!(
                            "会话 ID：{}",
                            identity.host_session_id.as_deref().unwrap_or("旧版未提供")
                        )),
                )
                .when(d.has_interception(), |this| {
                    this.child(div().text_size(px(12.)).child(format!(
                        "{} · {}",
                        self.rule_label(d),
                        d.action_label()
                    )))
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(rgb(appearance::MUTED))
                            .child("记录的是插件拒绝或扣留结果；已执行操作不会撤销。"),
                    )
                })
                .child(
                    Button::new("overview-close-detail")
                        .ghost()
                        .small()
                        .label("收起详情")
                        .on_click(cx.listener(|s, _, _, cx| {
                            s.detail = None;
                            cx.notify();
                        })),
                ),
            );
        }
        content = content.child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .mt_4()
                .child(
                    div()
                        .text_size(px(16.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("拦截历史"),
                )
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(appearance::MUTED))
                        .child(format!("{} 条保留记录", logs.len())),
                ),
        );
        if logs.is_empty() {
            content = content.child(
                div()
                    .p_5()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(appearance::BORDER))
                    .text_color(rgb(appearance::MUTED))
                    .child("暂无拦截记录。发生拦截后，会在这里显示所属会话、原因和命中规则。"),
            );
        }
        const PAGE_SIZE: usize = 10;
        let pages = logs.len().div_ceil(PAGE_SIZE).max(1);
        let page = self.connections_page.min(pages - 1);
        for row in logs.iter().skip(page * PAGE_SIZE).take(PAGE_SIZE) {
            let identity = row.display_identity(true);
            let record = (*row).clone();
            let actor = row
                .interception
                .as_ref()
                .and_then(|e| e.agent_type.as_ref())
                .map(|a| format!(" · 子代理 {a}"))
                .unwrap_or_else(|| {
                    if row
                        .interception
                        .as_ref()
                        .is_some_and(|e| e.agent_id.is_some())
                    {
                        " · 子代理".into()
                    } else {
                        String::new()
                    }
                });
            let tool = row
                .interception
                .as_ref()
                .and_then(|e| e.tool.as_ref())
                .map(|t| format!(" · {t}"))
                .unwrap_or_default();
            let when = if row.blocked_at() > 0 {
                sessions::updated_label(row.blocked_at(), now).replace("更新", "拦截")
            } else {
                "旧版记录 · 时间未提供".into()
            };
            content = content.child(
                div()
                    .flex()
                    .items_start()
                    .gap_3()
                    .py_4()
                    .border_b_1()
                    .border_color(rgb(appearance::BORDER))
                    .child(
                        div()
                            .w(px(112.))
                            .flex_shrink_0()
                            .text_size(px(11.))
                            .text_color(rgb(appearance::MUTED))
                            .child(when),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .v_flex()
                            .gap_2()
                            .child(
                                div()
                                    .text_size(px(13.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(identity.title().to_owned()),
                            )
                            .child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(rgb(appearance::MUTED))
                                    .child(format!(
                                        "{} · {}{actor}",
                                        identity.project_name(),
                                        identity.agent_name()
                                    )),
                            )
                            .child(div().text_size(px(12.)).child(format!(
                                "{} · {}{tool}",
                                self.rule_label(row),
                                row.action_label()
                            ))),
                    )
                    .child(
                        Button::new(SharedString::from(format!("intercept-{}", row.session)))
                            .ghost()
                            .small()
                            .label("详情")
                            .on_click(cx.listener(move |s, _, _, cx| {
                                s.detail = Some(record.clone());
                                s.scroll.set_offset(point(px(0.), px(0.)));
                                cx.notify();
                            })),
                    ),
            );
        }
        if pages > 1 {
            content = content.child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(div().text_size(px(11.)).child(format!(
                        "第 {} / {} 页",
                        page + 1,
                        pages
                    )))
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
        content.into_any_element()
    }
    fn tools(&self, cx: &mut Context<Self>) -> AnyElement {
        let h = self.harnesses.first();
        let installed = h.is_some_and(|h| h.installed);
        let enabled = h.and_then(|h| h.enabled);
        let disabled = self.busy || self.manager.demo || !h.is_some_and(|h| h.found && h.query_ok);
        let (label, action) = if !installed {
            ("安装插件", "install")
        } else if enabled == Some(false) {
            ("启用插件", "enable")
        } else {
            ("更新内置插件", "update")
        };
        let state = if !installed {
            "未安装"
        } else if enabled == Some(false) {
            "已禁用"
        } else {
            "已安装"
        };
        let mut content = div()
            .v_flex()
            .gap_5()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(appearance::badge("1 个支持的工具", false))
                    .child(
                        div()
                            .flex()
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
                                    .flex()
                                    .items_center()
                                    .gap_3()
                                    .child(
                                        div()
                                            .size(px(38.))
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .rounded_lg()
                                            .bg(rgb(0x332923))
                                            .child(
                                                Icon::new(IconName::SquareTerminal)
                                                    .size(px(20.))
                                                    .text_color(rgb(0xD5A282)),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .v_flex()
                                            .gap_1()
                                            .child(
                                                div()
                                                    .text_size(px(15.))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .child("Claude Code"),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(12.))
                                                    .text_color(rgb(appearance::MUTED))
                                                    .child(format!(
                                                        "程序版本 {}",
                                                        h.map(|h| h.version.as_str())
                                                            .unwrap_or("检测中")
                                                    )),
                                            ),
                                    ),
                            )
                            .child(appearance::badge(state, enabled == Some(true))),
                    )
                    .child(
                        div()
                            .v_flex()
                            .px_5()
                            .pb_3()
                            .child(self.property(
                                "插件版本",
                                h.map(|h| h.plugin.as_str()).unwrap_or("检测中"),
                            ))
                            .child(self.property("内置版本", backend::BUNDLED_VERSION))
                            .child(self.property("安装范围", "当前用户"))
                            .child(self.property("生效方式", "新会话加载 · 已有会话以概览页为准")),
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
                            .child(
                                Button::new("install-primary")
                                    .primary()
                                    .small()
                                    .icon(IconName::Plus)
                                    .label(label)
                                    .disabled(disabled)
                                    .on_click(
                                        cx.listener(move |s, _, w, cx| s.action(action, w, cx)),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap_1()
                                    .child(
                                        Button::new("disable")
                                            .ghost()
                                            .small()
                                            .label("禁用插件")
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
        if !h.is_some_and(|h| ["2.1.312", "2.1.325"].contains(&h.version.as_str()))
            && !self.manager.demo
        {
            content = content.child(
                div()
                    .flex()
                    .gap_2()
                    .text_size(px(12.))
                    .text_color(rgb(0xC9AC77))
                    .child(appearance::icon(IconName::CircleAlert))
                    .child("此程序版本尚未完成兼容性验收。"),
            );
        }
        content = content.child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .py_3()
                .border_b_1()
                .border_color(rgb(appearance::BORDER))
                .child(
                    div()
                        .flex()
                        .gap_3()
                        .items_center()
                        .child(appearance::icon(IconName::RefreshCw))
                        .child(appearance::section(
                            "插件更新",
                            "手动检查项目发布源，更新时保留本机规则。",
                        )),
                )
                .child(
                    Button::new("check-update")
                        .small()
                        .label("检查更新")
                        .disabled(self.busy || self.manager.demo)
                        .on_click(cx.listener(|s, _, w, cx| {
                            s.work(w, cx, |_| {
                                updates::Release::check().map(Outcome::UpdateChecked)
                            })
                        })),
                ),
        );
        if let Some(release) = self.release.clone() {
            content = content.child(
                Button::new("apply-update")
                    .primary()
                    .small()
                    .label(format!("下载并更新至 {}", release.version))
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
                self.panel(
                    "卸载插件？",
                    "移除当前用户的插件注册，保留规则和其他插件；已有会话不自动退出。",
                    cx,
                )
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(
                            Button::new("confirm-uninstall")
                                .small()
                                .label("卸载并保留规则")
                                .on_click(cx.listener(|s, _, w, cx| s.action("uninstall", w, cx))),
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
        content.child(div().flex().gap_2().text_size(px(11.)).text_color(rgb(appearance::MUTED)).child(appearance::icon(IconName::Info)).child("仅覆盖本机接入的 Claude Code。普通 Chat、Cowork、远程与 WSL 会话不在当前范围。更新安装不等于已有会话已生效。")).into_any_element()
    }
    fn property(&self, key: &str, value: &str) -> Div {
        div()
            .flex()
            .justify_between()
            .gap_4()
            .py_2()
            .text_size(px(12.))
            .child(
                div()
                    .text_color(rgb(appearance::MUTED))
                    .child(key.to_owned()),
            )
            .child(value.to_owned())
    }
    fn begin_edit(&mut self, index: Option<usize>, w: &mut Window, cx: &mut Context<Self>) {
        self.scroll.set_offset(point(px(0.), px(0.)));
        self.edit = true;
        self.edit_index = index;
        self.reveal = false;
        let (name, value) = if let Some(i) = index {
            let d = self.draft.as_ref().unwrap();
            let r = &d.rows()[i];
            (
                d.name(r),
                r["detector"]["values"][0].as_str().unwrap_or("").to_owned(),
            )
        } else {
            (String::new(), String::new())
        };
        self.name.update(cx, |s, cx| {
            s.set_value(name, w, cx);
            s.focus(w, cx);
        });
        self.value.update(cx, |s, cx| {
            s.set_value(value, w, cx);
            s.set_masked(true, w, cx);
        });
        cx.notify();
    }
    fn clear_editor(&mut self, w: &mut Window, cx: &mut Context<Self>) {
        self.edit = false;
        self.name.update(cx, |s, cx| s.set_value("", w, cx));
        self.value.update(cx, |s, cx| s.set_value("", w, cx));
    }
    fn rules_page(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut content = div().v_flex().gap_2().child(
            div()
                .flex()
                .gap_2()
                .child(
                    Button::new("reload-rules")
                        .icon(IconName::RefreshCw)
                        .small()
                        .label("重新读取")
                        .disabled(self.busy)
                        .on_click(cx.listener(|s, _, w, cx| {
                            if s.dirty() || s.edit {
                                s.confirm_discard = true;
                                s.scroll.set_offset(point(px(0.), px(0.)));
                                cx.notify();
                            } else {
                                s.work(w, cx, |m| m.document().map(Outcome::Loaded));
                            }
                        })),
                )
                .child(
                    Button::new("restore-rules")
                        .icon(IconName::Undo2)
                        .small()
                        .label("恢复上一版到草稿")
                        .disabled(self.busy || self.edit || self.draft.is_none())
                        .on_click(cx.listener(|s, _, w, cx| {
                            let baseline = s.draft.as_ref().unwrap().baseline.clone();
                            s.work(w, cx, move |m| {
                                m.previous_document(baseline).map(Outcome::Previous)
                            });
                        })),
                ),
        );
        let Some(d) = &self.draft else {
            return content
                .child(self.panel(
                    "规则尚未读取",
                    "配置无效时保留原文件；请修复后重新读取。",
                    cx,
                ))
                .into_any_element();
        };
        content = content.child(
            div()
                .text_sm()
                .text_color(cx.theme().muted_foreground)
                .child(format!(
                    "已保存 {} · {}",
                    self.saved
                        .as_ref()
                        .map(|d| appearance::revision(&d.version()))
                        .unwrap_or_default(),
                    if self.dirty() {
                        "有未保存更改"
                    } else {
                        "所有更改已保存"
                    }
                )),
        );
        if self.confirm_discard {
            content = content.child(
                self.panel("放弃草稿并重新读取？", "尚未保存的修改将丢失。", cx)
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(Button::new("confirm-discard").label("放弃并读取").on_click(
                                cx.listener(|s, _, w, cx| {
                                    s.confirm_discard = false;
                                    s.clear_editor(w, cx);
                                    s.work(w, cx, |m| m.document().map(Outcome::Loaded));
                                }),
                            ))
                            .child(Button::new("cancel-discard").label("取消").on_click(
                                cx.listener(|s, _, _, cx| {
                                    s.confirm_discard = false;
                                    cx.notify();
                                }),
                            )),
                    ),
            );
        }
        if self.edit {
            content =
                content.child(
                    self.panel(
                        if self.edit_index.is_some() {
                            "编辑规则"
                        } else {
                            "添加规则"
                        },
                        "每条规则一个精确值。名称和敏感文本只保存在本机。",
                        cx,
                    )
                    .child(div().text_sm().child("名称"))
                    .child(Input::new(&self.name))
                    .child(div().text_sm().child("敏感文本"))
                    .child(Input::new(&self.value))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                Button::new("reveal-value")
                                    .label(if self.reveal {
                                        "隐藏文本"
                                    } else {
                                        "显示文本"
                                    })
                                    .on_click(cx.listener(|s, _, w, cx| {
                                        s.reveal = !s.reveal;
                                        s.value.update(cx, |v, cx| v.set_masked(!s.reveal, w, cx));
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new("add-draft")
                                    .primary()
                                    .label("加入草稿")
                                    .on_click(cx.listener(|s, _, w, cx| {
                                        let result = s.draft.as_mut().unwrap().edit(
                                            s.edit_index,
                                            s.name.read(cx).value().to_string(),
                                            s.value.read(cx).value().to_string(),
                                        );
                                        match result {
                                            Ok(()) => s.clear_editor(w, cx),
                                            Err(e) => s.notice = error_text(e).into(),
                                        }
                                        cx.notify();
                                    })),
                            )
                            .child(Button::new("cancel-editor").label("取消").on_click(
                                cx.listener(|s, _, w, cx| {
                                    s.clear_editor(w, cx);
                                    cx.notify();
                                }),
                            )),
                    ),
                );
        }
        for (title, kind) in [
            ("内置规则", 0),
            ("自定义敏感文本", 1),
            ("其他已有规则（只读保留）", 2),
        ] {
            let rows: Vec<_> = d
                .rows()
                .iter()
                .enumerate()
                .filter(|(_, r)| match kind {
                    0 => rules::builtin(r).is_some(),
                    1 => rules::simple_exact(r),
                    _ => !rules::editable(r),
                })
                .collect();
            if rows.is_empty() && kind == 2 {
                continue;
            }
            content = content.child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .mt_4()
                    .mb_1()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .text_size(px(13.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(title),
                            )
                            .child(appearance::badge(format!("{}", rows.len()), false)),
                    )
                    .when(kind == 1, |v| {
                        v.child(
                            Button::new("add-rule")
                                .icon(IconName::Plus)
                                .small()
                                .label("添加规则")
                                .disabled(self.busy || self.edit)
                                .on_click(cx.listener(|s, _, w, cx| s.begin_edit(None, w, cx))),
                        )
                    }),
            );
            if rows.is_empty() && kind == 1 {
                content = content.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .p_4()
                        .rounded_md()
                        .border_1()
                        .border_color(rgb(appearance::BORDER))
                        .child(appearance::icon(IconName::CaseSensitive))
                        .child(
                            div()
                                .v_flex()
                                .gap_1()
                                .child(div().text_size(px(12.)).child("尚未添加敏感文本"))
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(appearance::MUTED))
                                        .child("添加自定义精确文本，命中后阻止继续处理。"),
                                ),
                        ),
                );
            }
            for (i, r) in rows {
                let scope = r["sources"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| match s {
                        "tool.input" => "工具参数",
                        "tool.result" => "工具结果",
                        "user.prompt" => "用户输入",
                        _ => "上下文",
                    })
                    .collect::<Vec<_>>()
                    .join("、");
                let detail = if let Some((_, s)) = rules::builtin(r) {
                    format!("{s} · {scope}")
                } else if kind == 1 {
                    format!("精确匹配，区分大小写 · 内容已隐藏 · {scope}")
                } else {
                    format!(
                        "动作 {} · {scope} · 保留原始配置",
                        r["action"].as_str().unwrap_or("未知")
                    )
                };
                let row = div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .gap_3()
                    .py_3()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .child(
                        div()
                            .size(px(30.))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded_md()
                            .bg(rgb(appearance::SURFACE))
                            .child(appearance::icon(if kind == 1 {
                                IconName::CaseSensitive
                            } else {
                                IconName::Settings2
                            })),
                    )
                    .child(
                        div()
                            .v_flex()
                            .flex_1()
                            .min_w_0()
                            .gap_1()
                            .child(d.name(r))
                            .child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(cx.theme().muted_foreground)
                                    .child(detail),
                            ),
                    )
                    .child(
                        Switch::new(("rule-toggle", i))
                            .accessibility_label(d.name(r))
                            .small()
                            .checked(r["enabled"] == true)
                            .disabled(self.busy || self.edit || kind == 2)
                            .on_change(cx.listener(move |s, _, _, cx| {
                                s.draft.as_mut().unwrap().toggle(i);
                                cx.notify();
                            })),
                    )
                    .when(kind == 1, |v| {
                        v.child(
                            Button::new(("rule-edit", i))
                                .ghost()
                                .small()
                                .label("编辑")
                                .disabled(self.busy || self.edit)
                                .on_click(
                                    cx.listener(move |s, _, w, cx| s.begin_edit(Some(i), w, cx)),
                                ),
                        )
                        .child(
                            Button::new(("rule-delete", i))
                                .ghost()
                                .small()
                                .label("删除")
                                .disabled(self.busy || self.edit)
                                .on_click(cx.listener(move |s, _, _, cx| {
                                    s.draft.as_mut().unwrap().remove(i);
                                    cx.notify();
                                })),
                        )
                    });
                content = content.child(row);
            }
        }
        let summary = self
            .saved
            .as_ref()
            .map(|old| d.summary(old))
            .unwrap_or_default();
        content
            .child(
                self.panel(
                    "更改应用于新会话",
                    if self.dirty() {
                        summary
                    } else {
                        "更改只在新会话加载；不会解除已阻断会话。".into()
                    },
                    cx,
                )
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(
                            Button::new("discard")
                                .label("放弃更改")
                                .disabled(self.busy || !self.dirty() || self.edit)
                                .on_click(cx.listener(|s, _, _, cx| {
                                    s.draft = s.saved.clone();
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("save")
                                .icon(IconName::Check)
                                .small()
                                .primary()
                                .label("保存更改")
                                .disabled(self.busy || !self.dirty() || self.edit)
                                .on_click(cx.listener(|s, _, w, cx| {
                                    let d = s.draft.clone().unwrap();
                                    s.work(w, cx, move |m| {
                                        m.commit_document(d).map(Outcome::Saved)
                                    });
                                })),
                        ),
                ),
            )
            .into_any_element()
    }
}
fn error_text(code: &str) -> &'static str {
    match code {
        "UPDATE_FEED_UNAVAILABLE" => "无法连接项目发布源，当前插件保持不变。请检查网络后重试。",
        "UPDATE_PACKAGE_UNPUBLISHED" => "发布源尚未提供桌面可用的插件包，可继续使用内置版本。",
        "UPDATE_DIGEST_REQUIRED"
        | "UPDATE_DIGEST_MISMATCH"
        | "UPDATE_PACKAGE_INVALID"
        | "UPDATE_FEED_INVALID" => "更新包来源或完整性校验未通过，未执行安装。",
        "DESKTOP_UPDATE_REQUIRED" => "此插件包含检测引擎变更，请先升级桌面应用以保持规则校验一致。",
        "UPDATE_DOWNLOAD_FAILED" => "更新包下载未完成，当前插件保持不变。",
        "RULES_CHANGED_EXTERNALLY" => "规则已被其他程序修改。草稿仍保留，请重新读取后再编辑。",
        "ANOTHER_OPERATION_RUNNING" => "另一个管理操作正在进行，请稍后重试。",
        "RULE_FIELDS_REQUIRED" => "请填写名称和非空文本；名称最多 60 字，文本最多 8 KiB。",
        "RULE_CONFIG_REJECTED" => "规则校验未通过，原配置未被替换。",
        "NO_PREVIOUS_RULES" | "FILE_UNAVAILABLE" => "无法读取文件或尚无上一版，请重新读取配置。",
        "CLAUDE_NOT_FOUND" | "COMMAND_UNAVAILABLE" => "未找到可执行程序，请选择 Claude Code 程序。",
        "NOT_CLAUDE_CODE" => "所选程序未返回 Claude Code 版本信息。",
        "INSTALL_VERIFICATION_FAILED" => {
            "命令完成后未能确认安装状态，请重新检测。不要将此状态视为已安装。"
        }
        "BUNDLED_VERSION_OLDER" => "已安装版本比应用内置版本更新，已拒绝降级。",
        "COMMAND_TIMEOUT" => "程序执行超时，请重新检测安装状态。",
        "COMMAND_FAILED" => "插件命令失败。已尝试恢复安装源文件，宿主注册状态请重新检测。",
        _ => "操作未完成，草稿保留。请重试或重新检测；原始错误内容不显示。",
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
            (
                "nav-tools",
                "安装管理",
                Page::Tools,
                IconName::SquareTerminal,
            ),
            ("nav-rules", "规则编辑", Page::Rules, IconName::Settings2),
        ] {
            let active = self.page == page;
            nav = nav.child(
                appearance::navigation_item(id, label, glyph, active).on_click(cx.listener(
                    move |s, _, _, cx| {
                        s.page = page;
                        if page == Page::Overview {
                            s.connections_page = 0;
                            s.detail = None;
                        }
                        s.scroll.set_offset(point(px(0.), px(0.)));
                        cx.notify();
                    },
                )),
            );
        }
        let (title, subtitle, glyph) = match self.page {
            Page::Overview => (
                "概览",
                "查看正在保护的会话，以及曾经发生的拦截。",
                IconName::LayoutDashboard,
            ),
            Page::Tools => (
                "安装管理",
                "连接本机编程工具，管理插件与更新。",
                IconName::SquareTerminal,
            ),
            Page::Rules => (
                "规则编辑",
                "定义需要留在本机的信息。更改仅在新会话生效。",
                IconName::Settings2,
            ),
        };
        let page = match self.page {
            Page::Overview => self.overview(cx),
            Page::Tools => self.tools(cx),
            Page::Rules => self.rules_page(cx),
        };
        let mut body = div().v_flex().gap_4();
        if self.about {
            body=body.child(self.panel("关于 Agent Safeguard",format!("桌面 {} · 内置插件 {} · 代码 MIT / GeoIP 数据 CC BY 4.0（DB-IP）。检测在本机执行，退出窗口不停止已加载插件。",env!("CARGO_PKG_VERSION"),backend::BUNDLED_VERSION),cx).child(Button::new("open-data").label("打开本地数据目录").on_click(cx.listener(|s,_,_,cx|cx.reveal_path(&s.manager.base())))));
        }
        if self.close_pending {
            body =
                body.child(
                    self.panel(
                        "仍有未完成操作或未保存更改",
                        "返回规则保存，或者明确放弃后关闭。",
                        cx,
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(Button::new("cancel-close").label("继续编辑").on_click(
                                cx.listener(|s, _, _, cx| {
                                    s.close_pending = false;
                                    s.page = Page::Rules;
                                    cx.notify();
                                }),
                            ))
                            .child(
                                Button::new("discard-close")
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
                    .w(px(240.))
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
                                    "帮助与关于",
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
                            .pt_7()
                            .pb_6()
                            .child(
                                div()
                                    .v_flex()
                                    .gap_1()
                                    .mb_6()
                                    .child(
                                        div()
                                            .text_size(px(23.))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .child(title),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(12.))
                                            .text_color(rgb(appearance::MUTED))
                                            .child(subtitle),
                                    ),
                            )
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
                            .px_7()
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
                    .h(px(52.))
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
                                    .w(px(240.))
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
                                            .child(div().text_size(px(13.)).child(title)),
                                    )
                                    .when(self.manager.demo, |this| {
                                        this.child(appearance::badge("演示模式", false))
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
                window_bounds: Some(WindowBounds::centered(size(px(1040.), px(780.)), cx)),
                window_min_size: Some(size(px(800.), px(600.))),
                titlebar: Some(TitlebarOptions {
                    title: Some("Agent Safeguard".into()),
                    traffic_light_position: Some(point(px(16.), px(19.))),
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
