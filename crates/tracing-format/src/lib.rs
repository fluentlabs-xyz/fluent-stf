//! JSON event formatter that injects static service identity fields at the
//! top level of every emitted event. Used by the orchestrator's `LOG_FORMAT=json`
//! branch so Graylog can filter on `service` / `version` / `env` directly,
//! without an extractor pipeline rule against `spans[]`.
//!
//! The formatter delegates to the stock `tracing_subscriber::fmt::format::Json`
//! formatter and splices `service`, `version`, and `env` keys after the leading
//! `{` of the produced JSON object. This keeps every other field of the standard
//! JSON layout (`timestamp`, `level`, flattened event fields, span context,
//! `target`) untouched.
//!
//! `service` and `version` are compile-time constants embedded via `env!`; `env`
//! is the value of the `DEPLOY_ENV` environment variable, captured once at
//! subscriber init.

use std::fmt;

use tracing::{Event, Subscriber};
use tracing_subscriber::{
    fmt::{
        format::{Format, Json, Writer},
        time::SystemTime,
        FmtContext, FormatEvent, FormatFields,
    },
    registry::LookupSpan,
};

/// Wraps the stock JSON event formatter and prepends static identity fields.
#[derive(Debug)]
pub struct ServiceJson {
    inner: Format<Json, SystemTime>,
    service: &'static str,
    version: &'static str,
    env: String,
}

impl ServiceJson {
    pub fn new(service: &'static str, version: &'static str, env: String) -> Self {
        let inner = tracing_subscriber::fmt::format()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false);
        Self { inner, service, version, env }
    }
}

impl<S, N> FormatEvent<S, N> for ServiceJson
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        // Render the standard JSON layout into a buffer, then splice the static
        // identity fields after the opening `{`. The inner formatter writes a
        // trailing newline; we strip it and reapply it once after the splice.
        let mut buf = String::new();
        self.inner.format_event(ctx, Writer::new(&mut buf), event)?;
        let body = buf.strip_suffix('\n').unwrap_or(&buf);
        let body = body.strip_prefix('{').unwrap_or(body);
        let separator = if body.starts_with('}') { "" } else { "," };
        writeln!(
            writer,
            "{{\"service\":\"{}\",\"version\":\"{}\",\"env\":\"{}\"{}{}",
            escape_json_string(self.service),
            escape_json_string(self.version),
            escape_json_string(&self.env),
            separator,
            body,
        )
    }
}

/// Minimal JSON string escape for the three static identity fields. Only the
/// characters that JSON strictly requires escaping (`"` and `\`) and the
/// control characters at U+0000–U+001F are handled; the values for `service`,
/// `version`, and `env` are operator-controlled deployment metadata so the
/// fast path is the common case where no escape is needed.
fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing::Subscriber;
    use tracing_subscriber::{fmt, layer::SubscriberExt, registry::Registry};

    use super::{escape_json_string, ServiceJson};

    #[test]
    fn escape_passthrough_for_safe_strings() {
        assert_eq!(escape_json_string("witness-orchestrator"), "witness-orchestrator");
        assert_eq!(escape_json_string("1.2.3"), "1.2.3");
        assert_eq!(escape_json_string("production"), "production");
    }

    #[test]
    fn escape_quotes_and_backslashes() {
        assert_eq!(escape_json_string("a\"b"), "a\\\"b");
        assert_eq!(escape_json_string("a\\b"), "a\\\\b");
    }

    #[test]
    fn escape_control_characters() {
        assert_eq!(escape_json_string("\n"), "\\n");
        assert_eq!(escape_json_string("\t"), "\\t");
        assert_eq!(escape_json_string("\u{0001}"), "\\u0001");
    }

    /// Capturing writer for the formatter; lets the test scope a subscriber
    /// to a single thread without globally initialising one.
    #[derive(Clone)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriterHandle;
        fn make_writer(&'a self) -> Self::Writer {
            CaptureWriterHandle(Arc::clone(&self.0))
        }
    }

    struct CaptureWriterHandle(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriterHandle {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn build_subscriber(buf: Arc<Mutex<Vec<u8>>>) -> impl Subscriber {
        let layer = fmt::layer()
            .with_writer(CaptureWriter(buf))
            .with_ansi(false)
            .event_format(ServiceJson::new("witness-orchestrator", "0.1.0", "test".to_string()));
        Registry::default().with(layer)
    }

    #[test]
    fn emits_top_level_service_version_env_keys() {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        tracing::subscriber::with_default(build_subscriber(Arc::clone(&buf)), || {
            tracing::info!(batch_index = 42u64, "test event");
        });
        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let line = output.lines().next().expect("at least one log line");

        assert!(
            line.starts_with("{\"service\":\"witness-orchestrator\","),
            "service must be the first top-level key, got: {line}"
        );
        assert!(line.contains("\"version\":\"0.1.0\""), "version key missing: {line}");
        assert!(line.contains("\"env\":\"test\""), "env key missing: {line}");
        assert!(line.contains("\"batch_index\":42"), "event field missing: {line}");
        assert!(line.contains("\"message\":\"test event\""), "message missing: {line}");

        let parsed: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
        assert_eq!(parsed["service"], "witness-orchestrator");
        assert_eq!(parsed["version"], "0.1.0");
        assert_eq!(parsed["env"], "test");
    }
}
