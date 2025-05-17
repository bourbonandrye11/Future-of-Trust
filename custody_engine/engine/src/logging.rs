

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use tracing_appender::rolling;
use std::path::Path;

/// Initialize tracing with both stdout and rolling file output.
/// Format: human-readable logfmt OR JSON if desired.
pub fn init_logging(log_dir: &str, json_format: bool) {
    // Log file = logs/custody.log.{date}
    let file_appender = rolling::daily(log_dir, "custody.log");

    // Cloneable writer (can be shared across threads)
    let (non_blocking_file, _guard) = tracing_appender::non_blocking(file_appender);

    // Console layer (stdout for dev visibility)
    let stdout_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_target(false)
        .with_level(true);

    // File layer (logfmt or JSON format depending on input)
    let file_layer = if json_format {
        fmt::layer()
            .json()
            .with_writer(non_blocking_file)
            .with_current_span(false)
            .with_span_list(false)
            .with_level(true)
            .boxed()
    } else {
        fmt::layer()
            .with_writer(non_blocking_file)
            .with_target(false)
            .with_level(true)
            .boxed()
    };

    // Combine all layers and set global subscriber
    tracing_subscriber::registry()
        .with(stdout_layer)
        .with(file_layer)
        .init();
}
