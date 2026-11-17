use std::process::ExitCode;

use clap::Parser;

// Modules live in the `kata` library crate (`src/lib.rs`) so
// integration tests under `tests/` can reach them; binaries
// themselves are not testable from `tests/`. Importing via the
// library keeps the binary entry point and the test surface in
// sync — there is no second copy of any module here.
use kata::cli;

fn main() -> ExitCode {
    // Load operator-local `.env` if present (in cwd or ancestors). No-op
    // when absent. Populates std::env before clap parses `#[arg(env = ...)]`
    // defaults and before any config file resolves env-var interpolations.
    // See `.env.example` for the surface.
    cli::load_operator_dotenv();
    let raw_native_service = cli::is_raw_native_service_invocation();
    cli::install_native_service_panic_hook(raw_native_service);
    let cli = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let exit_code = error.exit_code();
            let diagnostic = error.to_string();
            cli::report_native_service_startup_error(raw_native_service, &diagnostic);
            let _ = error.print();
            return ExitCode::from(exit_code_as_u8(exit_code));
        }
    };
    let structured_native_service = cli::is_native_service_invocation(&cli);
    if structured_native_service && !raw_native_service {
        cli::install_native_service_panic_hook(true);
    }
    let native_service = raw_native_service || structured_native_service;
    let run_result = cli::run(cli);
    let outcome =
        combine_command_and_telemetry_results(run_result, kata_core::shutdown_telemetry());
    match outcome.result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Preserve anyhow's default chain rendering (`Error: {err:?}`),
            // then map the error onto the deterministic exit contract: a
            // typed OpError (2 usage / 3 not-found / 4 conflict|approval-
            // pending / 5 engine / 6 network) or the sysexits-style
            // `KataClientError` SSE/cursor variants `kata events
            // --exit-on`/`--since` can surface (65/66). See
            // `cli::exit_code_for_error`'s doc comment: a refusal the main
            // answered takes its contract class. Untyped errors keep the
            // flat exit 1.
            let diagnostic = format!("Error: {err:?}");
            let native_diagnostic = outcome.secondary.as_ref().map_or_else(
                || diagnostic.clone(),
                |secondary| format!("{diagnostic}\n{secondary}"),
            );
            cli::report_native_service_startup_error(native_service, &native_diagnostic);
            eprintln!("{diagnostic}");
            if let Some(secondary) = outcome.secondary {
                eprintln!("{secondary}");
            }
            ExitCode::from(exit_code_as_u8(cli::exit_code_for_error(&err)))
        }
    }
}

struct CombinedTopLevelResult {
    result: anyhow::Result<()>,
    secondary: Option<String>,
}

/// Combine command and telemetry teardown outcomes without losing either.
///
/// A teardown failure after command success becomes a typed engine error
/// (exit 5). When the command already failed, its error and exit code remain
/// primary and teardown is reported as a secondary diagnostic.
fn combine_command_and_telemetry_results(
    command: anyhow::Result<()>,
    telemetry: kata_types::error::KataResult<()>,
) -> CombinedTopLevelResult {
    match (command, telemetry) {
        (Ok(()), Ok(())) => CombinedTopLevelResult {
            result: Ok(()),
            secondary: None,
        },
        (Err(command), Ok(())) => CombinedTopLevelResult {
            result: Err(command),
            secondary: None,
        },
        (Ok(()), Err(telemetry)) => CombinedTopLevelResult {
            result: Err(kata_op_contract::OpError::engine(format!(
                "telemetry teardown failed: {telemetry}"
            ))
            .into()),
            secondary: None,
        },
        (Err(command), Err(telemetry)) => CombinedTopLevelResult {
            result: Err(command),
            secondary: Some(format!("Telemetry teardown error: {telemetry}")),
        },
    }
}

/// Clamp a contract exit code into the `u8` shell exit range. All mapped
/// codes are small positive integers, so this is an identity for the real
/// contract and a defensive clamp only for an out-of-range future code.
fn exit_code_as_u8(code: i32) -> u8 {
    u8::try_from(code).unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_command_with_teardown_failure_becomes_typed_engine_error() {
        let outcome = combine_command_and_telemetry_results(
            Ok(()),
            Err(kata_types::error::KataError::Internal(
                "flush timed out".to_string(),
            )),
        );
        let error = outcome
            .result
            .expect_err("teardown failure must be nonzero");
        let typed = error
            .downcast_ref::<kata_op_contract::OpError>()
            .expect("teardown failure must retain the typed operation contract");
        assert_eq!(typed.code, kata_op_contract::OpErrorCode::Engine);
        assert_eq!(cli::exit_code_for_error(&error), 5);
        assert!(outcome.secondary.is_none());
    }

    #[test]
    fn command_error_remains_primary_when_teardown_also_fails() {
        let command: anyhow::Error =
            kata_op_contract::OpError::not_found("missing execution").into();
        let outcome = combine_command_and_telemetry_results(
            Err(command),
            Err(kata_types::error::KataError::Internal(
                "flush timed out".to_string(),
            )),
        );
        let error = outcome.result.expect_err("primary command failure remains");
        assert_eq!(cli::exit_code_for_error(&error), 3);
        assert_eq!(
            outcome.secondary.as_deref(),
            Some("Telemetry teardown error: internal error: flush timed out"),
        );
    }

    #[test]
    fn successful_command_and_teardown_remain_success() {
        let outcome = combine_command_and_telemetry_results(Ok(()), Ok(()));
        assert!(outcome.result.is_ok());
        assert!(outcome.secondary.is_none());
    }
}
