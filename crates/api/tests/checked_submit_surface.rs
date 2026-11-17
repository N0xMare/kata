use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn runtime_sources_do_not_call_unchecked_workflow_submit_surfaces() {
    let repo_root = repo_root();
    let mut findings = Vec::new();

    for path in workspace_rust_sources(&repo_root) {
        if !is_runtime_source(&path) {
            continue;
        }
        scan_source_file(&repo_root, &path, &mut findings);
    }

    assert!(
        findings.is_empty(),
        "unchecked workflow parser/submit runtime call sites:\n{}",
        findings.join("\n")
    );
}

#[test]
fn public_inspect_helpers_compile_to_execution_program_artifacts() {
    let repo_root = repo_root();
    let preflight = fs::read_to_string(repo_root.join("crates/program/src/preflight.rs"))
        .expect("read preflight.rs");
    assert!(
        preflight.contains("pub fn build_workflow_compiled_artifact_from_file(\n    path: &Path,")
            && preflight.contains("pub fn build_starlark_workflow_compiled_artifact("),
        "public inspect/preflight surface must expose checked artifact builders for supported Starlark source forms"
    );
    assert!(
        !preflight.contains("pub fn build_toml_workflow_compiled_artifact("),
        "there is no TOML workflow frontend; preflight must not expose a TOML compiled-artifact builder"
    );
    assert!(
        preflight.contains("pub execution_program: ExecutionProgram,"),
        "compiled artifacts must carry the checked ExecutionProgram"
    );
    assert!(
        preflight.contains(
            "let execution_program = compile_execution_program_with_library(checked, binder, &mut deferred)?;"
        ),
        "compiled artifacts must lower through the ExecutionProgram compiler, handed the deferred-node-facts collector"
    );
    assert!(
        !preflight.contains("pub fn build_workflow_preflight("),
        "public preflight API must not expose checked-envelope preflight assembly"
    );
    assert!(
        !preflight.contains("pub fn build_workflow_compiled_artifact_from_parts("),
        "public preflight API must not expose generic raw WorkflowDefinition parts"
    );
    let preflight_builders = public_function_names(&preflight)
        .into_iter()
        .filter(|name| name.contains("compiled_artifact"))
        .collect::<Vec<_>>();
    assert_eq!(
        preflight_builders,
        owned_names(&[
            "build_workflow_compiled_artifact_from_file",
            "build_starlark_workflow_compiled_artifact",
        ]),
        "inspect/preflight must expose exactly the file-backed and inline-Starlark checked artifact builders"
    );

    let workflow_lib =
        fs::read_to_string(repo_root.join("crates/program/src/lib.rs")).expect("read lib.rs");
    assert!(
        !workflow_lib.contains("pub mod parser;")
            && !workflow_lib.contains("pub mod starlark_eval;"),
        "checked frontend parser/evaluator modules must stay private; public callers must use ExecutionProgram/artifact builders"
    );

    let parser = parser_module_source(&repo_root);
    assert!(
        parser.contains("pub(crate) fn from_parts(")
            && parser.contains("pub(crate) fn definition(&self)")
            && parser.contains("pub(crate) fn extensions(&self)"),
        "checked-definition construction and inspection must stay crate-private compiler internals"
    );
    assert!(
        !parser.contains("pub fn from_parts(")
            && !parser.contains("pub fn definition(&self)")
            && !parser.contains("pub fn extensions(&self)"),
        "checked-definition envelope internals must not become public API"
    );
    assert!(
        !parser.contains("try_update_extensions") && !parser.contains("try_cap_stage_timeouts"),
        "checked-definition envelope must not expose broad private mutation helpers; policy refinements should rebuild through validation"
    );

    let execution_program = execution_program_module_source(&repo_root);
    assert!(
        !execution_program.contains("pub fn compile_execution_program(\n    checked:")
            && !execution_program
                .contains("pub fn compile_execution_program_with_options(\n    checked:")
            && !execution_program.contains("pub fn compile_execution_program_from_parts(\n"),
        "checked-envelope and generic raw-parts ExecutionProgram lowering must not be public"
    );
    assert!(
        execution_program.contains("pub fn compile_agent_run_execution_program("),
        "API-shaped one-shot agent runs must use a narrow checked-IR compiler helper"
    );
    assert!(
        execution_program.contains("#[cfg(debug_assertions)]\n#[doc(hidden)]\npub fn compile_execution_program_from_parts_for_tests("),
        "generic raw-parts compiler helper must stay debug/test-only and hidden from the production public surface"
    );
    let compiler =
        fs::read_to_string(repo_root.join("crates/program/src/execution_program/compile.rs"))
            .expect("read execution_program/compile.rs");
    let public_compilers = public_function_names(&compiler)
        .into_iter()
        .filter(|name| name.starts_with("compile_"))
        .collect::<Vec<_>>();
    assert_eq!(
        public_compilers,
        owned_names(&[
            "compile_execution_program_from_file",
            "compile_starlark_execution_program",
            "compile_agent_run_execution_program",
            "compile_execution_program_from_parts_for_tests",
        ]),
        "workflow compiler public surface must stay limited to Starlark/file input, the narrow agent-run API, and the hidden debug helper"
    );
}

#[test]
fn executable_workflow_frontend_surface_is_starlark_only() {
    let repo_root = repo_root();
    let workflow_types = fs::read_to_string(repo_root.join("crates/types/src/workflow.rs"))
        .expect("read workflow.rs");
    let enum_body = workflow_types
        .split("pub enum WorkflowSourceFormat {")
        .nth(1)
        .and_then(|tail| tail.split_once('}').map(|(body, _)| body))
        .expect("WorkflowSourceFormat enum body");
    let variants = enum_body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("#[") && !line.starts_with("//"))
        .map(|line| line.trim_end_matches(','))
        .collect::<Vec<_>>();
    assert_eq!(
        variants,
        ["Starlark", "Api"],
        "WorkflowSourceFormat must remain exactly Starlark plus the narrow programmatic API source"
    );
    assert!(
        enum_body.contains("#[default]\n    Starlark,"),
        "Starlark must remain the default and sole executable file frontend"
    );
}

#[test]
fn production_submit_request_schemas_are_starlark_only() {
    let repo_root = repo_root();
    let rest = fs::read_to_string(repo_root.join("crates/api/src/rest/workflows.rs"))
        .expect("read REST workflow routes");
    // The submit surfaces gained a typed
    // invocation `params` object — a resolved-at-admission `{name: value}` map,
    // NOT a new workflow SOURCE. The source fields stay pinned below; `params` is
    // the only added field, reviewed here.
    assert_eq!(
        named_struct_field_names(&rest, "CreateExecutionBody"),
        owned_names(&[
            "ref_name",
            "starlark",
            "filename",
            "external_inputs",
            "params",
            "target"
        ]),
        "POST /executions request fields drifted; workflow sources must remain workflow_ref or workflow_starlark (params and target are not sources)"
    );
    let body = named_struct_body(&rest, "CreateExecutionBody");
    assert!(
        body.contains("rename = \"workflow_ref\"")
            && body.contains("rename = \"workflow_starlark\"")
            && body.contains("rename = \"workflow_filename\""),
        "REST submit wire fields must stay pinned to workflow_ref, workflow_starlark, and workflow_filename"
    );

    let op_requests = fs::read_to_string(repo_root.join("crates/op-contract/src/requests.rs"))
        .expect("read operation requests");
    assert_eq!(
        named_struct_field_names(&op_requests, "RunRequest"),
        owned_names(&[
            "workflow",
            "workflow_starlark",
            "workflow_filename",
            "params",
            "target",
            "wait",
            "wait_timeout_secs",
        ]),
        "shared run operation request gained an unreviewed workflow source (params, target \
         and wait_timeout_secs, which bounds `wait`, are NOT workflow sources)"
    );

    let client = fs::read_to_string(repo_root.join("crates/client/src/client.rs"))
        .expect("read client request types");
    assert_eq!(
        named_struct_field_names(&client, "CreateExecutionBody"),
        owned_names(&[
            "ref_name",
            "starlark",
            "filename",
            "external_inputs",
            "params",
            "target"
        ]),
        "client execution request gained an unreviewed workflow source (params and target are \
         not sources)"
    );
    let client_body = named_struct_body(&client, "CreateExecutionBody");
    assert!(
        client_body.contains("rename = \"workflow_ref\"")
            && client_body.contains("rename = \"workflow_starlark\"")
            && client_body.contains("rename = \"workflow_filename\""),
        "client submit wire fields must stay pinned to workflow_ref, workflow_starlark, and workflow_filename"
    );
}

#[test]
fn rust_source_introspection_sees_qualified_and_split_public_functions() {
    let source = r#"
        pub fn plain() {}
        pub async fn asynchronous() {}
        pub const fn constant() {}
        pub unsafe extern "C" fn foreign() {}
        pub
        async
        fn split_across_lines() {}
        pub(crate) async fn restricted() {}
        const TEXT: &str = "pub async fn string_literal() {}";
        // pub async fn line_comment() {}
        /* pub unsafe fn block_comment() {} */
    "#;
    assert_eq!(
        public_function_names(source),
        owned_names(&[
            "plain",
            "asynchronous",
            "constant",
            "foreign",
            "split_across_lines",
        ])
    );
}

#[test]
fn executor_public_surface_requires_execution_program_submission() {
    let repo_root = repo_root();
    let executor = executor_module_source(&repo_root);

    assert!(
        executor.contains(
            "pub fn submit_execution_program(\n        &self,\n        execution_program: ExecutionProgram,"
        ),
        "WorkflowExecutor must expose ExecutionProgram submission as the public execution boundary"
    );
    assert!(
        executor.contains("pub fn compile_ref_execution_program(")
            && executor.contains("pub fn compile_inline_starlark_execution_program("),
        "API compile helpers must return ExecutionProgram for every supported Starlark source form"
    );
    assert!(
        !executor.contains("pub fn compile_inline_toml_execution_program("),
        "there is no TOML workflow frontend; the API must not expose a TOML compile helper"
    );
    assert!(
        !executor.contains("pub fn submit_checked(")
            && !executor.contains("pub fn submit_checked_with_initial_external_inputs("),
        "WorkflowExecutor must not expose checked-definition submit methods"
    );
    assert!(
        !executor.contains("pub fn parse_inline_toml_checked(")
            && !executor.contains("pub fn parse_inline_starlark_checked("),
        "kata-api must not expose public inline parse helpers that return CheckedWorkflowDefinition"
    );
    assert!(
        !executor.contains("pub fn promote_with_controller_application(")
            && !executor.contains("pub fn park_candidate_with_controller_application("),
        "direct promote/park APIs must not accept controller-application context; controller applications are server-owned factory apply/finalize effects"
    );
}

#[test]
fn runtime_constructors_are_execution_program_only() {
    let repo_root = repo_root();
    let runner = fs::read_to_string(repo_root.join("crates/workflow/src/runner/mod.rs"))
        .expect("read runner/mod.rs");
    assert!(
        runner.contains("pub fn new_from_program(\n        execution_program: ExecutionProgram,"),
        "WorkflowRunner must expose ExecutionProgram-backed construction"
    );
    assert!(
        !runner.contains("pub fn new(\n        definition:")
            && !runner.contains("pub fn new(\n        workflow:")
            && !runner.contains("pub fn new_from_definition("),
        "WorkflowRunner must not expose raw WorkflowDefinition construction"
    );

    let orchestrator = fs::read_to_string(repo_root.join("crates/program/src/orchestrator.rs"))
        .expect("read orchestrator.rs");
    assert!(
        orchestrator.contains(
            "pub fn from_execution_program(program: &ExecutionProgram) -> KataResult<Self>"
        ),
        "Orchestrator must be constructed from the checked ExecutionProgram graph"
    );
    assert!(
        !orchestrator.contains("pub fn from_definition(")
            && !orchestrator.contains("pub fn from_workflow("),
        "Orchestrator must not expose raw WorkflowDefinition construction"
    );
}

#[test]
fn attempt_claims_go_through_the_operational_chain_only() {
    let repo_root = repo_root();
    let operational = rust_sources_under(&repo_root.join("crates/core/src/operational"))
        .iter()
        .map(|p| fs::read_to_string(p).expect("read operational module source"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        operational.contains(
            "pub fn claim_attempt(\n        &self,\n        execution_id: Ulid,\n        attempt_id: Ulid,\n        claim: &AttemptClaimSpec,"
        ),
        "the operational chain's attempt-claim door must keep its checked authority shape"
    );
    assert!(
        operational.contains("pub fn claim_attempt_parked_for_approval(")
            && operational.contains("pub fn decide_capsule_approval("),
        "the approval gate's park and decide doors stay on the operational chain"
    );

    let transport =
        fs::read_to_string(repo_root.join("crates/transport/src/types.rs")).expect("read types.rs");
    assert!(
        transport.contains("pub struct CheckedDispatchFrame")
            && transport.contains("pub fn new(frame: DispatchFrame)"),
        "CheckedDispatchFrame remains the send-boundary witness the transport requires"
    );
}

#[test]
fn low_level_worker_boundaries_require_checked_assignments() {
    let repo_root = repo_root();
    let supervisor = fs::read_to_string(repo_root.join("crates/transport/src/supervisor.rs"))
        .expect("read supervisor.rs");
    assert!(
        !supervisor.contains("pub async fn dispatch(&self"),
        "WorkerPoolSupervisor must not expose generic public dispatch; worker selection belongs to Dispatcher after checked-IR validation"
    );
    assert!(
        supervisor.contains("pub fn claim_dispatch_authority(&self) -> KataResult<WorkerPoolDispatchAuthority>")
            && supervisor.contains("fn validate_dispatch_authority(\n        &self,\n        authority: &WorkerPoolDispatchAuthority,"),
        "WorkerPoolSupervisor must require a claimed dispatch authority before sending work"
    );
    assert!(
        // The value that crosses is the tagged frame.
        supervisor.contains("pub async fn dispatch_to(\n        &self,\n        authority: &WorkerPoolDispatchAuthority,\n        worker_id: &str,\n        frame: CheckedDispatchFrame,\n    ) -> KataResult<()>"),
        "WorkerPoolSupervisor::dispatch_to must require dispatch authority and CheckedDispatchFrame"
    );
    assert!(
        supervisor.contains("pub(crate) transport: Arc<dyn WorkerTransport>"),
        "WorkerInfo must not expose the raw WorkerTransport handle outside kata-transport"
    );
    assert!(
        supervisor.contains("pub fn result_transport(&self) -> Arc<dyn WorkerResultTransport>"),
        "WorkerInfo must expose only a receive-side transport view for reactors"
    );

    let reactor = fs::read_to_string(repo_root.join("crates/workflow/src/reactor.rs"))
        .expect("read reactor.rs");
    assert!(
        reactor.contains("transport: Arc<dyn WorkerResultTransport>"),
        "ResultReactor must store the receive-only transport view, not raw WorkerTransport"
    );

    let executor = fs::read_to_string(repo_root.join("crates/worker/src/capsule_route.rs"))
        .expect("read capsule_route.rs");
    assert!(
        executor.contains(
            "pub(crate) async fn execute(\n        &self,\n        frame: &CapsuleAssignment,"
        ),
        "CapsuleRoute::execute must be crate-private; public execution enters through execute_capsule_frame"
    );
    let capsule_execution =
        fs::read_to_string(repo_root.join("crates/worker/src/capsule_execution.rs"))
            .expect("read capsule_execution.rs");
    assert!(
        capsule_execution.contains("pub async fn execute_capsule_frame("),
        "capsule frames are the worker's only execute surface"
    );

    let worker_transport = fs::read_to_string(repo_root.join("crates/transport/src/transport.rs"))
        .expect("read transport.rs");
    assert!(
        // The payload is the tagged frame.
        worker_transport.contains("async fn dispatch(&self, frame: CheckedDispatchFrame)"),
        "WorkerTransport::dispatch must require CheckedDispatchFrame; a raw DispatchFrame is only a serialized wire frame after validation"
    );
    assert!(
        !worker_transport.contains("async fn dispatch(&self, frame: DispatchFrame)"),
        "WorkerTransport::dispatch must not expose an unchecked send surface"
    );
}

/// Concatenate every source file of the `kata-api` executor module
/// (`crates/api/src/executor/`). The executor is a module directory; the
/// public-surface assertions
/// scan the module as a whole so a helper moving between sibling files
/// does not evade the check.
fn executor_module_source(repo_root: &Path) -> String {
    rust_sources_under(&repo_root.join("crates/api/src/executor"))
        .iter()
        .map(|p| fs::read_to_string(p).expect("read executor module source"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Concatenate every source file of the `kata-program` parser module
/// (`crates/program/src/parser/`), a module directory; the
/// checked-definition surface assertions scan the module as a whole.
fn parser_module_source(repo_root: &Path) -> String {
    rust_sources_under(&repo_root.join("crates/program/src/parser"))
        .iter()
        .map(|p| fs::read_to_string(p).expect("read parser module source"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// True when `path` is inside the dispatcher module directory
/// `crates/workflow/src/dispatcher/`.
fn in_dispatcher_module(path: &Path) -> bool {
    path.to_string_lossy()
        .contains("crates/workflow/src/dispatcher/")
}

/// True when `path` is inside the parser module directory
/// `crates/program/src/parser/`.
fn in_parser_module(path: &Path) -> bool {
    path.to_string_lossy()
        .contains("crates/program/src/parser/")
}

fn execution_program_module_source(repo_root: &Path) -> String {
    rust_sources_under(&repo_root.join("crates/program/src/execution_program"))
        .iter()
        .map(|p| fs::read_to_string(p).expect("read execution_program module source"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("api crate lives under <repo>/crates/api")
        .to_path_buf()
}

fn rust_sources_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rust_sources(root, &mut out);
    out.sort();
    out
}

fn workspace_rust_sources(repo_root: &Path) -> Vec<PathBuf> {
    let mut out = rust_sources_under(&repo_root.join("crates"));
    out.extend(rust_sources_under(&repo_root.join("bin")));
    out.sort();
    out
}

/// Names of the `pub` (and ONLY `pub`) functions in one Rust source.
///
/// A RESTRICTED visibility — `pub(crate) fn`, `pub(super) fn`, `pub(in path) fn`
/// — is deliberately NOT a hit: the `token == "("` arm below skips it. Callers
/// that ask "what can another CRATE reach" want exactly that; "what can any
/// OTHER MODULE reach" is a strictly wider question this function does not
/// answer.
fn public_function_names(source: &str) -> Vec<String> {
    let tokens = rust_tokens(source);
    let mut names = Vec::new();
    let mut cursor = 0;
    while cursor < tokens.len() {
        if tokens[cursor] != "pub" {
            cursor += 1;
            continue;
        }
        let mut item = cursor + 1;
        // `pub(crate)` / `pub(super)` / `pub(in ..)` — a RESTRICTED visibility is
        // not `pub`, and this function's contract is `pub`.
        if tokens.get(item).is_some_and(|token| token == "(") {
            cursor += 1;
            continue;
        }
        while tokens.get(item).is_some_and(|token| {
            matches!(
                token.as_str(),
                "async" | "const" | "unsafe" | "extern" | "default"
            )
        }) {
            item += 1;
        }
        if tokens.get(item).is_some_and(|token| token == "fn")
            && let Some(name) = tokens.get(item + 1)
            && is_rust_identifier(name)
        {
            names.push(name.clone());
        }
        cursor += 1;
    }
    names
}

fn owned_names(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_string()).collect()
}

fn named_struct_field_names(source: &str, struct_name: &str) -> Vec<String> {
    let tokens = rust_tokens(source);
    let name_index = tokens
        .windows(2)
        .position(|pair| pair[0] == "struct" && pair[1] == struct_name)
        .unwrap_or_else(|| panic!("missing struct {struct_name}"));
    let body_start = tokens[name_index + 2..]
        .iter()
        .position(|token| token == "{")
        .map_or_else(
            || panic!("struct {struct_name} has no named-field body"),
            |offset| name_index + 2 + offset,
        );

    let mut fields = Vec::new();
    let mut depth = 1usize;
    let mut segment = Vec::new();
    for token in &tokens[body_start + 1..] {
        match token.as_str() {
            "{" | "(" | "[" | "<" => {
                depth += 1;
                segment.push(token.as_str());
            }
            "}" | ")" | "]" | ">" => {
                if depth == 1 && token == "}" {
                    if let Some(name) = field_name_from_segment(&segment) {
                        fields.push(name);
                    }
                    break;
                }
                depth = depth.saturating_sub(1);
                segment.push(token.as_str());
            }
            "," if depth == 1 => {
                if let Some(name) = field_name_from_segment(&segment) {
                    fields.push(name);
                }
                segment.clear();
            }
            _ if depth == 1 => segment.push(token.as_str()),
            _ => {}
        }
    }
    fields
}

fn field_name_from_segment(segment: &[&str]) -> Option<String> {
    let colon = segment.iter().position(|token| *token == ":")?;
    segment[..colon]
        .iter()
        .rev()
        .find(|token| is_rust_identifier(token) && **token != "pub")
        .map(|name| (*name).to_string())
}

fn named_struct_body<'a>(source: &'a str, struct_name: &str) -> &'a str {
    let declaration = source
        .find(&format!("struct {struct_name}"))
        .unwrap_or_else(|| panic!("missing struct {struct_name}"));
    let body_start = source[declaration..].find('{').map_or_else(
        || panic!("struct {struct_name} has no body"),
        |offset| declaration + offset,
    );
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[body_start..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[body_start + 1..body_start + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated struct {struct_name}")
}

fn is_rust_identifier(token: &str) -> bool {
    token
        .chars()
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && token
            .chars()
            .all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn rust_tokens(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        match bytes[cursor] {
            byte if byte.is_ascii_whitespace() => cursor += 1,
            b'/' if bytes.get(cursor + 1) == Some(&b'/') => {
                cursor += 2;
                while cursor < bytes.len() && bytes[cursor] != b'\n' {
                    cursor += 1;
                }
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'*') => {
                cursor += 2;
                let mut depth = 1usize;
                while cursor < bytes.len() && depth > 0 {
                    if bytes.get(cursor..cursor + 2) == Some(b"/*") {
                        depth += 1;
                        cursor += 2;
                    } else if bytes.get(cursor..cursor + 2) == Some(b"*/") {
                        depth -= 1;
                        cursor += 2;
                    } else {
                        cursor += 1;
                    }
                }
            }
            b'b' if bytes.get(cursor + 1) == Some(&b'"') => {
                cursor = skip_quoted(bytes, cursor + 1, b'"');
            }
            b'b' if bytes.get(cursor + 1) == Some(&b'r')
                && bytes
                    .get(cursor + 2)
                    .is_some_and(|byte| *byte == b'"' || *byte == b'#') =>
            {
                cursor = skip_raw_string(bytes, cursor + 1);
            }
            b'"' => cursor = skip_quoted(bytes, cursor, b'"'),
            b'\'' if rust_lifetime_starts(bytes, cursor) => {
                tokens.push("'".to_string());
                cursor += 1;
            }
            b'\'' => cursor = skip_quoted(bytes, cursor, b'\''),
            b'r' if bytes
                .get(cursor + 1)
                .is_some_and(|byte| *byte == b'"' || *byte == b'#') =>
            {
                cursor = skip_raw_string(bytes, cursor);
            }
            byte if byte == b'_' || byte.is_ascii_alphabetic() => {
                let start = cursor;
                cursor += 1;
                while cursor < bytes.len()
                    && (bytes[cursor] == b'_' || bytes[cursor].is_ascii_alphanumeric())
                {
                    cursor += 1;
                }
                tokens.push(source[start..cursor].to_string());
            }
            byte => {
                tokens.push(char::from(byte).to_string());
                cursor += 1;
            }
        }
    }
    tokens
}

fn rust_lifetime_starts(bytes: &[u8], cursor: usize) -> bool {
    let Some(next) = bytes.get(cursor + 1) else {
        return false;
    };
    if !(*next == b'_' || next.is_ascii_alphabetic()) {
        return false;
    }
    let mut end = cursor + 2;
    while bytes
        .get(end)
        .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
    {
        end += 1;
    }
    bytes.get(end) != Some(&b'\'')
}

fn skip_quoted(bytes: &[u8], mut cursor: usize, delimiter: u8) -> usize {
    cursor += 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor = (cursor + 2).min(bytes.len()),
            byte if byte == delimiter => return cursor + 1,
            _ => cursor += 1,
        }
    }
    cursor
}

fn skip_raw_string(bytes: &[u8], mut cursor: usize) -> usize {
    cursor += 1;
    let hashes_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return hashes_start;
    }
    let hash_count = cursor - hashes_start;
    cursor += 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"'
            && bytes.get(cursor + 1..cursor + 1 + hash_count)
                == Some(&bytes[hashes_start..hashes_start + hash_count])
        {
            return cursor + 1 + hash_count;
        }
        cursor += 1;
    }
    cursor
}

fn collect_rust_sources(path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn is_runtime_source(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.contains("/src/")
        && !text.contains("/tests/")
        && !text.contains("/test-utils/")
        && !text.contains("/target/")
        // `*_tests.rs` are `#[cfg(test)] #[path = "..."]` test siblings extracted
        // out of inline `mod tests` blocks (crate convention, e.g. parser_tests.rs);
        // they are test code, not runtime source, so exclude them from the scan.
        && !text.ends_with("_tests.rs")
        // And neither is `<mod>/tests.rs`. It is reached ONLY through
        // `#[cfg(test)] mod tests;` (e.g. the `tests` module of `crates/program/src/dsl/mod.rs`),
        // so it is test code whose PATH looks like production — nothing in it says
        // `/tests/` or `_tests.rs`. Admitting it would make this file's corpus
        // disagree with the sibling guard (`lifecycle_face_seams.rs::is_runtime`,
        // which excludes it by name), and the closed compile-site allowlist below
        // finds such a divergence.
        && path
            .file_name()
            .is_none_or(|name| name.to_string_lossy() != "tests.rs")
}

fn scan_source_file(repo_root: &Path, path: &Path, findings: &mut Vec<String>) {
    let Ok(source) = fs::read_to_string(path) else {
        return;
    };
    let mut pending_cfg_test = false;
    let mut cfg_test_depth = 0usize;

    for (line_index, line) in source.lines().enumerate() {
        let line_no = line_index + 1;
        let trimmed = line.trim();

        if cfg_test_depth > 0 {
            cfg_test_depth = update_brace_depth(cfg_test_depth, line);
            continue;
        }

        if pending_cfg_test {
            if trimmed.is_empty() || trimmed.starts_with("#[") {
                continue;
            }
            // ANY module under `#[cfg(test)]` is test code, regardless of its
            // name — the crate has named test modules beyond `mod tests`
            // (`mod admission_gate_tests`, `mod scope_window_tests`, ...), and a
            // `mod tests`-only match would scan their bodies as runtime source
            // (false-positive raw-insert findings).
            if trimmed.starts_with("mod ") || trimmed.starts_with("pub mod ") {
                cfg_test_depth = line
                    .chars()
                    .filter(|ch| *ch == '{')
                    .count()
                    .saturating_sub(line.chars().filter(|ch| *ch == '}').count());
                pending_cfg_test = false;
                continue;
            }
            pending_cfg_test = false;
        }

        if trimmed.starts_with("#[cfg(test)]") {
            pending_cfg_test = true;
            continue;
        }
        if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        for forbidden in forbidden_patterns(path, line) {
            let rel = path.strip_prefix(repo_root).unwrap_or(path);
            findings.push(format!(
                "{}:{line_no}: {forbidden}: {}",
                rel.display(),
                trimmed
            ));
        }
    }
}

fn update_brace_depth(depth: usize, line: &str) -> usize {
    let opens = line.chars().filter(|ch| *ch == '{').count();
    let closes = line.chars().filter(|ch| *ch == '}').count();
    depth.saturating_add(opens).saturating_sub(closes)
}

fn brace_delta(line: &str) -> usize {
    update_brace_depth(0, line)
}

fn extract_fn_name(trimmed: &str) -> Option<String> {
    let start = trimmed.find("fn ")? + "fn ".len();
    let rest = &trimmed[start..];
    let name: String = rest
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn forbidden_patterns(path: &Path, line: &str) -> Vec<&'static str> {
    let mut patterns = Vec::new();
    if line.contains(".parse_ref(") && !line.contains("fn parse_ref(") {
        patterns.push("WorkflowExecutor::parse_ref-style call");
    }
    if line.contains("executor.submit(") || line.contains("workflow_executor.submit(") {
        patterns.push("WorkflowExecutor::submit(WorkflowDefinition)-style call");
    }
    if line.contains("WorkflowRunner::new(") {
        patterns.push("WorkflowRunner::new raw-definition execution path");
    }
    if line.contains("execution_lifecycle: Option")
        || line.contains("Option<ExecutionLifecycleFace>")
        || line.contains("Option<&ExecutionLifecycleFace>")
    {
        patterns.push("optional checked ExecutionProgram store in runtime source");
    }
    if line.contains("Orchestrator::from_definition(") {
        patterns.push("Orchestrator::from_definition raw-definition execution path");
    }
    if in_parser_module(path)
        && (line.contains("pub definition:") || line.contains("pub extensions:"))
    {
        patterns.push("public mutable checked-definition field");
    }
    if in_parser_module(path) && line.contains("pub fn into_parts(") {
        patterns.push("public checked-definition deconstruction escape hatch");
    }
    if in_parser_module(path) && line.contains("pub fn try_update(") {
        patterns.push("public broad checked-definition mutation escape hatch");
    }
    if path.ends_with("crates/api/src/rest/workflows.rs") && line.contains("\"definition\"") {
        patterns.push("workflow inspect exposes normalized WorkflowDefinition");
    }
    if path.ends_with("crates/api/src/executor/mod.rs")
        && line.contains("pub fn persist_workflow_level_failure(")
    {
        patterns.push("workflow-level failure helper without ExecutionProgram authority");
    }
    if is_public_raw_dispatch_method(path, line) {
        patterns.push("public raw dispatcher submission method");
    }
    if path.ends_with("crates/transport/src/transport.rs")
        // The payload is the tagged frame, so an unchecked send surface would name
        // `DispatchFrame` instead.
        && line.contains("async fn dispatch(&self, frame: DispatchFrame)")
    {
        patterns.push("public raw worker transport dispatch method");
    }
    if path.ends_with("crates/transport/src/supervisor.rs")
        && line.contains("pub transport: Arc<dyn WorkerTransport>")
    {
        patterns.push("public raw worker transport handle");
    }
    if is_raw_dispatch_call(line) && !is_raw_dispatch_allowlisted(path) {
        patterns.push("raw dispatcher submission outside checked dispatch path");
    }
    if is_stage_executor_execute_call(line) && !is_stage_executor_execute_allowlisted(path) {
        patterns.push("direct StageExecutor::execute call outside checked worker boundary");
    }
    if line.contains("synthetic_for_test(") {
        patterns.push("test-only synthetic dispatch authority in runtime source");
    }
    // The FRAME's checked wrapper is the value the send boundary demands: a caller outside
    // the dispatch path that could mint it could hand the transport an unchecked frame.
    if line.contains("CheckedDispatchFrame::new(")
        && !is_checked_dispatch_frame_constructor_allowlisted(path)
    {
        patterns
            .push("checked dispatch frame wrapper outside dispatcher/transport/worker boundary");
    }
    patterns
}

fn is_raw_dispatch_call(line: &str) -> bool {
    line.contains(".submit(")
}

fn is_public_raw_dispatch_method(path: &Path, line: &str) -> bool {
    in_dispatcher_module(path)
        && (line.contains("pub fn submit(") || line.contains("pub async fn submit("))
}

fn is_stage_executor_execute_call(line: &str) -> bool {
    line.contains("executor.execute(") || line.contains("self.executor.execute(")
}

fn is_stage_executor_execute_allowlisted(path: &Path) -> bool {
    path.ends_with("crates/worker/src/worker_loop.rs")
}

fn is_checked_dispatch_frame_constructor_allowlisted(path: &Path) -> bool {
    in_dispatcher_module(path)
        || path.ends_with("crates/transport/src/supervisor.rs")
        || path.ends_with("crates/worker/src/worker_loop.rs")
}

fn is_raw_dispatch_allowlisted(path: &Path) -> bool {
    in_dispatcher_module(path)
}

// ── The compile-surface CLOSED ALLOWLIST ─────────────────────────────────────
//
// Every other negative in this file is a forbidden-SUBSTRING rule with a
// per-file or per-fn exemption. That shape fails open twice over: renaming a
// symbol passes every negative silently, and moving a violating call into an
// allowlisted file defeats the allowlist. A compile of a pack into an
// `ExecutionProgram` is the one operation where the question is not "is this
// symbol spelled right" but "is THIS SITE allowed to mint program bytes at all",
// so it is expressed as a CLOSED allowlist of (path, fn) pairs: an unlisted site
// is a finding, and a listed site that no longer exists is ALSO a finding.

/// Direct compiler calls covered by this lexical census. Calls through other
/// helpers are not transitively attributed to their callers by this scanner.
const COMPILE_SURFACES: &[&str] = &[
    "compile_ref_execution_program",
    "compile_inline_starlark_execution_program",
    "compile_execution_program",
    "compile_execution_program_with_library",
    "compile_execution_program_with_options",
    "compile_execution_program_from_parts",
    "compile_execution_program_from_file",
    "compile_starlark_execution_program",
    "compile_agent_run_execution_program",
];

/// Why a site is allowed to compile. The class is part of the allowlist because
/// "which face is this" is the question checked-program lineage actually asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompileSiteClass {
    /// The compile CREATES the run: the program handed to the runner and the
    /// program persisted are one value in one call frame. Lineage is satisfied
    /// because there is no pre-existing run whose lineage could be ignored.
    SubmitFace,
    /// Install / migration / rebind: the compile produces a PIN that later firing
    /// reads back. The schedule path works this way.
    InstallOrMigration,
    /// Read-only projection: preflight, inspect, or an upgrade compat sweep. The
    /// result is reported, never dispatched.
    PreflightOrInspect,
    /// The compile module's own internal delegation between its entry points.
    CompilerInternal,
    /// Fixture construction for the workflow test harness.
    TestHarness,
}

/// The closed set, measured over the runtime corpus only.
///
/// Its size needs no document, because
/// [`compile_surfaces_are_reachable_only_from_a_submit_or_install_face`] proves
/// *observed ⊆ allowlist* and
/// [`every_compile_site_allowlist_entry_still_names_a_live_site`] proves
/// *allowlist ⊆ observed*, so the two together force the observed pair set to
/// equal this constant and counting it counts the population. The pre-dedup
/// call-site count is the output of [`observed_compile_sites`].
const COMPILE_SITE_ALLOWLIST: &[(&str, &str, CompileSiteClass)] = &[
    // -- submit faces: the compile creates the run ---------------------------
    (
        "crates/api/src/executor/compile.rs",
        "compile_inline_starlark_execution_program",
        CompileSiteClass::SubmitFace,
    ),
    (
        "crates/api/src/executor/mod.rs",
        "compile_ref_execution_program",
        CompileSiteClass::SubmitFace,
    ),
    (
        "crates/api/src/executor/worker_selection.rs",
        "agent_run_execution_program",
        CompileSiteClass::SubmitFace,
    ),
    (
        "crates/api/src/op_dispatch.rs",
        "compile_run_program",
        CompileSiteClass::SubmitFace,
    ),
    (
        "crates/api/src/rest/workflows.rs",
        "create_execution",
        CompileSiteClass::SubmitFace,
    ),
    // -- install / migration: the compile produces a PIN ---------------------
    (
        "bin/kata/src/boot.rs",
        "reconcile_one_schedule",
        CompileSiteClass::InstallOrMigration,
    ),
    // -- preflight / inspect: reported, never dispatched ---------------------
    (
        "crates/program/src/preflight.rs",
        "build_workflow_compiled_artifact",
        CompileSiteClass::PreflightOrInspect,
    ),
    // -- the compiler delegating to itself -----------------------------------
    (
        "crates/program/src/execution_program/compile.rs",
        "compile_execution_program_with_library",
        CompileSiteClass::CompilerInternal,
    ),
    // A subworkflow child is compiled at its PARENT's check, through the same
    // compiler, and embedded in the parent's program — the compile that makes the
    // parent's bytes, not a compile inside a running execution.
    (
        "crates/program/src/execution_program/subworkflow_binding.rs",
        "bind_child",
        CompileSiteClass::CompilerInternal,
    ),
    (
        "crates/program/src/execution_program/compile.rs",
        "compile_execution_program_from_file",
        CompileSiteClass::CompilerInternal,
    ),
    (
        "crates/program/src/execution_program/compile.rs",
        "compile_starlark_execution_program",
        CompileSiteClass::CompilerInternal,
    ),
    (
        "crates/program/src/execution_program/compile.rs",
        "compile_agent_run_execution_program",
        CompileSiteClass::CompilerInternal,
    ),
    (
        "crates/program/src/execution_program/compile.rs",
        "compile_execution_program_from_parts",
        CompileSiteClass::CompilerInternal,
    ),
    (
        "crates/program/src/execution_program/compile.rs",
        "compile_execution_program_from_parts_for_tests",
        CompileSiteClass::CompilerInternal,
    ),
    (
        "crates/program/src/test_harness.rs",
        "compile_fixture_source",
        CompileSiteClass::TestHarness,
    ),
];

/// Whether a `#[cfg(..)]` attribute gates its item out of production builds.
///
/// Mirrors the workspace guard's `predicate_mentions_test`
/// so the two agree
/// on what "runtime" means: whole-word `test` (so `latest` does not gate) plus the
/// `test-support` feature.
fn cfg_predicate_mentions_test(attribute: &str) -> bool {
    if attribute.contains("test-support") || attribute.contains("test_support") {
        return true;
    }
    let bytes = attribute.as_bytes();
    let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    bytes.windows(4).enumerate().any(|(at, window)| {
        window == b"test"
            && !(at > 0 && bytes.get(at - 1).copied().is_some_and(word))
            && !bytes.get(at + 4).copied().is_some_and(word)
    })
}

/// Every (path, fn) pair in the runtime corpus that calls a compile surface.
fn observed_compile_sites() -> Vec<(String, String, usize)> {
    let repo_root = repo_root();
    let mut paths = workspace_rust_sources(&repo_root);
    paths.retain(|path| is_runtime_source(path));

    let mut observed = Vec::new();
    for path in paths {
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        let rel = path
            .strip_prefix(&repo_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let mut pending_cfg_test = false;
        // Skipping the body of a test-gated item: (brace depth, opening brace seen).
        let mut skipping: Option<(usize, bool)> = None;
        let mut pending_fn: Option<String> = None;
        let mut current_fn: Option<(String, usize)> = None;

        for (line_index, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            // Skip the WHOLE item a test `cfg` gates — `mod`, `impl`, or a bare
            // `fn`. Blanking only `mod` blocks is what let
            // `#[cfg(any(test, feature = "test-support"))] fn rig_nucleus_program`
            // (`crates/workflow/src/dispatcher/mod.rs`) be scanned as production.
            if let Some((depth, seen_open)) = skipping.as_mut() {
                if line.contains('{') {
                    *seen_open = true;
                }
                *depth = update_brace_depth(*depth, line);
                if (*seen_open && *depth == 0) || (!*seen_open && trimmed.ends_with(';')) {
                    skipping = None;
                }
                continue;
            }
            if pending_cfg_test {
                if trimmed.is_empty() || trimmed.starts_with("#[") || trimmed.starts_with("//") {
                    continue;
                }
                pending_cfg_test = false;
                let seen_open = line.contains('{');
                let depth = brace_delta(line);
                if (seen_open && depth == 0) || (!seen_open && trimmed.ends_with(';')) {
                    continue;
                }
                skipping = Some((depth, seen_open));
                continue;
            }
            if trimmed.starts_with("#[cfg(") && cfg_predicate_mentions_test(trimmed) {
                pending_cfg_test = true;
                continue;
            }
            if trimmed.starts_with("//") {
                continue;
            }

            let mut opened_on_this_line = false;
            if current_fn.is_none()
                && pending_fn.is_none()
                && let Some(name) = extract_fn_name(trimmed)
            {
                pending_fn = Some(name);
            }
            if current_fn.is_none()
                && line.contains('{')
                && let Some(name) = pending_fn.take()
            {
                current_fn = Some((name, brace_delta(line)));
                opened_on_this_line = true;
            }

            if let Some((name, _)) = current_fn.as_ref() {
                for surface in COMPILE_SURFACES {
                    // A CALL, not a definition.
                    if trimmed.contains(&format!("{surface}("))
                        && !trimmed.contains(&format!("fn {surface}("))
                    {
                        observed.push((rel.clone(), name.clone(), line_index + 1));
                    }
                }
            }

            if let Some((_, depth)) = current_fn.as_mut() {
                if !opened_on_this_line {
                    *depth = update_brace_depth(*depth, line);
                }
                if *depth == 0 {
                    current_fn = None;
                }
            }
        }
    }
    observed
}

/// THE CLOSED ALLOWLIST. A production site that compiles a pack into an
/// `ExecutionProgram` must be a submit face, an install/migration pin, a
/// read-only preflight, or the compiler's own internals — nothing else. There is no
/// mid-flight class: the subworkflow child spawn, the last compile reached from
/// inside a running execution, spawns the child program its parent's check bound
/// and compiles nothing.
#[test]
fn compile_surfaces_are_reachable_only_from_a_submit_or_install_face() {
    let allowed: std::collections::BTreeSet<(&str, &str)> = COMPILE_SITE_ALLOWLIST
        .iter()
        .map(|(path, function, _)| (*path, *function))
        .collect();
    let findings: Vec<String> = observed_compile_sites()
        .into_iter()
        .filter(|(path, function, _)| !allowed.contains(&(path.as_str(), function.as_str())))
        .map(|(path, function, line)| format!("{path}:{line} in fn {function}"))
        .collect();
    assert!(
        findings.is_empty(),
        "an ExecutionProgram may only be compiled from a submit face, an install/migration pin, a \
         read-only preflight, or the compiler's own internals (a checked program binds \
         complete resolved import/source lineage, so compiling BY NAME from anywhere that already \
         has a run in flight silently substitutes bytes the run's own check never saw). These \
         sites are not on the allowlist — add them WITH a class if they are legitimate, or route \
         them through a persisted pin:\n{}",
        findings.join("\n")
    );
}

/// NON-VACUITY. Every allowlist entry must still name a listed direct compiler call.
///
/// This is the half a forbidden-substring guard can never have: an exemption that
/// outlives the thing it exempts is a lie, and a stale entry silently widens the
/// closed set.
#[test]
fn every_compile_site_allowlist_entry_still_names_a_live_site() {
    let observed: std::collections::BTreeSet<(String, String)> = observed_compile_sites()
        .into_iter()
        .map(|(path, function, _)| (path, function))
        .collect();
    let stale: Vec<String> = COMPILE_SITE_ALLOWLIST
        .iter()
        .filter(|(path, function, _)| {
            !observed.contains(&((*path).to_string(), (*function).to_string()))
        })
        .map(|(path, function, _)| format!("{path} :: {function}"))
        .collect();
    assert!(
        stale.is_empty(),
        "COMPILE_SITE_ALLOWLIST names sites with no listed direct compiler call. A stale exemption \
         silently widens the closed set — delete these entries:\n{}",
        stale.join("\n")
    );
}
