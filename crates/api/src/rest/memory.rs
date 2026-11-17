//! Native memory/context endpoints.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use kata_core::store::MemoryObjectQuery;
use kata_types::memory::{
    MemoryObjectKind, MemoryObjectStatus, MemoryProposal, MemoryProposalResponse, MemoryScope,
    MemorySnapshot,
};
use serde::Deserialize;

use super::err_json;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/memory",
            get(get_memory_snapshot).post(post_memory_proposal),
        )
        .route("/memory/{id}", get(get_memory_object))
}

#[derive(Debug, Deserialize)]
struct MemorySnapshotQuery {
    kind: Option<String>,
    kinds: Option<String>,
    status: Option<String>,
    statuses: Option<String>,
    query: Option<String>,
    limit: Option<u32>,
    /// Optional read-scope restriction. `scope_tier` is
    /// `global` | `project` | `workflow`; `project`/`workflow` require the
    /// respective component params. Absent = flat read (operator plane =
    /// full visibility, entitled at `Global`).
    scope_tier: Option<String>,
    scope_project: Option<String>,
    scope_workflow: Option<String>,
}

async fn get_memory_snapshot(
    State(state): State<AppState>,
    Query(query): Query<MemorySnapshotQuery>,
) -> impl IntoResponse {
    let Some(store) = state.memory_store.as_ref() else {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "native memory store unavailable",
        );
    };
    let kinds = match parse_kind_filters(query.kind.as_deref(), query.kinds.as_deref()) {
        Ok(kinds) => kinds,
        Err(error) => return err_json(StatusCode::BAD_REQUEST, error),
    };
    let statuses = match parse_status_filters(query.status.as_deref(), query.statuses.as_deref()) {
        Ok(statuses) => statuses,
        Err(error) => return err_json(StatusCode::BAD_REQUEST, error),
    };
    let limit = match parse_limit(query.limit) {
        Ok(limit) => limit,
        Err(error) => return err_json(StatusCode::BAD_REQUEST, error),
    };
    let text_query = match parse_text_query(query.query.as_deref()) {
        Ok(query) => query,
        Err(error) => return err_json(StatusCode::BAD_REQUEST, error),
    };
    let scope_window = match parse_scope_window(
        query.scope_tier.as_deref(),
        query.scope_project.as_deref(),
        query.scope_workflow.as_deref(),
    ) {
        Ok(window) => window,
        Err(error) => return err_json(StatusCode::BAD_REQUEST, error),
    };

    match store.snapshot_query(MemoryObjectQuery {
        kinds,
        statuses,
        query: text_query,
        limit,
        // `None` (no `scope_tier`) = flat operator
        // read; a supplied tier restricts the read to that base scope's window.
        scope_window,
    }) {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn post_memory_proposal(
    State(state): State<AppState>,
    Json(proposal): Json<MemoryProposal>,
) -> impl IntoResponse {
    let Some(store) = state.memory_store.as_ref() else {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "native memory store unavailable",
        );
    };

    match store.apply_proposal(proposal) {
        Ok(response) => memory_response(response).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn get_memory_object(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Some(store) = state.memory_store.as_ref() else {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "native memory store unavailable",
        );
    };

    match store.get(&id) {
        Ok(Some(object)) => Json(object).into_response(),
        Ok(None) => err_json(StatusCode::NOT_FOUND, format!("unknown memory object {id}")),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

fn parse_kind_filters(
    kind: Option<&str>,
    kinds: Option<&str>,
) -> Result<Vec<MemoryObjectKind>, String> {
    if kind.is_some() && kinds.is_some() {
        return Err("use either `kind` or `kinds`, not both".to_string());
    }
    parse_filter_list("memory kind", kind.or(kinds), MemoryObjectKind::parse)
}

fn parse_status_filters(
    status: Option<&str>,
    statuses: Option<&str>,
) -> Result<Vec<MemoryObjectStatus>, String> {
    if status.is_some() && statuses.is_some() {
        return Err("use either `status` or `statuses`, not both".to_string());
    }
    parse_filter_list(
        "memory status",
        status.or(statuses),
        MemoryObjectStatus::parse,
    )
}

fn parse_filter_list<T>(
    label: &str,
    value: Option<&str>,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Vec<T>, String>
where
    T: Copy + Eq,
{
    let Some(raw) = value else {
        return Ok(Vec::new());
    };
    let mut parsed = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err(format!("{label} filter cannot contain an empty value"));
        }
        let value = parse(token).ok_or_else(|| format!("unknown {label} {token:?}"))?;
        if !parsed.contains(&value) {
            parsed.push(value);
        }
    }
    Ok(parsed)
}

fn parse_limit(limit: Option<u32>) -> Result<Option<u32>, String> {
    match limit {
        Some(0) => Err("memory snapshot limit must be greater than zero".to_string()),
        Some(limit) if limit > 1000 => {
            Err("memory snapshot limit must be less than or equal to 1000".to_string())
        }
        other => Ok(other),
    }
}

/// Build the read-scope visibility window from the `scope_*` query params.
///
/// `None` tier → `Ok(None)` (flat read). A tier yields the base scope's
/// `ancestors_inclusive()` window (the scope + its strict ancestors), so a
/// `workflow` read sees its workflow + project + global objects but no sibling
/// workflow. `project`/`workflow` require their component params.
fn parse_scope_window(
    tier: Option<&str>,
    project: Option<&str>,
    workflow: Option<&str>,
) -> Result<Option<Vec<MemoryScope>>, String> {
    let Some(tier) = tier.map(str::trim).filter(|tier| !tier.is_empty()) else {
        return Ok(None);
    };
    let base = match tier {
        "global" => MemoryScope::Global,
        "project" => {
            let project = project
                .map(str::trim)
                .filter(|project| !project.is_empty())
                .ok_or("scope_tier=project requires a non-empty scope_project")?;
            MemoryScope::Project {
                project: project.to_string(),
            }
        }
        "workflow" => {
            let project = project
                .map(str::trim)
                .filter(|project| !project.is_empty())
                .ok_or("scope_tier=workflow requires a non-empty scope_project")?;
            let workflow = workflow
                .map(str::trim)
                .filter(|workflow| !workflow.is_empty())
                .ok_or("scope_tier=workflow requires a non-empty scope_workflow")?;
            MemoryScope::Workflow {
                project: project.to_string(),
                workflow: workflow.to_string(),
            }
        }
        other => {
            return Err(format!(
                "unknown scope_tier {other:?} (expected global, project, or workflow)"
            ));
        }
    };
    Ok(Some(base.ancestors_inclusive()))
}

fn parse_text_query(query: Option<&str>) -> Result<Option<String>, String> {
    const MAX_QUERY_CHARS: usize = 256;
    let Some(query) = query else {
        return Ok(None);
    };
    let query = query.trim();
    if query.is_empty() {
        return Ok(None);
    }
    if query.chars().count() > MAX_QUERY_CHARS {
        return Err(format!("query must be <= {MAX_QUERY_CHARS} characters"));
    }
    Ok(Some(query.to_string()))
}

fn memory_response(response: MemoryProposalResponse) -> impl IntoResponse {
    let status = if response.conflict.is_some() {
        StatusCode::CONFLICT
    } else {
        StatusCode::OK
    };
    (status, Json(response))
}

const _: fn(MemorySnapshot) = {
    fn f(_: MemorySnapshot) {}
    f
};

#[cfg(test)]
mod scope_window_tests {
    use super::parse_scope_window;
    use kata_types::memory::MemoryScope;

    #[test]
    fn absent_tier_is_flat_read() {
        assert_eq!(parse_scope_window(None, None, None).unwrap(), None);
    }

    #[test]
    fn workflow_tier_builds_ancestor_window() {
        let window = parse_scope_window(Some("workflow"), Some("p"), Some("w1"))
            .unwrap()
            .expect("workflow tier yields a window");
        assert_eq!(
            window,
            MemoryScope::Workflow {
                project: "p".into(),
                workflow: "w1".into(),
            }
            .ancestors_inclusive(),
            "the window is the workflow's own scope plus its strict ancestors"
        );
        // The sibling workflow is NOT in the window — the isolation the store
        // enforces when this window is supplied.
        assert!(!window.contains(&MemoryScope::Workflow {
            project: "p".into(),
            workflow: "w2".into(),
        }));
    }

    #[test]
    fn project_tier_requires_project_component() {
        assert!(parse_scope_window(Some("project"), None, None).is_err());
    }

    #[test]
    fn unknown_tier_is_rejected() {
        assert!(parse_scope_window(Some("galaxy"), None, None).is_err());
    }
}
