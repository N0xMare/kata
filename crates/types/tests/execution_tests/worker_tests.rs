//! Worker inventory wire-shape tests.

use kata_types::worker::{WorkerInventory, WorkerSnapshot};

#[test]
fn worker_snapshot_round_trips_json_shape() {
    let snapshot = WorkerSnapshot {
        id: "embedded-0".to_string(),
        transport: "in_process".to_string(),
        capabilities: vec!["agent:codex".to_string(), "shell".to_string()],
        alive: true,
        active_assignment_count: 2,
    };

    let json = serde_json::to_value(&snapshot).unwrap();
    assert_eq!(json["id"], "embedded-0");
    assert_eq!(json["transport"], "in_process");
    assert_eq!(
        json["capabilities"],
        serde_json::json!(["agent:codex", "shell"])
    );
    assert_eq!(json["alive"], true);
    assert_eq!(json["active_assignment_count"], 2);

    let decoded: WorkerSnapshot = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, snapshot);
}

#[test]
fn worker_inventory_is_a_json_array() {
    let inventory: WorkerInventory = vec![WorkerSnapshot {
        id: "w1".to_string(),
        transport: "local_socket".to_string(),
        capabilities: vec![],
        alive: false,
        active_assignment_count: 0,
    }];

    let json = serde_json::to_value(&inventory).unwrap();
    assert!(json.is_array(), "{json:?}");
    assert_eq!(json[0]["id"], "w1");
}
