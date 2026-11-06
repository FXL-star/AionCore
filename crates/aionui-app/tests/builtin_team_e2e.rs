mod common;

use aionui_app::{AppConfig, AppServices, build_module_states, create_router_with_states};
use aionui_db::{ISidebarStore, ITeamRepository, SqliteSidebarStore, SqliteTeamRepository};
use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;

use common::{body_json, get_request, get_with_token, json_with_token, setup_and_login};

#[tokio::test]
async fn builtin_office_team_bootstraps_restores_and_rejects_configuration_writes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("aionui_team=info,aionui_conversation=warn")
        .with_test_writer()
        .try_init();
    let tmp = tempfile::tempdir().unwrap();
    let config = AppConfig {
        data_dir: tmp.path().to_path_buf(),
        work_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    let db = aionui_db::init_database_memory().await.unwrap();
    let services = AppServices::from_config(db, &config).await.unwrap();
    let mut events = services.event_bus.subscribe();
    let started = std::time::Instant::now();
    let (states, _) = build_module_states(&services).await.unwrap();
    let repo = SqliteTeamRepository::new(services.database.pool().clone());
    let row = repo
        .get_team_by_source_ref("system_default_user", "builtin-office-suite")
        .await
        .unwrap()
        .expect("fresh startup must materialize the embedded office team without enabled assistants or providers");
    eprintln!("fresh builtin startup: {} ms", started.elapsed().as_millis());
    assert_eq!(row.source, "builtin");
    let agents: Vec<serde_json::Value> = serde_json::from_str(&row.agents).unwrap();
    assert_eq!(agents.len(), 3);
    assert_eq!(agents.iter().filter(|a| a["role"] == "lead").count(), 1);
    let mut references = agents
        .iter()
        .map(|a| a["assistant_id"].as_str().unwrap())
        .collect::<Vec<_>>();
    references.sort_unstable();
    assert_eq!(references, ["excel-creator", "ppt-creator", "word-creator"]);
    let mut created = 0;
    while let Ok(event) = events.try_recv() {
        if event.name == "team.created" {
            assert_eq!(event.data["user_id"], "system_default_user");
            assert_eq!(event.data["team_id"], row.id);
            created += 1;
        }
    }
    assert_eq!(created, 1);

    let service = states.team.service.clone();
    let sidebar = SqliteSidebarStore::new(services.database.pool().clone());
    sidebar
        .set_team_archived("system_default_user", &row.id, Some(100))
        .await
        .unwrap();
    let restored = service.list_teams("system_default_user").await.unwrap();
    assert_eq!(restored.iter().filter(|t| t.is_builtin).count(), 1);
    assert_eq!(restored[0].id, row.id);
    let active_members: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conversations WHERE json_extract(extra, '$.teamId') = ? AND archived_at IS NULL",
    )
    .bind(&row.id)
    .fetch_one(services.database.pool())
    .await
    .unwrap();
    assert_eq!(active_members, 3);
    service.list_teams("system_default_user").await.unwrap();
    let after = repo.get_team("system_default_user", &row.id).await.unwrap().unwrap();
    assert_eq!(after.agents, row.agents);

    let mut app = create_router_with_states(&services, states);
    let (token, csrf) = setup_and_login(&mut app, &services, "admin", "StrongP@ss1").await;
    let slot = agents[0]["slot_id"].as_str().unwrap();
    let conversation = agents[0]["conversation_id"].as_str().unwrap();
    let team_path = format!("/api/teams/{}", row.id);
    let no_csrf = axum::http::Request::builder()
        .method("DELETE")
        .uri(&team_path)
        .header("authorization", format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.clone().oneshot(no_csrf).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(body_json(response).await.to_string().contains("CSRF_INVALID"));
    while events.try_recv().is_ok() {}
    for (method, path, body) in [
        ("DELETE", team_path.clone(), json!({})),
        ("PATCH", format!("{team_path}/name"), json!({"name": "Changed"})),
        (
            "POST",
            format!("{team_path}/agents"),
            json!({"name": "New", "role": "teammate", "assistant_id": "word-creator", "model": ""}),
        ),
        ("DELETE", format!("{team_path}/agents/{slot}"), json!({})),
        (
            "PATCH",
            format!("{team_path}/agents/{slot}/name"),
            json!({"name": "Changed"}),
        ),
        (
            "PATCH",
            format!("{team_path}/agents/{slot}/model"),
            json!({"model_id": "changed"}),
        ),
        ("POST", format!("/api/sidebar/team/{}/archive", row.id), json!({})),
        (
            "POST",
            format!("/api/sidebar/conversation/{conversation}/archive"),
            json!({}),
        ),
        ("DELETE", format!("/api/conversations/{conversation}"), json!({})),
        (
            "PATCH",
            format!("/api/conversations/{conversation}"),
            json!({"model": {"provider_id": "provider", "model": "changed"}}),
        ),
        (
            "PATCH",
            format!("/api/conversations/{conversation}"),
            json!({"extra": {"teamId": null}}),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(json_with_token(method, &path, body, &token, &csrf))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
        let body = body_json(response).await;
        assert!(body.to_string().contains("BUILTIN_TEAM_IMMUTABLE"), "{path}: {body}");
    }
    let response = app.clone().oneshot(get_with_token(&team_path, &token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["data"]["is_builtin"], true);
    while let Ok(event) = events.try_recv() {
        assert_ne!(event.name, "team.removed");
    }
    let response = app.clone().oneshot(get_request("/api/teams")).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let (other_token, other_csrf) = setup_and_login(&mut app, &services, "other", "StrongP@ss2").await;
    let response = app
        .clone()
        .oneshot(json_with_token(
            "DELETE",
            &team_path,
            json!({}),
            &other_token,
            &other_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = app.oneshot(get_with_token("/api/teams", &other_token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let other = body_json(response).await;
    assert!(
        other["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["is_builtin"] == true && t["id"] != row.id)
    );
    assert_eq!(
        repo.get_team("system_default_user", &row.id)
            .await
            .unwrap()
            .unwrap()
            .agents,
        row.agents
    );
}
