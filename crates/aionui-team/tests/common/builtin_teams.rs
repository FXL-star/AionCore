//! Team bootstrap and mutation tests using the real SQLite team repository.
use super::*;
use aionui_db::{SqliteProviderRepository, SqliteTeamRepository};
use aionui_team::BuiltinTeamRegistry;

struct Fixture {
    service: Arc<TeamSessionService>,
    repo: Arc<SqliteTeamRepository>,
    ports: Arc<FakeConversationPorts>,
    conversations: Arc<MockConversationRepo>,
    events: Arc<RecordingBroadcaster>,
    providers: Arc<SqliteProviderRepository>,
}

async fn fixture(pool: &sqlx::SqlitePool) -> Fixture {
    for user in ["user1", "user2"] {
        sqlx::query("INSERT INTO users (id, user_type, username, password_hash, status, session_generation, created_at, updated_at) VALUES (?, 'local', ?, 'hash', 'active', 0, 1, 1)")
            .bind(user).bind(user).execute(pool).await.unwrap();
    }
    let repo = Arc::new(SqliteTeamRepository::new(pool.clone()));
    let conversations = Arc::new(MockConversationRepo::new());
    let ports = Arc::new(FakeConversationPorts::new(conversations.clone()));
    let events = Arc::new(RecordingBroadcaster::new());
    let providers = Arc::new(SqliteProviderRepository::new(pool.clone()));
    let definitions = ["word-creator", "ppt-creator", "excel-creator"]
        .into_iter()
        .map(|id| {
            let mut row = word_creator_definition();
            row.id = format!("def-{id}");
            row.assistant_id = id.to_owned();
            row.source_ref = Some(id.to_owned());
            row.agent_id = "aionrs".to_owned();
            row
        })
        .collect();
    let service = TeamSessionService::new_with_capability_port(
        repo.clone(),
        Arc::new(StubAgentMetadataRepo::empty()),
        // Built-in materialization must work even when the picker is empty.
        Arc::new(EmptyTeamAssistantCatalog),
        Arc::new(PairAssistantDefinitionRepo { rows: definitions }),
        Arc::new(EmptyAssistantOverlayRepo),
        providers.clone(),
        ports.clone(),
        ports.clone(),
        events.clone(),
        Arc::new(CountingTaskManager::new(success_factory())),
        noop_turn_port(),
        noop_cancellation_port(),
        Arc::new(TestTeamToolCapabilityPort),
        Arc::new(std::path::PathBuf::from("/tmp/aioncore-test")),
    );
    Fixture {
        service,
        repo,
        ports,
        conversations,
        events,
        providers,
    }
}

#[tokio::test]
async fn materialization_is_concurrently_idempotent_user_scoped_and_restores_archives() {
    let db = aionui_db::init_database_memory().await.unwrap();
    let fx = fixture(db.pool()).await;
    let registry = Arc::new(BuiltinTeamRegistry::load_embedded());
    fx.service.with_builtin_registry(registry.clone());
    let (left, right) = tokio::join!(fx.service.list_teams("user1"), fx.service.list_teams("user1"));
    let left = left.unwrap();
    let right = right.unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].id, right[0].id);
    assert!(left[0].is_builtin);
    assert_eq!(left[0].assistants.len(), 3);
    assert_eq!(
        left[0].assistants.iter().filter(|agent| agent.role == "lead").count(),
        1
    );
    assert_eq!(fx.conversations.conversations.lock().unwrap().len(), 3);
    let events = fx.events.events_by_name("team.created");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data["user_id"], "user1");
    let row = fx.repo.get_team("user1", &left[0].id).await.unwrap().unwrap();
    assert_eq!(row.source, "builtin");
    assert_eq!(row.source_ref.as_deref(), Some("builtin-office-suite"));
    sqlx::query("UPDATE teams SET archived_at = 123 WHERE id = ?")
        .bind(&row.id)
        .execute(db.pool())
        .await
        .unwrap();
    fx.service.materialize_builtin_teams("user1", &registry).await.unwrap();
    let archived: Option<i64> = sqlx::query_scalar("SELECT archived_at FROM teams WHERE id = ?")
        .bind(&row.id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(archived, None);
    assert_eq!(fx.events.events_by_name("team.created").len(), 2);
    let other = fx.service.list_teams("user2").await.unwrap();
    assert_eq!(other.len(), 1);
    assert_ne!(other[0].id, row.id);
    assert_eq!(fx.conversations.conversations.lock().unwrap().len(), 6);
}

fn assert_read_only(error: TeamError) {
    assert!(
        matches!(error, TeamError::BuiltinTeamImmutable),
        "unexpected error: {error:?}"
    );
    let api: aionui_common::ApiError = error.into();
    assert!(
        matches!(api, aionui_common::ApiError::Coded { status, code: "BUILTIN_TEAM_IMMUTABLE", .. } if status == axum::http::StatusCode::FORBIDDEN)
    );
}

#[tokio::test]
async fn all_explicit_mutations_are_rejected_without_changes_or_events() {
    let db = aionui_db::init_database_memory().await.unwrap();
    let fx = fixture(db.pool()).await;
    fx.service
        .materialize_builtin_teams("user1", &BuiltinTeamRegistry::load_embedded())
        .await
        .unwrap();
    let team = fx.service.list_teams("user1").await.unwrap().remove(0);
    let agent = &team.assistants[1];
    let row = fx.repo.get_team("user1", &team.id).await.unwrap().unwrap();
    fx.events.clear();
    assert_read_only(fx.service.remove_team("user1", &team.id).await.unwrap_err());
    assert_read_only(fx.service.rename_team("user1", &team.id, "changed").await.unwrap_err());
    assert_read_only(
        fx.service
            .add_agent(
                "user1",
                &team.id,
                AddAgentRequest {
                    name: "extra".into(),
                    role: "teammate".into(),
                    backend: None,
                    model: String::new(),
                    assistant_id: Some("word-creator".into()),
                },
            )
            .await
            .unwrap_err(),
    );
    assert_read_only(
        fx.service
            .remove_agent("user1", &team.id, &agent.slot_id)
            .await
            .unwrap_err(),
    );
    assert_read_only(
        fx.service
            .rename_agent("user1", &team.id, &agent.slot_id, "changed")
            .await
            .unwrap_err(),
    );
    assert_read_only(
        fx.service
            .update_agent_model("user1", &team.id, &agent.slot_id, "changed")
            .await
            .unwrap_err(),
    );
    assert_read_only(
        fx.service
            .set_session_mode("user1", &team.id, "changed")
            .await
            .unwrap_err(),
    );
    assert_read_only(
        fx.service
            .set_conversation_config_option(
                "user1",
                &team.id,
                &agent.conversation_id,
                "model",
                SetConfigOptionRequest {
                    value: "changed".into(),
                },
            )
            .await
            .unwrap_err(),
    );
    let after = fx.repo.get_team("user1", &team.id).await.unwrap().unwrap();
    assert_eq!(serde_json::to_value(row).unwrap(), serde_json::to_value(after).unwrap());
    assert_eq!(fx.conversations.conversations.lock().unwrap().len(), 3);
    assert!(fx.events.events.lock().unwrap().is_empty());
    assert!(
        matches!(fx.service.remove_team("user2", &team.id).await, Err(TeamError::TeamNotFound(id)) if id == team.id)
    );
    assert!(
        matches!(fx.service.rename_team("user1", "missing", "x").await, Err(TeamError::TeamNotFound(id)) if id == "missing")
    );
    fx.service.ensure_session("user1", &team.id).await.unwrap();
    assert_read_only(
        fx.service
            .spawn_agent_in_session(
                &team.id,
                team.leader_assistant_id.as_deref().unwrap(),
                SpawnAgentRequest {
                    name: "spawned".into(),
                    assistant_id: Some("word-creator".into()),
                },
            )
            .await
            .unwrap_err(),
    );
    assert_eq!(fx.conversations.conversations.lock().unwrap().len(), 3);
    fx.service.dispose_all();
    let custom = fx
        .service
        .create_team(
            "user1",
            CreateTeamRequest {
                name: "custom".into(),
                agents: aionrs_two_agent_input(),
                workspace: None,
            },
        )
        .await
        .unwrap();
    assert!(!custom.is_builtin);
    fx.service.rename_team("user1", &custom.id, "renamed").await.unwrap();
    fx.service
        .remove_agent("user1", &custom.id, &custom.assistants[1].slot_id)
        .await
        .unwrap();
    fx.service.remove_team("user1", &custom.id).await.unwrap();
}

#[tokio::test]
async fn failed_member_creation_rolls_back_and_retries_cleanly() {
    let db = aionui_db::init_database_memory().await.unwrap();
    let fx = fixture(db.pool()).await;
    fx.ports.fail_create_at.store(2, Ordering::SeqCst);
    let registry = BuiltinTeamRegistry::load_embedded();
    fx.service.materialize_builtin_teams("user1", &registry).await.unwrap();
    assert!(fx.repo.list_teams_by_user("user1").await.unwrap().is_empty());
    assert!(fx.conversations.conversations.lock().unwrap().is_empty());
    assert!(fx.events.events_by_name("team.created").is_empty());
    fx.ports.fail_create_at.store(0, Ordering::SeqCst);
    fx.service.materialize_builtin_teams("user1", &registry).await.unwrap();
    assert_eq!(fx.repo.list_teams_by_user("user1").await.unwrap().len(), 1);
    assert_eq!(fx.conversations.conversations.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn provider_configured_after_bootstrap_supplies_models_at_session_start() {
    let db = aionui_db::init_database_memory().await.unwrap();
    let fx = fixture(db.pool()).await;
    fx.service
        .materialize_builtin_teams("user1", &BuiltinTeamRegistry::load_embedded())
        .await
        .unwrap();
    let team = fx.service.list_teams("user1").await.unwrap().remove(0);
    assert!(team.assistants.iter().all(|agent| agent.model.is_empty()));
    fx.providers
        .create(aionui_db::CreateProviderParams {
            id: Some("late-provider"),
            user_id: "user1",
            platform: "openai",
            name: "late",
            base_url: "http://localhost",
            api_key_encrypted: "fixture",
            models: r#"["late-model"]"#,
            enabled: true,
            capabilities: "[]",
            context_limit: None,
            model_protocols: None,
            model_enabled: None,
            model_health: None,
            model_settings: "{}",
            bedrock_config: None,
            is_full_url: false,
        })
        .await
        .unwrap();
    fx.service.ensure_session("user1", &team.id).await.unwrap();
    let resolved = fx.service.get_team("user1", &team.id).await.unwrap();
    assert!(resolved.assistants.iter().all(|agent| agent.model == "late-model"));
    for agent in &resolved.assistants {
        assert_eq!(
            fx.conversations.get_extra(&agent.conversation_id).unwrap()["current_model_id"],
            "late-model"
        );
    }
    fx.service.dispose_all();
}
