use super::*;
use crate::builtin::{BuiltinTeam, BuiltinTeamRegistry};
use crate::ports::TeamAssistantCatalogEntry;

/// System provisioning resolves manifest references independently of the user's
/// assistant-picker visibility preferences. This catalog is never used by CRUD.
struct BuiltinProvisioningCatalog {
    user_id: String,
    entries: Vec<TeamAssistantCatalogEntry>,
}

#[async_trait::async_trait]
impl TeamAssistantCatalogPort for BuiltinProvisioningCatalog {
    async fn list_team_selectable_assistants(
        &self,
        user_id: &str,
    ) -> Result<Vec<TeamAssistantCatalogEntry>, TeamError> {
        if self.user_id != user_id {
            return Err(TeamError::Forbidden("built-in provisioning owner mismatch".to_owned()));
        }
        Ok(self.entries.clone())
    }
}

impl TeamSessionService {
    /// A fresh installation can materialize teams before any provider exists.
    /// Resolve unset models when the runtime is first requested after setup.
    pub(super) async fn resolve_unset_builtin_models(&self, user_id: &str, team: &mut Team) -> Result<(), TeamError> {
        if !team.is_builtin() {
            return Ok(());
        }
        let mut changed = Vec::new();
        for agent in &mut team.agents {
            if !agent.model.trim().is_empty() {
                continue;
            }
            let Some(model) = self.default_model_for_backend(user_id, &agent.backend).await else {
                continue;
            };
            self.conversation_port
                .initialize_builtin_model(&agent.conversation_id, &model)
                .await?;
            agent.model.clone_from(&model);
            changed.push((agent.slot_id.clone(), model));
        }
        if !changed.is_empty() {
            self.repo
                .update_team(
                    user_id,
                    &team.id,
                    &UpdateTeamParams {
                        agents: Some(serde_json::to_string(&team.agents)?),
                        ..Default::default()
                    },
                )
                .await?;
            if let Some(session) = self.sessions.get(&team.id).map(|entry| Arc::clone(&entry.session)) {
                for (slot_id, model) in &changed {
                    session.update_agent_model(slot_id, model).await?;
                }
            }
            info!(team_id = %team.id, agent_count = changed.len(), "Resolved built-in team models after provider setup");
        }
        Ok(())
    }

    /// Install the startup manifest and enable lazy provisioning for new users.
    pub fn with_builtin_registry(&self, registry: Arc<BuiltinTeamRegistry>) {
        *self.builtin_registry.write().unwrap() = Some(registry);
    }

    /// Materialize enabled definitions once per user, restoring archived teams.
    /// A broken definition is isolated so it cannot prevent startup or listing.
    pub async fn materialize_builtin_teams(
        &self,
        user_id: &str,
        registry: &BuiltinTeamRegistry,
    ) -> Result<(), TeamError> {
        let lock = self
            .builtin_materialization_locks
            .entry(user_id.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;
        let started = std::time::Instant::now();
        let mut created_or_restored = 0;
        let mut skipped = 0;
        let mut failed = 0;
        debug!(user_id, definitions = registry.len(), "Materializing built-in teams");
        for definition in registry.all() {
            if !definition.default_enabled {
                skipped += 1;
                continue;
            }
            match self.materialize_builtin_team(user_id, definition).await {
                Ok(true) => created_or_restored += 1,
                Ok(false) => skipped += 1,
                Err(error) => {
                    failed += 1;
                    warn!(user_id, source_ref = %definition.id, error = %error, "Skipping built-in team that could not be materialized");
                }
            }
        }
        if created_or_restored > 0 || failed > 0 {
            info!(
                user_id,
                created_or_restored,
                skipped,
                failed,
                elapsed_ms = started.elapsed().as_millis(),
                "Built-in team materialization completed"
            );
        }
        Ok(())
    }

    async fn materialize_builtin_team(&self, user_id: &str, definition: &BuiltinTeam) -> Result<bool, TeamError> {
        if let Some(row) = self.repo.get_team_by_source_ref(user_id, &definition.id).await? {
            let restored = self.repo.restore_builtin_team(user_id, &row.id).await?;
            if restored {
                info!(team_id = %row.id, source_ref = %definition.id, "Built-in team restored");
                self.broadcast_team_created(user_id, &row.id, &row.name);
            }
            return Ok(restored);
        }

        let mut inputs = definition.agents.clone();
        let mut entries = Vec::with_capacity(inputs.len());
        for input in &mut inputs {
            let assistant_id = input
                .assistant_id
                .as_deref()
                .ok_or_else(|| TeamError::InvalidRequest("built-in member requires assistant_id".to_owned()))?;
            let assistant = self
                .assistant_definition_repo
                .get_by_assistant_id_for_user(user_id, assistant_id)
                .await?
                .filter(|assistant| {
                    assistant.source == "builtin" && assistant.owner_type == "system" && assistant.deleted_at.is_none()
                })
                .ok_or_else(|| TeamError::InvalidRequest(format!("Built-in assistant not found: {assistant_id}")))?;
            let backend =
                spawn_support::resolve_runtime_backend(&self.agent_metadata_repo, user_id, &assistant.agent_id).await?;
            if input.model.trim().is_empty() {
                input.model = if assistant.default_model_mode == "fixed" {
                    assistant.default_model_value.filter(|model| !model.trim().is_empty())
                } else {
                    None
                }
                .or(self.default_model_for_backend(user_id, &backend).await)
                .unwrap_or_default();
            }
            entries.push(TeamAssistantCatalogEntry {
                assistant_id: assistant_id.to_owned(),
                name: assistant.name,
                backend,
                description: assistant.description.unwrap_or_default(),
                skills: Vec::new(),
            });
        }
        let provisioner = TeamAgentProvisioner::new(
            self.repo.clone(),
            self.agent_metadata_repo.clone(),
            Arc::new(BuiltinProvisioningCatalog {
                user_id: user_id.to_owned(),
                entries,
            }),
            self.provider_repo.clone(),
            self.conversation_port.clone(),
            self.capability_port.clone(),
        );
        let team_id = generate_id();
        info!(team_id, source_ref = %definition.id, "Creating built-in team");
        let provisioned = provisioner
            .provision_initial_agents(user_id, &team_id, &inputs, None)
            .await?;
        let now = now_ms();
        let persist_result = async {
            let (project_id, folder_id) = self
                .resolve_binding_best_effort(user_id, &provisioned.team_workspace)
                .await;
            let row = TeamRow {
                id: team_id.clone(),
                user_id: user_id.to_owned(),
                source: "builtin".to_owned(),
                source_ref: Some(definition.id.clone()),
                name: definition.name.clone(),
                workspace: provisioned.team_workspace.clone(),
                workspace_mode: definition.workspace_mode.clone(),
                agents: serde_json::to_string(&provisioned.agents)?,
                lead_agent_id: provisioned.lead_agent_id.clone(),
                session_mode: None,
                agents_version: "1.0.1".to_owned(),
                created_at: now,
                updated_at: now,
                project_id,
                folder_id,
            };
            self.repo.create_team(&row).await?;
            Ok::<(), TeamError>(())
        }
        .await;
        if let Err(error) = persist_result {
            self.provisioner()
                .cleanup_initial_agents(user_id, &provisioned.agents)
                .await;
            return Err(error);
        }
        info!(team_id, source_ref = %definition.id, "Built-in team created");
        self.broadcast_team_created(user_id, &team_id, &definition.name);
        Ok(true)
    }

    /// Verify ownership first so read-only errors cannot disclose foreign teams.
    pub(super) async fn ensure_team_mutable(
        &self,
        user_id: &str,
        team_id: &str,
        operation: &'static str,
    ) -> Result<Team, TeamError> {
        let team = self.load_owned_team(user_id, team_id).await?;
        if team.is_builtin() {
            warn!(team_id, operation, "Rejected modification of built-in team");
            return Err(TeamError::BuiltinTeamImmutable);
        }
        Ok(team)
    }
}
