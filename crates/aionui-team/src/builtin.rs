//! Compiled-in team manifests, with an optional fixture-directory override.

use std::collections::HashMap;
use std::path::PathBuf;

use aionui_api_types::TeamAgentInput;
use include_dir::{Dir, include_dir};
use serde::Deserialize;
use tracing::warn;

static BUILTIN_TEAM_ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../aionui-app/assets/builtin-teams");

#[derive(Debug, Clone, Deserialize)]
pub struct BuiltinTeam {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub name_i18n: HashMap<String, String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub description_i18n: HashMap<String, String>,
    #[serde(default = "shared_workspace")]
    pub workspace_mode: String,
    pub agents: Vec<TeamAgentInput>,
    #[serde(default)]
    pub sort_order: i32,
    #[serde(default)]
    pub default_enabled: bool,
}

fn shared_workspace() -> String {
    "shared".to_owned()
}

impl BuiltinTeam {
    fn validate(&self) -> Result<(), &'static str> {
        if self.id.trim().is_empty() || self.name.trim().is_empty() {
            return Err("team id and name must not be empty");
        }
        if self.workspace_mode != "shared" {
            return Err("only shared workspaces are supported");
        }
        let mut leaders = 0;
        for agent in &self.agents {
            if agent.name.trim().is_empty()
                || agent.assistant_id.as_deref().is_none_or(|id| id.trim().is_empty())
                || agent.conversation_id.as_deref().is_some_and(|id| !id.trim().is_empty())
            {
                return Err("members require a name and assistant_id and must not reuse conversations");
            }
            match agent.role.trim() {
                "lead" | "leader" => leaders += 1,
                "teammate" => {}
                _ => return Err("member role must be lead, leader or teammate"),
            }
        }
        if leaders != 1 {
            return Err("exactly one team agent must have role lead");
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct BuiltinTeamRegistry {
    teams: HashMap<String, BuiltinTeam>,
}

impl BuiltinTeamRegistry {
    pub fn load() -> Self {
        if let Some(path) = std::env::var_os("AIONUI_BUILTIN_TEAMS_PATH") {
            let path = PathBuf::from(path);
            if path.exists() {
                return Self::load_from_dir(path);
            }
            warn!("AIONUI_BUILTIN_TEAMS_PATH does not exist; using embedded teams");
        }
        Self::load_embedded()
    }

    pub fn load_embedded() -> Self {
        match BUILTIN_TEAM_ASSETS.get_file("teams.json") {
            Some(file) => Self::parse(file.contents()),
            None => {
                warn!("Embedded built-in team manifest is missing");
                Self::empty()
            }
        }
    }

    pub fn load_from_dir(path: PathBuf) -> Self {
        match std::fs::read(path.join("teams.json")) {
            Ok(bytes) => Self::parse(&bytes),
            Err(error) => {
                warn!(error = %error, "Could not read built-in team manifest");
                Self::empty()
            }
        }
    }

    fn parse(bytes: &[u8]) -> Self {
        #[derive(Deserialize)]
        struct Manifest {
            teams: Vec<serde_json::Value>,
        }
        let manifest = match serde_json::from_slice::<Manifest>(bytes) {
            Ok(manifest) => manifest,
            Err(error) => {
                warn!(error = %error, "Invalid built-in team manifest");
                return Self::empty();
            }
        };
        let mut teams = HashMap::new();
        for entry in manifest.teams {
            let team = match serde_json::from_value::<BuiltinTeam>(entry) {
                Ok(team) => team,
                Err(error) => {
                    warn!(error = %error, "Skipping malformed built-in team");
                    continue;
                }
            };
            if let Err(reason) = team.validate() {
                warn!(source_ref = %team.id, reason, "Skipping invalid built-in team");
                continue;
            }
            if teams.contains_key(&team.id) {
                warn!(source_ref = %team.id, "Skipping duplicate built-in team id");
                continue;
            }
            teams.insert(team.id.clone(), team);
        }
        Self { teams }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn has(&self, id: &str) -> bool {
        self.teams.contains_key(id)
    }

    pub fn get(&self, id: &str) -> Option<&BuiltinTeam> {
        self.teams.get(id)
    }

    pub fn all(&self) -> Vec<&BuiltinTeam> {
        let mut teams: Vec<_> = self.teams.values().collect();
        teams.sort_by(|left, right| (left.sort_order, &left.id).cmp(&(right.sort_order, &right.id)));
        teams
    }

    pub fn len(&self) -> usize {
        self.teams.len()
    }

    pub fn is_empty(&self) -> bool {
        self.teams.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn embedded_office_team_has_three_assistants_and_one_leader() {
        let registry = BuiltinTeamRegistry::load_embedded();
        let team = registry.get("builtin-office-suite").unwrap();
        assert!(team.default_enabled);
        assert_eq!(team.workspace_mode, "shared");
        assert_eq!(team.agents.len(), 3);
        assert_eq!(team.agents[0].assistant_id.as_deref(), Some("word-creator"));
        assert!(team.validate().is_ok());
    }

    #[test]
    fn malformed_entries_do_not_hide_valid_teams_and_order_is_stable() {
        let valid = json!({"id": "b", "name": "B", "agents": [
            {"assistant_id": "word-creator", "name": "Word", "role": "lead", "model": ""}
        ]});
        let mut first = valid.clone();
        first["id"] = json!("a");
        let mut isolated = valid.clone();
        isolated["id"] = json!("isolated");
        isolated["workspace_mode"] = json!("isolated");
        let mut no_leader = valid.clone();
        no_leader["agents"][0]["role"] = json!("teammate");
        let bytes = serde_json::to_vec(&json!({"teams": [
            {}, isolated, no_leader, valid.clone(), valid, first
        ]}))
        .unwrap();
        let registry = BuiltinTeamRegistry::parse(&bytes);
        assert_eq!(
            registry.all().iter().map(|team| team.id.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn invalid_and_empty_disk_manifests_are_safe() {
        let dir = tempfile::tempdir().unwrap();
        assert!(BuiltinTeamRegistry::load_from_dir(dir.path().to_owned()).is_empty());
        std::fs::write(dir.path().join("teams.json"), "not json").unwrap();
        assert!(BuiltinTeamRegistry::load_from_dir(dir.path().to_owned()).is_empty());
        std::fs::write(dir.path().join("teams.json"), r#"{"teams":[]}"#).unwrap();
        assert!(BuiltinTeamRegistry::load_from_dir(dir.path().to_owned()).is_empty());
    }
}
