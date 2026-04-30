// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! 1Password auth backend.
//!
//! Shells out to the `op` CLI to fetch OAuth credentials directly from
//! 1Password instead of reading them from local files. The `op` CLI handles
//! authentication mode selection transparently:
//!   - `OP_SERVICE_ACCOUNT_TOKEN` set → headless service-account mode
//!   - otherwise → desktop-app integration (Touch ID prompt on first use)
//!
//! Activated by setting `GOOGLE_WORKSPACE_CLI_OP_ITEM`. Optionally pair with
//! `GOOGLE_WORKSPACE_CLI_OP_VAULT` when the item ref is bare.

use std::sync::Mutex;

use anyhow::{anyhow, Context};
use serde::Deserialize;
use serde_json::{json, Value};

/// Reference to a 1Password item.
///
/// Two forms are accepted:
/// - Secret-reference URI: `op://VaultName/ItemNameOrId` (vault embedded).
/// - Bare item id/name paired with a `vault` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpRef {
    pub vault: Option<String>,
    pub item: String,
}

impl OpRef {
    /// Parse an `OpRef` from the values of `GOOGLE_WORKSPACE_CLI_OP_ITEM` and
    /// optionally `GOOGLE_WORKSPACE_CLI_OP_VAULT`.
    pub fn parse(item_env: &str, vault_env: Option<&str>) -> anyhow::Result<Self> {
        let item_env = item_env.trim();
        if item_env.is_empty() {
            anyhow::bail!("GOOGLE_WORKSPACE_CLI_OP_ITEM is empty");
        }

        if let Some(rest) = item_env.strip_prefix("op://") {
            let mut parts = rest.splitn(3, '/');
            let vault = parts
                .next()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("Invalid op:// reference '{item_env}': missing vault"))?;
            let item = parts
                .next()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("Invalid op:// reference '{item_env}': missing item"))?;
            // A trailing /field segment is allowed but ignored — we always pull
            // the whole item and pick fields by label.
            if let Some(env_vault) = vault_env.map(str::trim).filter(|v| !v.is_empty()) {
                if env_vault != vault {
                    eprintln!(
                        "Warning: GOOGLE_WORKSPACE_CLI_OP_VAULT='{env_vault}' is ignored because \
                         GOOGLE_WORKSPACE_CLI_OP_ITEM is a full op:// reference with vault='{vault}'."
                    );
                }
            }
            return Ok(OpRef {
                vault: Some(vault.to_string()),
                item: item.to_string(),
            });
        }

        let vault = vault_env.map(str::trim).filter(|s| !s.is_empty());
        if vault.is_none() {
            anyhow::bail!(
                "GOOGLE_WORKSPACE_CLI_OP_ITEM='{item_env}' is a bare reference, but \
                 GOOGLE_WORKSPACE_CLI_OP_VAULT is not set. \
                 Either include the vault (op://VAULT/{item_env}) or set OP_VAULT."
            );
        }

        Ok(OpRef {
            vault: vault.map(str::to_string),
            item: item_env.to_string(),
        })
    }

    /// Build the `op item get` argv (without the leading `op` binary).
    fn op_get_args(&self) -> Vec<String> {
        let mut args = vec![
            "item".to_string(),
            "get".to_string(),
            self.item.clone(),
            "--format".to_string(),
            "json".to_string(),
        ];
        if let Some(v) = &self.vault {
            args.push("--vault".to_string());
            args.push(v.clone());
        }
        args
    }
}

/// Fields extracted from a 1Password item.
///
/// All fields are optional at this layer — `to_credential_json` enforces the
/// real requirements (either OAuth triple or `service_account_json`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OpItemFields {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    /// Full service account key JSON, in one field. Mutually exclusive with the OAuth triple.
    pub service_account_json: Option<String>,
    /// User email, informational.
    pub account: Option<String>,
    /// GCP project id, used for quota/billing header.
    pub project_id: Option<String>,
    /// The 1Password item title — used for status/export display only.
    pub item_title: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpField {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpItem {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    fields: Vec<OpField>,
}

/// Parse the output of `op item get <ref> --format json` into `OpItemFields`.
///
/// Field matching is case-insensitive against the field's `label` and falls
/// back to its `id`. Empty values are treated as absent.
pub(crate) fn parse_op_item_json(stdout: &str) -> anyhow::Result<OpItemFields> {
    let item: OpItem = serde_json::from_str(stdout)
        .context("Failed to parse `op item get --format json` output")?;

    let mut fields = OpItemFields {
        item_title: item.title,
        ..Default::default()
    };

    for f in &item.fields {
        let key = f
            .label
            .as_deref()
            .or(f.id.as_deref())
            .unwrap_or("")
            .to_ascii_lowercase();
        let value = f.value.as_deref().unwrap_or("");
        if value.is_empty() {
            continue;
        }
        match key.as_str() {
            "client_id" | "clientid" => fields.client_id = Some(value.to_string()),
            "client_secret" | "clientsecret" => fields.client_secret = Some(value.to_string()),
            "refresh_token" | "refreshtoken" => fields.refresh_token = Some(value.to_string()),
            "service_account_json" | "service_account" | "service_account_key" | "sa_json" => {
                fields.service_account_json = Some(value.to_string());
            }
            "account" | "email" => fields.account = Some(value.to_string()),
            "project_id" | "projectid" | "project" => {
                fields.project_id = Some(value.to_string());
            }
            _ => {}
        }
    }

    Ok(fields)
}

/// Convert fetched fields into the JSON shape that `auth::parse_credential_file` accepts.
///
/// - If `service_account_json` is set, returns it verbatim (already valid SA JSON).
/// - Else requires `client_id`, `client_secret`, `refresh_token` and emits an
///   `authorized_user` blob.
/// - Else returns an error listing the missing fields.
pub fn fields_to_credential_json(f: &OpItemFields) -> anyhow::Result<String> {
    if let Some(sa) = &f.service_account_json {
        // Sanity check: must parse as JSON with type=service_account.
        let parsed: Value = serde_json::from_str(sa).context(
            "1Password field 'service_account_json' is not valid JSON. \
             Paste the entire service-account key file contents into this field.",
        )?;
        if parsed.get("type").and_then(Value::as_str) != Some("service_account") {
            anyhow::bail!(
                "1Password field 'service_account_json' must be a service-account key \
                 (with \"type\":\"service_account\")."
            );
        }
        return Ok(sa.clone());
    }

    let mut missing: Vec<&str> = Vec::new();
    if f.client_id.is_none() {
        missing.push("client_id");
    }
    if f.client_secret.is_none() {
        missing.push("client_secret");
    }
    if f.refresh_token.is_none() {
        missing.push("refresh_token");
    }
    if !missing.is_empty() {
        anyhow::bail!(
            "1Password item is missing required fields: {}. \
             Required: client_id, client_secret, refresh_token (OR a single service_account_json field).",
            missing.join(", ")
        );
    }

    let blob = json!({
        "type": "authorized_user",
        "client_id": f.client_id.as_deref().unwrap(),
        "client_secret": f.client_secret.as_deref().unwrap(),
        "refresh_token": f.refresh_token.as_deref().unwrap(),
    });
    Ok(serde_json::to_string(&blob)
        .expect("authorized_user JSON is fixed-shape and serializes infallibly"))
}

// ── Process-wide cache ──────────────────────────────────────────────

/// Cache the fetched fields so `get_token` and `get_quota_project` don't shell
/// out twice within one CLI invocation. We `clone()` on read; the field set is
/// small, so the indirection of `Arc` would be overkill.
static CACHED: Mutex<Option<OpItemFields>> = Mutex::new(None);

/// Returns a clone of the cached fields if `fetch_item` ran this process.
pub fn cached_fields() -> Option<OpItemFields> {
    CACHED.lock().unwrap().clone()
}

#[cfg(test)]
pub fn reset_cache_for_test() {
    *CACHED.lock().unwrap() = None;
}

// ── Subprocess + test seam ──────────────────────────────────────────

/// Captured output of an `op` CLI invocation.
#[derive(Debug, Clone)]
pub struct OpOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub spawn_error: Option<String>,
}

impl OpOutput {
    fn success(&self) -> bool {
        self.status == Some(0) && self.spawn_error.is_none()
    }
}

type OpRunner = Box<
    dyn for<'a> Fn(
            &'a [String],
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = OpOutput> + Send + 'a>>
        + Send
        + Sync,
>;

static OP_RUNNER: Mutex<Option<OpRunner>> = Mutex::new(None);

/// Install a stub runner for tests. The closure receives the argv (without the
/// leading `op` binary) and returns canned output.
#[cfg(test)]
pub fn set_op_runner_for_test<F>(runner: F)
where
    F: Fn(&[String]) -> OpOutput + Send + Sync + 'static,
{
    let boxed: OpRunner = Box::new(move |args| {
        let out = runner(args);
        Box::pin(async move { out })
    });
    *OP_RUNNER.lock().unwrap() = Some(boxed);
}

#[cfg(test)]
pub fn clear_op_runner_for_test() {
    *OP_RUNNER.lock().unwrap() = None;
}

/// Run the `op` CLI with the given args. Falls back to spawning the real binary
/// when no test runner is installed.
async fn run_op(args: &[String]) -> OpOutput {
    // Construct the future under the lock, then drop the guard before awaiting
    // — guards aren't `Send` and would taint the surrounding async block.
    let stub_future = {
        let guard = OP_RUNNER.lock().unwrap();
        guard.as_ref().map(|runner| runner(args))
    };
    if let Some(fut) = stub_future {
        return fut.await;
    }

    let result = tokio::process::Command::new("op").args(args).output().await;

    match result {
        Ok(out) => OpOutput {
            status: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            spawn_error: None,
        },
        Err(e) => OpOutput {
            status: None,
            stdout: String::new(),
            stderr: String::new(),
            spawn_error: Some(format!("{e}")),
        },
    }
}

/// Translate a failed `op` invocation into a user-friendly error message.
fn translate_op_error(args: &[String], output: &OpOutput) -> anyhow::Error {
    if let Some(err) = &output.spawn_error {
        if err.contains("No such file") || err.contains("not found") {
            return anyhow!(
                "1Password CLI ('op') not found in PATH. \
                 Install: https://developer.1password.com/docs/cli/get-started"
            );
        }
        return anyhow!("Failed to spawn `op`: {err}");
    }

    let stderr = output.stderr.trim();
    let stderr_lc = stderr.to_lowercase();

    if stderr_lc.contains("connect to 1password.app")
        || stderr_lc.contains("not currently signed in")
        || stderr_lc.contains("connecting to desktop app")
        || stderr_lc.contains("1password app is not running")
    {
        return anyhow!(
            "1Password desktop app is not running or signed in. \
             Open 1Password, or set OP_SERVICE_ACCOUNT_TOKEN for headless mode.\n\
             op stderr: {stderr}"
        );
    }

    if stderr_lc.contains("service account token") || stderr_lc.contains("unauthorized") {
        return anyhow!(
            "1Password service account auth failed (OP_SERVICE_ACCOUNT_TOKEN may be invalid or revoked).\n\
             op stderr: {stderr}"
        );
    }

    if stderr_lc.contains("isn't a vault") || stderr_lc.contains("vault doesn't exist") {
        return anyhow!(
            "1Password vault not found. Check GOOGLE_WORKSPACE_CLI_OP_VAULT or the vault embedded in the op:// reference.\n\
             op stderr: {stderr}"
        );
    }

    if stderr_lc.contains("isn't an item")
        || stderr_lc.contains("no item found")
        || stderr_lc.contains("not found")
    {
        return anyhow!(
            "1Password item '{}' not found. Check OP_ITEM/OP_VAULT.\n\
             op stderr: {stderr}",
            args.get(2).cloned().unwrap_or_default()
        );
    }

    anyhow!(
        "`op {}` failed with exit code {:?}: {stderr}",
        args.join(" "),
        output.status
    )
}

/// Fetch an item from 1Password, parse fields, and populate the process-wide cache.
pub async fn fetch_item(op_ref: &OpRef) -> anyhow::Result<OpItemFields> {
    if let Some(cached) = CACHED.lock().unwrap().clone() {
        return Ok(cached);
    }
    let args = op_ref.op_get_args();
    let output = run_op(&args).await;
    if !output.success() {
        return Err(translate_op_error(&args, &output));
    }
    let fields = parse_op_item_json(&output.stdout)?;
    *CACHED.lock().unwrap() = Some(fields.clone());
    Ok(fields)
}

// ── Write path: create or update a 1Password item ──────────────────

/// Write OAuth credentials into a 1Password item. Creates the item if it does
/// not exist; updates it if `overwrite` is true; errors otherwise.
pub async fn put_item(
    op_ref: &OpRef,
    fields: &OpItemFields,
    overwrite: bool,
) -> anyhow::Result<String> {
    let exists = item_exists(op_ref).await?;
    if exists && !overwrite {
        anyhow::bail!(
            "1Password item '{}' already exists. Pass --force to overwrite.",
            op_ref.item
        );
    }

    let assignments = build_field_assignments(fields);
    if assignments.is_empty() {
        anyhow::bail!("No fields to write — refusing to create an empty 1Password item.");
    }

    if exists {
        let mut args = vec!["item".to_string(), "edit".to_string(), op_ref.item.clone()];
        if let Some(v) = &op_ref.vault {
            args.push("--vault".to_string());
            args.push(v.clone());
        }
        args.push("--format".to_string());
        args.push("json".to_string());
        for a in &assignments {
            args.push(a.clone());
        }
        let output = run_op(&args).await;
        if !output.success() {
            return Err(translate_op_error(&args, &output));
        }
        Ok(op_ref.item.clone())
    } else {
        let mut args = vec![
            "item".to_string(),
            "create".to_string(),
            "--category".to_string(),
            "API Credential".to_string(),
            "--title".to_string(),
            op_ref.item.clone(),
        ];
        if let Some(v) = &op_ref.vault {
            args.push("--vault".to_string());
            args.push(v.clone());
        }
        args.push("--format".to_string());
        args.push("json".to_string());
        for a in &assignments {
            args.push(a.clone());
        }
        let output = run_op(&args).await;
        if !output.success() {
            return Err(translate_op_error(&args, &output));
        }
        // Stdout is the JSON of the newly-created item; extract the title for display.
        let created: OpItem = serde_json::from_str(&output.stdout).unwrap_or(OpItem {
            title: Some(op_ref.item.clone()),
            fields: Vec::new(),
        });
        Ok(created.title.unwrap_or_else(|| op_ref.item.clone()))
    }
}

fn build_field_assignments(f: &OpItemFields) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(v) = &f.client_id {
        out.push(format!("client_id[text]={v}"));
    }
    if let Some(v) = &f.client_secret {
        out.push(format!("client_secret[concealed]={v}"));
    }
    if let Some(v) = &f.refresh_token {
        out.push(format!("refresh_token[concealed]={v}"));
    }
    if let Some(v) = &f.account {
        out.push(format!("account[text]={v}"));
    }
    if let Some(v) = &f.project_id {
        out.push(format!("project_id[text]={v}"));
    }
    if let Some(v) = &f.service_account_json {
        out.push(format!("service_account_json[concealed]={v}"));
    }
    out
}

async fn item_exists(op_ref: &OpRef) -> anyhow::Result<bool> {
    let args = op_ref.op_get_args();
    let output = run_op(&args).await;
    if output.success() {
        return Ok(true);
    }
    if let Some(err) = &output.spawn_error {
        // Distinguish missing `op` from a missing item.
        if err.contains("No such file") || err.contains("not found") {
            return Err(anyhow!(
                "1Password CLI ('op') not found in PATH. \
                 Install: https://developer.1password.com/docs/cli/get-started"
            ));
        }
    }
    let stderr_lc = output.stderr.to_lowercase();
    if stderr_lc.contains("isn't an item")
        || stderr_lc.contains("no item found")
        || stderr_lc.contains("not found")
    {
        return Ok(false);
    }
    // Some other failure (auth, vault not found, etc.) — surface it.
    Err(translate_op_error(&args, &output))
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_oauth_item() -> &'static str {
        r#"{
            "id": "abc123",
            "title": "GWS CLI (Uptown)",
            "vault": {"id": "v1", "name": "LLC"},
            "category": "API_CREDENTIAL",
            "fields": [
                {"id": "username", "type": "STRING", "label": "client_id", "value": "611-uptown.apps.googleusercontent.com"},
                {"id": "credential", "type": "CONCEALED", "label": "client_secret", "value": "GOCSPX-secret"},
                {"id": "refresh_token", "type": "CONCEALED", "label": "refresh_token", "value": "1//rt-value"},
                {"id": "account", "type": "STRING", "label": "account", "value": "zachb@uptowngroupstpaul.com"},
                {"id": "project_id", "type": "STRING", "label": "project_id", "value": "znetstar-llc-automation"}
            ]
        }"#
    }

    fn sample_sa_item() -> &'static str {
        r#"{
            "id": "abc",
            "title": "Service Account",
            "fields": [
                {"id": "key", "type": "CONCEALED", "label": "service_account_json", "value": "{\"type\":\"service_account\",\"project_id\":\"sa-project\",\"private_key_id\":\"k\",\"private_key\":\"PEM\",\"client_email\":\"sa@p.iam.gserviceaccount.com\",\"client_id\":\"123\",\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"token_uri\":\"https://oauth2.googleapis.com/token\"}"}
            ]
        }"#
    }

    #[test]
    fn op_ref_parse_uri_form() {
        let r = OpRef::parse("op://LLC/jqdyd123", None).unwrap();
        assert_eq!(r.vault.as_deref(), Some("LLC"));
        assert_eq!(r.item, "jqdyd123");
    }

    #[test]
    fn op_ref_parse_uri_with_field_segment_ignored() {
        let r = OpRef::parse("op://LLC/jqdyd123/refresh_token", None).unwrap();
        assert_eq!(r.vault.as_deref(), Some("LLC"));
        assert_eq!(r.item, "jqdyd123");
    }

    #[test]
    fn op_ref_parse_bare_with_vault() {
        let r = OpRef::parse("jqdyd123", Some("LLC")).unwrap();
        assert_eq!(r.vault.as_deref(), Some("LLC"));
        assert_eq!(r.item, "jqdyd123");
    }

    #[test]
    fn op_ref_parse_bare_without_vault_errors() {
        let err = OpRef::parse("jqdyd123", None).unwrap_err();
        assert!(err.to_string().contains("OP_VAULT"), "{err}");
    }

    #[test]
    fn op_ref_parse_empty_errors() {
        assert!(OpRef::parse("", Some("LLC")).is_err());
        assert!(OpRef::parse("   ", Some("LLC")).is_err());
    }

    #[test]
    fn op_ref_parse_uri_missing_item_errors() {
        assert!(OpRef::parse("op://LLC", None).is_err());
        assert!(OpRef::parse("op://LLC/", None).is_err());
    }

    #[test]
    fn op_ref_op_get_args() {
        let r = OpRef::parse("op://LLC/jqdyd123", None).unwrap();
        let args = r.op_get_args();
        assert_eq!(
            args,
            vec!["item", "get", "jqdyd123", "--format", "json", "--vault", "LLC"]
        );
    }

    #[test]
    fn parse_op_item_json_oauth_happy() {
        let f = parse_op_item_json(sample_oauth_item()).unwrap();
        assert_eq!(
            f.client_id.as_deref(),
            Some("611-uptown.apps.googleusercontent.com")
        );
        assert_eq!(f.client_secret.as_deref(), Some("GOCSPX-secret"));
        assert_eq!(f.refresh_token.as_deref(), Some("1//rt-value"));
        assert_eq!(f.account.as_deref(), Some("zachb@uptowngroupstpaul.com"));
        assert_eq!(f.project_id.as_deref(), Some("znetstar-llc-automation"));
        assert_eq!(f.item_title.as_deref(), Some("GWS CLI (Uptown)"));
        assert!(f.service_account_json.is_none());
    }

    #[test]
    fn parse_op_item_json_case_insensitive_labels() {
        let json = r#"{
            "title": "X",
            "fields": [
                {"label": "Client_ID", "value": "id"},
                {"label": "ClientSecret", "value": "sec"},
                {"label": "Refresh_Token", "value": "rt"}
            ]
        }"#;
        let f = parse_op_item_json(json).unwrap();
        assert_eq!(f.client_id.as_deref(), Some("id"));
        assert_eq!(f.client_secret.as_deref(), Some("sec"));
        assert_eq!(f.refresh_token.as_deref(), Some("rt"));
    }

    #[test]
    fn parse_op_item_json_empty_values_ignored() {
        let json = r#"{
            "title": "X",
            "fields": [
                {"label": "client_id", "value": ""},
                {"label": "client_secret"}
            ]
        }"#;
        let f = parse_op_item_json(json).unwrap();
        assert!(f.client_id.is_none());
        assert!(f.client_secret.is_none());
    }

    #[test]
    fn parse_op_item_json_falls_back_to_id_when_label_missing() {
        let json = r#"{
            "title": "X",
            "fields": [
                {"id": "client_id", "value": "id_val"},
                {"id": "client_secret", "value": "secret_val"}
            ]
        }"#;
        let f = parse_op_item_json(json).unwrap();
        assert_eq!(f.client_id.as_deref(), Some("id_val"));
        assert_eq!(f.client_secret.as_deref(), Some("secret_val"));
    }

    #[test]
    fn parse_op_item_json_malformed_errors() {
        assert!(parse_op_item_json("not json").is_err());
    }

    #[test]
    fn fields_to_credential_json_oauth_happy() {
        let f = OpItemFields {
            client_id: Some("cid".into()),
            client_secret: Some("csec".into()),
            refresh_token: Some("rt".into()),
            ..Default::default()
        };
        let json = fields_to_credential_json(&f).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v.get("type").and_then(Value::as_str),
            Some("authorized_user")
        );
        assert_eq!(v.get("client_id").and_then(Value::as_str), Some("cid"));
        assert_eq!(v.get("client_secret").and_then(Value::as_str), Some("csec"));
        assert_eq!(v.get("refresh_token").and_then(Value::as_str), Some("rt"));
    }

    #[test]
    fn fields_to_credential_json_missing_fields_lists_them() {
        let f = OpItemFields {
            client_id: Some("cid".into()),
            ..Default::default()
        };
        let err = fields_to_credential_json(&f).unwrap_err().to_string();
        // The error names the missing fields in a `missing required fields: …`
        // segment; client_id was provided so it must not appear there.
        let missing_segment = err
            .split_once("missing required fields: ")
            .and_then(|(_, rest)| rest.split_once('.'))
            .map(|(seg, _)| seg)
            .unwrap_or("");
        assert!(missing_segment.contains("client_secret"), "{err}");
        assert!(missing_segment.contains("refresh_token"), "{err}");
        assert!(
            !missing_segment.contains("client_id"),
            "provided field should not be listed as missing: {missing_segment}"
        );
    }

    #[test]
    fn fields_to_credential_json_service_account_passthrough() {
        let f = parse_op_item_json(sample_sa_item()).unwrap();
        let json = fields_to_credential_json(&f).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v.get("type").and_then(Value::as_str),
            Some("service_account")
        );
        assert_eq!(
            v.get("client_email").and_then(Value::as_str),
            Some("sa@p.iam.gserviceaccount.com")
        );
    }

    #[test]
    fn fields_to_credential_json_invalid_sa_json_errors() {
        let f = OpItemFields {
            service_account_json: Some("not json".into()),
            ..Default::default()
        };
        assert!(fields_to_credential_json(&f).is_err());
    }

    #[test]
    fn fields_to_credential_json_sa_wrong_type_errors() {
        let f = OpItemFields {
            service_account_json: Some(r#"{"type":"authorized_user"}"#.into()),
            ..Default::default()
        };
        let err = fields_to_credential_json(&f).unwrap_err().to_string();
        assert!(err.contains("service_account"), "{err}");
    }

    #[test]
    fn build_field_assignments_oauth() {
        let f = OpItemFields {
            client_id: Some("cid".into()),
            client_secret: Some("csec".into()),
            refresh_token: Some("rt".into()),
            account: Some("a@b.com".into()),
            project_id: Some("pid".into()),
            ..Default::default()
        };
        let a = build_field_assignments(&f);
        assert!(a.contains(&"client_id[text]=cid".to_string()));
        assert!(a.contains(&"client_secret[concealed]=csec".to_string()));
        assert!(a.contains(&"refresh_token[concealed]=rt".to_string()));
        assert!(a.contains(&"account[text]=a@b.com".to_string()));
        assert!(a.contains(&"project_id[text]=pid".to_string()));
    }

    #[test]
    fn translate_op_error_op_not_installed() {
        let out = OpOutput {
            status: None,
            stdout: String::new(),
            stderr: String::new(),
            spawn_error: Some("No such file or directory (os error 2)".to_string()),
        };
        let err = translate_op_error(&[], &out).to_string();
        assert!(err.contains("not found in PATH"), "{err}");
        assert!(err.contains("https://developer.1password.com"), "{err}");
    }

    #[test]
    fn translate_op_error_desktop_not_running() {
        let out = OpOutput {
            status: Some(1),
            stdout: String::new(),
            stderr: "could not connect to 1Password.app".to_string(),
            spawn_error: None,
        };
        let err = translate_op_error(&[], &out).to_string();
        assert!(err.contains("desktop app is not running"), "{err}");
        assert!(err.contains("OP_SERVICE_ACCOUNT_TOKEN"), "{err}");
    }

    #[test]
    fn translate_op_error_item_not_found() {
        let out = OpOutput {
            status: Some(1),
            stdout: String::new(),
            stderr: "\"x\" isn't an item.".to_string(),
            spawn_error: None,
        };
        let err = translate_op_error(
            &["item".to_string(), "get".to_string(), "x".to_string()],
            &out,
        )
        .to_string();
        assert!(err.contains("not found"), "{err}");
        assert!(err.contains("'x'"), "{err}");
    }

    #[test]
    fn translate_op_error_service_token_invalid() {
        let out = OpOutput {
            status: Some(1),
            stdout: String::new(),
            stderr: "service account token is not authorized".to_string(),
            spawn_error: None,
        };
        let err = translate_op_error(&[], &out).to_string();
        assert!(err.contains("service account"), "{err}");
    }

    #[test]
    fn translate_op_error_vault_not_found() {
        let out = OpOutput {
            status: Some(1),
            stdout: String::new(),
            stderr: "[ERROR] \"BadVault\" isn't a vault in this account.".to_string(),
            spawn_error: None,
        };
        let err = translate_op_error(&[], &out).to_string();
        assert!(err.contains("vault not found"), "{err}");
        assert!(err.contains("OP_VAULT"), "{err}");
    }
}
