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

use super::Helper;
use crate::auth;
use crate::error::GwsError;
use crate::executor;
use clap::{Arg, ArgMatches, Command};
use serde_json::{json, Value};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;

pub struct DriveHelper;

impl Helper for DriveHelper {
    fn inject_commands(
        &self,
        mut cmd: Command,
        _doc: &crate::discovery::RestDescription,
    ) -> Command {
        cmd = cmd.subcommand(
            Command::new("+upload")
                .about("[Helper] Upload a file with automatic metadata")
                .arg(
                    Arg::new("file")
                        .help("Path to file to upload")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("parent")
                        .long("parent")
                        .help("Parent folder ID")
                        .value_name("ID"),
                )
                .arg(
                    Arg::new("name")
                        .long("name")
                        .help("Target filename (defaults to source filename)")
                        .value_name("NAME"),
                )
                .arg(
                    Arg::new("convert")
                        .long("convert")
                        .help(
                            "Convert Office files to Google native formats on upload (.docx \
                             → Doc, .xlsx → Sheet, .pptx → Slides). No-op for other extensions.",
                        )
                        .action(clap::ArgAction::SetTrue),
                )
                .after_help(
                    "\
EXAMPLES:
  gws drive +upload ./report.pdf
  gws drive +upload ./report.pdf --parent FOLDER_ID
  gws drive +upload ./data.csv --name 'Sales Data.csv'
  gws drive +upload ./report.docx --convert  # uploads as a Google Doc

TIPS:
  MIME type is detected automatically.
  Filename is inferred from the local path unless --name is given.
  --convert maps .docx → Google Doc, .xlsx → Google Sheet, .pptx → Google Slides.",
                ),
        );
        cmd
    }

    fn handle<'a>(
        &'a self,
        doc: &'a crate::discovery::RestDescription,
        matches: &'a ArgMatches,
        _sanitize_config: &'a crate::helpers::modelarmor::SanitizeConfig,
    ) -> Pin<Box<dyn Future<Output = Result<bool, GwsError>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(matches) = matches.subcommand_matches("+upload") {
                let file_path = matches.get_one::<String>("file").unwrap();
                let parent_id = matches.get_one::<String>("parent");
                let name_arg = matches.get_one::<String>("name");
                let convert = matches.get_flag("convert");

                // Determine filename
                let filename = determine_filename(file_path, name_arg.map(|s| s.as_str()))?;

                // Find method: files.create
                let files_res = doc
                    .resources
                    .get("files")
                    .ok_or_else(|| GwsError::Discovery("Resource 'files' not found".to_string()))?;
                let create_method = files_res.methods.get("create").ok_or_else(|| {
                    GwsError::Discovery("Method 'files.create' not found".to_string())
                })?;

                // Build metadata
                let target_mime = if convert {
                    google_mime_for_path(file_path)
                } else {
                    None
                };
                let metadata =
                    build_metadata(&filename, parent_id.map(|s| s.as_str()), target_mime);

                let body_str = metadata.to_string();

                let scopes: Vec<&str> = create_method.scopes.iter().map(|s| s.as_str()).collect();
                let (token, auth_method) = match auth::get_token(&scopes).await {
                    Ok(t) => (Some(t), executor::AuthMethod::OAuth),
                    Err(_) if matches.get_flag("dry-run") => (None, executor::AuthMethod::None),
                    Err(e) => return Err(GwsError::Auth(format!("Drive auth failed: {e}"))),
                };

                executor::execute_method(
                    doc,
                    create_method,
                    None,
                    Some(&body_str),
                    token.as_deref(),
                    auth_method,
                    None,
                    Some(executor::UploadSource::File {
                        path: file_path,
                        content_type: None,
                    }),
                    matches.get_flag("dry-run"),
                    &executor::PaginationConfig::default(),
                    None,
                    &crate::helpers::modelarmor::SanitizeMode::Warn,
                    &crate::formatter::OutputFormat::default(),
                    false,
                )
                .await?;

                return Ok(true);
            }
            Ok(false)
        })
    }
}

fn determine_filename(file_path: &str, name_arg: Option<&str>) -> Result<String, GwsError> {
    if let Some(n) = name_arg {
        Ok(n.to_string())
    } else {
        Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
            .ok_or_else(|| GwsError::Validation("Invalid file path".to_string()))
    }
}

fn build_metadata(filename: &str, parent_id: Option<&str>, target_mime: Option<&str>) -> Value {
    let mut metadata = json!({
        "name": filename
    });

    if let Some(parent) = parent_id {
        metadata["parents"] = json!([parent]);
    }

    if let Some(mime) = target_mime {
        metadata["mimeType"] = json!(mime);
    }

    metadata
}

/// Maps an Office file extension to its Google native target mimeType for
/// Drive's on-upload conversion. Returns `None` for unsupported extensions
/// (so `--convert` becomes a no-op rather than an error).
fn google_mime_for_path(path: &str) -> Option<&'static str> {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())?
        .to_ascii_lowercase();
    match ext.as_str() {
        "docx" => Some("application/vnd.google-apps.document"),
        "xlsx" => Some("application/vnd.google-apps.spreadsheet"),
        "pptx" => Some("application/vnd.google-apps.presentation"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_filename_explicit() {
        assert_eq!(
            determine_filename("path/to/file.txt", Some("custom.txt")).unwrap(),
            "custom.txt"
        );
    }

    #[test]
    fn test_determine_filename_from_path() {
        assert_eq!(
            determine_filename("path/to/file.txt", None).unwrap(),
            "file.txt"
        );
    }

    #[test]
    fn test_determine_filename_invalid_path() {
        assert!(determine_filename("", None).is_err());
        assert!(determine_filename("/", None).is_err()); // Root has no filename component usually
    }

    #[test]
    fn test_build_metadata_no_parent() {
        let meta = build_metadata("file.txt", None, None);
        assert_eq!(meta["name"], "file.txt");
        assert!(meta.get("parents").is_none());
        assert!(meta.get("mimeType").is_none());
    }

    #[test]
    fn test_build_metadata_with_parent() {
        let meta = build_metadata("file.txt", Some("folder123"), None);
        assert_eq!(meta["name"], "file.txt");
        assert_eq!(meta["parents"][0], "folder123");
        assert!(meta.get("mimeType").is_none());
    }

    #[test]
    fn test_build_metadata_with_target_mime() {
        let meta = build_metadata(
            "report.docx",
            None,
            Some("application/vnd.google-apps.document"),
        );
        assert_eq!(meta["name"], "report.docx");
        assert_eq!(meta["mimeType"], "application/vnd.google-apps.document");
    }

    #[test]
    fn test_google_mime_for_path_docx() {
        assert_eq!(
            google_mime_for_path("/tmp/report.docx"),
            Some("application/vnd.google-apps.document")
        );
    }

    #[test]
    fn test_google_mime_for_path_xlsx() {
        assert_eq!(
            google_mime_for_path("./data.xlsx"),
            Some("application/vnd.google-apps.spreadsheet")
        );
    }

    #[test]
    fn test_google_mime_for_path_pptx() {
        assert_eq!(
            google_mime_for_path("deck.pptx"),
            Some("application/vnd.google-apps.presentation")
        );
    }

    #[test]
    fn test_google_mime_for_path_uppercase_extension() {
        assert_eq!(
            google_mime_for_path("REPORT.DOCX"),
            Some("application/vnd.google-apps.document")
        );
    }

    #[test]
    fn test_google_mime_for_path_unsupported() {
        assert_eq!(google_mime_for_path("notes.txt"), None);
        assert_eq!(google_mime_for_path("photo.png"), None);
        assert_eq!(google_mime_for_path("archive.zip"), None);
    }

    #[test]
    fn test_google_mime_for_path_no_extension() {
        assert_eq!(google_mime_for_path("README"), None);
        assert_eq!(google_mime_for_path(""), None);
    }
}
