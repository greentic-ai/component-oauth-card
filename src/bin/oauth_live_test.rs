use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const DEFAULT_REPO_URL: &str = "https://github.com/greenticai/events-provider-codex";
const DEFAULT_GITHUB_API_BASE: &str = "https://api.github.com";
const DEFAULT_GITHUB_REF: &str = "main";
const DEFAULT_PACK_FILE: &str = "oauth-github-latest.gtpack";
const DEFAULT_TENANT: &str = "default";
const DEFAULT_TEAM: &str = "default";
const DEFAULT_FLOW_ENV: &str = "dev";
const DEFAULT_PROVIDER: &str = "generic_oidc";
const DEFAULT_RUNTIME_PROVIDER_ID: &str = "oauth-oidc-executable";
const DEFAULT_OAUTH_SCOPES_CSV: &str = "read:user,repo";
const DEFAULT_OIDC_AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const DEFAULT_OIDC_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const DEFAULT_CALLBACK_WAIT_SECONDS: u64 = 180;
const DEFAULT_CALLBACK_POLL_SECONDS: u64 = 2;
const DEFAULT_MANUAL_PROMPT_AFTER_SECONDS: u64 = 20;
const DEFAULT_NGROK_API_URL: &str = "http://127.0.0.1:4040/api/tunnels";
const DEFAULT_NGROK_REQ_API_URL: &str = "http://127.0.0.1:4040/api/requests/http";
const DEFAULT_OAUTH_BROKER_CAP_ID: &str = "greentic.cap.oauth.broker.v1";

#[derive(Debug, Clone)]
struct Config {
    bundle_dir: PathBuf,
    tenant: String,
    team: String,
    flow_env: String,
    provider: String,
    runtime_provider_id: String,
    pack_file: String,
    repo_url: String,
    github_api_base: String,
    github_ref: String,
    oauth_scopes_csv: String,
    skip_setup: bool,
    skip_start: bool,
    auto_apply_setup: bool,
    secrets_mode: String,
    oidc_client_id: String,
    oidc_client_secret: String,
    oidc_client_id_key: String,
    oidc_client_secret_key: String,
    oidc_auth_url: String,
    oidc_token_url: String,
    oidc_public_base_url: String,
    oidc_redirect_path: String,
    oauth_broker_cap_id: String,
    public_web_enabled: bool,
    public_surface_policy: String,
    public_base_url: String,
    ngrok_api_url: String,
    ngrok_req_api_url: String,
    callback_wait_seconds: u64,
    callback_poll_seconds: u64,
    manual_callback_prompt_after_seconds: u64,
    allow_manual_callback_paste: bool,
    oauth_callback_url: String,
    oauth_callback_code: String,
    oauth_callback_state: String,
    start_log: PathBuf,
    run_log: PathBuf,
    auth_ctx_file: PathBuf,
    runner_input_file: PathBuf,
    run_input_file: PathBuf,
    token_resp_file: PathBuf,
    setup_answers_file: PathBuf,
    dev_secrets_path_default: PathBuf,
}

#[derive(Debug)]
struct RuntimeHandle {
    child: Option<Child>,
}

impl Drop for RuntimeHandle {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Debug, Clone, Default)]
struct CallbackData {
    uri: String,
    code: String,
    state: String,
    error: String,
    error_description: String,
}

#[derive(Debug)]
struct RepoParts {
    owner: String,
    repo: String,
}

#[derive(Debug)]
struct CommitData {
    sha: String,
    message: String,
    author: String,
    date: String,
    url: String,
}

fn main() -> Result<()> {
    let cfg = Config::from_env()?;
    run(cfg)
}

fn run(mut cfg: Config) -> Result<()> {
    fs::create_dir_all(cfg.bundle_dir.join("inputs"))
        .with_context(|| format!("create {}", cfg.bundle_dir.join("inputs").display()))?;
    fs::create_dir_all(cfg.bundle_dir.join("logs"))
        .with_context(|| format!("create {}", cfg.bundle_dir.join("logs").display()))?;

    if cfg.oidc_client_id.trim().is_empty() || cfg.oidc_client_secret.trim().is_empty() {
        bail!("set OIDC_CLIENT_ID and OIDC_CLIENT_SECRET for live OAuth");
    }

    let repo = parse_repo_url(&cfg.repo_url)?;

    let runtime = if cfg.skip_start {
        println!("== start operator runtime (skipped) ==");
        RuntimeHandle { child: None }
    } else {
        println!("== start operator runtime ==");
        let child = spawn_runtime(&cfg)?;
        RuntimeHandle { child: Some(child) }
    };
    let _runtime_guard = runtime;

    cfg.oidc_public_base_url = resolve_active_public_url(&cfg)?;
    if cfg.oidc_public_base_url.is_empty() {
        bail!("unable to determine public base URL from runtime state or ngrok API");
    }
    if !is_public_url_reachable(&cfg.oidc_public_base_url) {
        bail!(
            "public base URL appears offline: {}",
            cfg.oidc_public_base_url
        );
    }
    if cfg.public_base_url.trim().is_empty() {
        cfg.public_base_url = cfg.oidc_public_base_url.clone();
    }

    let scopes = parse_scopes(&cfg.oauth_scopes_csv);
    let scopes_space = scopes.join(" ");

    if cfg.auto_apply_setup {
        println!("== apply setup answers (oauth extension) ==");
        apply_setup_answers(&cfg, &scopes)?;
    }

    if cfg.skip_setup {
        println!("== setup oauth extension (skipped) ==");
    } else {
        println!("== setup oauth extension ==");
        run_setup(&cfg)?;
    }

    let state = Uuid::new_v4().as_simple().to_string();
    let code_verifier = build_code_verifier();
    let code_challenge = code_challenge_from_verifier(&code_verifier);

    let initiate_input = json!({
        "tenant": cfg.tenant,
        "state": state,
        "code_challenge": code_challenge,
        "scopes": scopes,
    });
    let initiate_payload = build_runtime_envelope(&cfg, &scopes, initiate_input);
    let initiate_json = capability_invoke_json(&cfg, "oauth.initiate_auth", &initiate_payload)?;

    if !initiate_json
        .get("ok")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!(
            "oauth.initiate_auth failed: {}",
            serde_json::to_string_pretty(&initiate_json).unwrap_or_default()
        );
    }

    let mut authorize_url = initiate_json
        .get("authorize_url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut redirect_uri = initiate_json
        .get("redirect_uri")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let redirect_uri_ingress = format!(
        "{}{}",
        trim_slash(&cfg.oidc_public_base_url),
        cfg.oidc_redirect_path
    );
    let redirect_path_active: String;

    let expected_prefix = format!("{}/v1/", trim_slash(&cfg.oidc_public_base_url));
    if redirect_uri.starts_with(&expected_prefix) {
        redirect_path_active = strip_origin(&redirect_uri);
    } else {
        redirect_uri = redirect_uri_ingress;
        redirect_path_active = cfg.oidc_redirect_path.clone();
        authorize_url = build_authorize_url(
            &cfg.oidc_auth_url,
            &cfg.oidc_client_id,
            &redirect_uri,
            &scopes_space,
            &state,
            &code_challenge,
        );
    }

    if authorize_url.is_empty() || redirect_uri.is_empty() {
        bail!(
            "unable to construct authorize URL / redirect URI from initiate response: {}",
            serde_json::to_string_pretty(&initiate_json).unwrap_or_default()
        );
    }

    write_json_file(
        &cfg.auth_ctx_file,
        &json!({
            "tenant": cfg.tenant,
            "team": cfg.team,
            "provider": cfg.provider,
            "runtime_provider_id": cfg.runtime_provider_id,
            "public_base_url": cfg.oidc_public_base_url,
            "redirect_uri": redirect_uri,
            "redirect_path": redirect_path_active,
            "authorize_url": authorize_url,
            "state": state,
            "code_challenge": code_challenge,
            "code_verifier": code_verifier,
            "scopes": scopes_space,
        }),
    )?;

    println!("== oauth initiate auth (extension callback) ==");
    println!("redirect_uri: {redirect_uri}");
    println!("open this URL and complete auth:");
    println!("{authorize_url}");
    println!();
    println!("waiting for OAuth callback...");

    let callback = wait_for_callback(
        &cfg,
        &state,
        &redirect_path_active,
        Instant::now() + Duration::from_secs(cfg.callback_wait_seconds),
    )?;
    println!("callback captured: {}", callback.uri);

    println!("== exchange code for access token (extension capability) ==");
    let token_input = json!({
        "tenant": cfg.tenant,
        "code": callback.code,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "execute_http": true,
    });
    let token_payload = build_runtime_envelope(&cfg, &scopes, token_input);
    let token_json = capability_invoke_json(&cfg, "oauth.get_access_token", &token_payload)?;
    write_json_file(&cfg.token_resp_file, &token_json)?;

    if !token_json
        .get("ok")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!(
            "oauth.get_access_token failed: {}",
            serde_json::to_string_pretty(&token_json).unwrap_or_default()
        );
    }

    let access_token = token_json
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if access_token.is_empty() {
        bail!(
            "oauth.get_access_token response missing access_token: {}",
            serde_json::to_string_pretty(&token_json).unwrap_or_default()
        );
    }

    println!("== execute latest commit live call ==");
    println!("repo_url: {}", cfg.repo_url);
    let commits_json = fetch_latest_commit(&cfg, &repo.owner, &repo.repo, &access_token)?;
    let commit = first_commit(&commits_json)?;

    write_json_file(
        &cfg.runner_input_file,
        &json!({
            "env": cfg.flow_env,
            "tenant": cfg.tenant,
            "team": cfg.team,
            "provider": cfg.provider,
            "github_repo_url": cfg.repo_url,
            "owner": repo.owner,
            "repo": repo.repo,
        }),
    )?;
    println!("runner input file: {}", cfg.runner_input_file.display());
    print_json_file(&cfg.runner_input_file)?;

    write_json_file(
        &cfg.run_input_file,
        &json!({
            "env": cfg.flow_env,
            "tenant": cfg.tenant,
            "team": cfg.team,
            "provider": cfg.provider,
            "owner": repo.owner,
            "repo": repo.repo,
            "commit_sha": commit.sha,
            "commit_message": commit.message,
            "commit_author": commit.author,
            "commit_date": commit.date,
            "commit_url": commit.url
        }),
    )?;
    println!("run input file: {}", cfg.run_input_file.display());
    print_json_file(&cfg.run_input_file)?;

    println!("== render flow card ==");
    let run_input = fs::read_to_string(&cfg.run_input_file)
        .with_context(|| format!("read {}", cfg.run_input_file.display()))?;
    let output = run_demo_flow(&cfg, &run_input)?;
    fs::write(&cfg.run_log, &output).with_context(|| format!("write {}", cfg.run_log.display()))?;
    print!("{output}");

    println!("== success ==");
    Ok(())
}

impl Config {
    fn from_env() -> Result<Self> {
        let args = std::env::args().collect::<Vec<_>>();
        let cwd = std::env::current_dir().context("resolve current dir")?;
        let bundle_dir_raw = env_string("BUNDLE_DIR", cwd.to_string_lossy().as_ref());
        let bundle_dir = PathBuf::from(bundle_dir_raw);

        let tenant = env_string("TENANT", DEFAULT_TENANT);
        let team = env_string("TEAM", DEFAULT_TEAM);
        let flow_env = env_string("FLOW_ENV", DEFAULT_FLOW_ENV);
        let provider = env_string("PROVIDER", DEFAULT_PROVIDER);
        let runtime_provider_id = env_string("RUNTIME_PROVIDER_ID", DEFAULT_RUNTIME_PROVIDER_ID);

        let default_client_id_key = format!("tenants/{tenant}/oauth/oidc/client_id");
        let default_client_secret_key = format!("tenants/{tenant}/oauth/oidc/client_secret");
        let default_redirect = format!(
            "/v1/oauth/ingress/{}/{}/{}",
            runtime_provider_id, tenant, team
        );

        let mut oidc_client_id = strip_brackets(&env_string("OIDC_CLIENT_ID", ""));
        let mut oidc_client_secret = strip_brackets(&env_string("OIDC_CLIENT_SECRET", ""));
        let mut oidc_client_id_key =
            strip_brackets(&env_string("OIDC_CLIENT_ID_KEY", &default_client_id_key));
        let mut oidc_client_secret_key = strip_brackets(&env_string(
            "OIDC_CLIENT_SECRET_KEY",
            &default_client_secret_key,
        ));

        if oidc_client_id.is_empty() && !oidc_client_id_key.contains('/') {
            oidc_client_id = oidc_client_id_key.clone();
            oidc_client_id_key = default_client_id_key;
        }
        if oidc_client_secret.is_empty() && !oidc_client_secret_key.contains('/') {
            oidc_client_secret = oidc_client_secret_key.clone();
            oidc_client_secret_key = default_client_secret_key;
        }

        let callback_wait_seconds =
            env_u64("CALLBACK_WAIT_SECONDS", DEFAULT_CALLBACK_WAIT_SECONDS)?;
        let callback_poll_seconds =
            env_u64("CALLBACK_POLL_SECONDS", DEFAULT_CALLBACK_POLL_SECONDS)?;
        let manual_callback_prompt_after_seconds = env_u64(
            "MANUAL_CALLBACK_PROMPT_AFTER_SECONDS",
            DEFAULT_MANUAL_PROMPT_AFTER_SECONDS,
        )?;

        let repo_url = args
            .get(1)
            .cloned()
            .or_else(|| std::env::var("GITHUB_REPO_URL").ok())
            .unwrap_or_else(|| DEFAULT_REPO_URL.to_string());

        let oidc_public_base_url = extract_https_url(&env_string("OIDC_PUBLIC_BASE_URL", ""));
        let oidc_redirect_path = env_string("OIDC_REDIRECT_PATH", &default_redirect);

        let mut public_base_url = extract_https_url(&env_string("PUBLIC_BASE_URL", ""));
        if public_base_url.is_empty() {
            public_base_url = oidc_public_base_url.clone();
        }

        let start_log = bundle_dir.join("logs/live_oauth_start.log");
        let run_log = bundle_dir.join("logs/live_oauth_run.log");
        let auth_ctx_file = bundle_dir.join("inputs/oauth.runtime.auth.context.json");
        let runner_input_file = bundle_dir.join("inputs/runner.input.json");
        let run_input_file = bundle_dir.join("inputs/run.input.json");
        let token_resp_file = bundle_dir.join("inputs/oauth.token.response.json");
        let setup_answers_file = bundle_dir.join("setup.answers.json");
        let dev_secrets_path_default = bundle_dir.join(".greentic/dev/.dev.secrets.env");

        Ok(Self {
            bundle_dir,
            tenant,
            team,
            flow_env,
            provider,
            runtime_provider_id,
            pack_file: env_string("PACK_FILE", DEFAULT_PACK_FILE),
            repo_url,
            github_api_base: env_string("GITHUB_API_BASE", DEFAULT_GITHUB_API_BASE),
            github_ref: env_string(
                "GITHUB_REF",
                std::env::var("BRANCH")
                    .unwrap_or_else(|_| DEFAULT_GITHUB_REF.to_string())
                    .as_str(),
            ),
            oauth_scopes_csv: env_string("OAUTH_SCOPES_CSV", DEFAULT_OAUTH_SCOPES_CSV),
            skip_setup: env_bool("SKIP_SETUP", false)?,
            skip_start: env_bool("SKIP_START", false)?,
            auto_apply_setup: env_bool("AUTO_APPLY_SETUP", true)?,
            secrets_mode: env_string("SECRETS_MODE", "self_hosted"),
            oidc_client_id,
            oidc_client_secret,
            oidc_client_id_key,
            oidc_client_secret_key,
            oidc_auth_url: env_string("OIDC_AUTH_URL", DEFAULT_OIDC_AUTH_URL),
            oidc_token_url: env_string("OIDC_TOKEN_URL", DEFAULT_OIDC_TOKEN_URL),
            oidc_public_base_url,
            oidc_redirect_path,
            oauth_broker_cap_id: env_string("OAUTH_BROKER_CAP_ID", DEFAULT_OAUTH_BROKER_CAP_ID),
            public_web_enabled: env_bool("PUBLIC_WEB_ENABLED", true)?,
            public_surface_policy: env_string("PUBLIC_SURFACE_POLICY", "enabled"),
            public_base_url,
            ngrok_api_url: env_string("NGROK_API_URL", DEFAULT_NGROK_API_URL),
            ngrok_req_api_url: env_string("NGROK_REQ_API_URL", DEFAULT_NGROK_REQ_API_URL),
            callback_wait_seconds,
            callback_poll_seconds,
            manual_callback_prompt_after_seconds,
            allow_manual_callback_paste: env_bool("ALLOW_MANUAL_CALLBACK_PASTE", false)?,
            oauth_callback_url: env_string("OAUTH_CALLBACK_URL", ""),
            oauth_callback_code: env_string("OAUTH_CALLBACK_CODE", ""),
            oauth_callback_state: env_string("OAUTH_CALLBACK_STATE", ""),
            start_log,
            run_log,
            auth_ctx_file,
            runner_input_file,
            run_input_file,
            token_resp_file,
            setup_answers_file,
            dev_secrets_path_default,
        })
    }
}

fn env_string(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_bool(name: &str, default: bool) -> Result<bool> {
    let raw = std::env::var(name).unwrap_or_else(|_| {
        if default {
            "true".to_string()
        } else {
            "false".to_string()
        }
    });
    match raw.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => bail!("{name} must be true or false (got {raw})"),
    }
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<u64>()
            .with_context(|| format!("{name} must be an integer (got {raw})")),
        Err(_) => Ok(default),
    }
}

fn strip_brackets(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

fn extract_https_url(raw: &str) -> String {
    raw.split_whitespace()
        .find(|token| token.starts_with("https://"))
        .unwrap_or_default()
        .trim_matches('"')
        .to_string()
}

fn apply_command_env(cfg: &Config, cmd: &mut Command) {
    if cfg.secrets_mode == "self_hosted" {
        cmd.env("GREENTIC_ALLOW_ENV_SECRETS", "0");
        cmd.env(
            "GREENTIC_DEV_SECRETS_PATH",
            std::env::var("GREENTIC_DEV_SECRETS_PATH")
                .unwrap_or_else(|_| cfg.dev_secrets_path_default.to_string_lossy().to_string()),
        );
    } else {
        cmd.env("GREENTIC_ALLOW_ENV_SECRETS", "1");
    }
}

fn run_checked(mut cmd: Command, context: &str) -> Result<OutputText> {
    let output = cmd
        .output()
        .with_context(|| format!("run command for {context}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        bail!("{context} failed\nstdout:\n{stdout}\nstderr:\n{stderr}");
    }
    Ok(OutputText { stdout, stderr })
}

#[derive(Debug)]
struct OutputText {
    stdout: String,
    stderr: String,
}

fn spawn_runtime(cfg: &Config) -> Result<Child> {
    let _ = fs::create_dir_all(cfg.start_log.parent().unwrap_or_else(|| Path::new(".")));
    let start_log = File::create(&cfg.start_log)
        .with_context(|| format!("create {}", cfg.start_log.display()))?;
    let start_log_err = start_log
        .try_clone()
        .with_context(|| format!("clone {}", cfg.start_log.display()))?;

    let mut cmd = Command::new("gtc");
    cmd.arg("op")
        .arg("demo")
        .arg("start")
        .arg("--bundle")
        .arg(&cfg.bundle_dir)
        .arg("--tenant")
        .arg(&cfg.tenant)
        .arg("--team")
        .arg(&cfg.team)
        .arg("--ngrok")
        .arg("on")
        .arg("--cloudflared")
        .arg("off")
        .stdout(Stdio::from(start_log))
        .stderr(Stdio::from(start_log_err));
    apply_command_env(cfg, &mut cmd);

    let mut child = cmd.spawn().context("start operator runtime")?;
    thread::sleep(Duration::from_secs(4));
    if child.try_wait().context("check runtime process")?.is_some() {
        let logs = fs::read_to_string(&cfg.start_log).unwrap_or_default();
        bail!("operator runtime failed to start\n{logs}");
    }
    println!("operator runtime running (pid={})", child.id());
    Ok(child)
}

fn resolve_active_public_url(cfg: &Config) -> Result<String> {
    let mut candidate = cfg.oidc_public_base_url.clone();
    let ngrok = find_ngrok_public_url(cfg).unwrap_or_default();
    let runtime = find_runtime_public_url_file(cfg).unwrap_or_default();

    if candidate.is_empty() {
        if !ngrok.is_empty() {
            candidate = ngrok.clone();
        } else if !runtime.is_empty() {
            candidate = runtime.clone();
        }
    }

    if !candidate.is_empty() && !is_public_url_reachable(&candidate) {
        if !ngrok.is_empty() && ngrok != candidate && is_public_url_reachable(&ngrok) {
            eprintln!(
                "warning: configured public URL is offline; switching to active ngrok URL: {ngrok}"
            );
            candidate = ngrok;
        } else if !runtime.is_empty() && runtime != candidate && is_public_url_reachable(&runtime) {
            eprintln!(
                "warning: configured public URL is offline; switching to runtime URL: {runtime}"
            );
            candidate = runtime;
        }
    }

    println!("== runtime public endpoint ==");
    println!("public_base_url: {candidate}");
    Ok(candidate)
}

fn find_ngrok_public_url(cfg: &Config) -> Result<String> {
    let value = http_get_json(&cfg.ngrok_api_url)?;
    let tunnels = value
        .get("tunnels")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for tunnel in tunnels {
        if let Some(url) = tunnel.get("public_url").and_then(Value::as_str)
            && url.starts_with("https://")
        {
            return Ok(url.to_string());
        }
    }
    Ok(String::new())
}

fn find_runtime_public_url_file(cfg: &Config) -> Result<String> {
    let key = format!("{}.{}", cfg.tenant, cfg.team);
    let file = cfg
        .bundle_dir
        .join("state/runtime")
        .join(key)
        .join("public_base_url.txt");
    if !file.exists() {
        return Ok(String::new());
    }
    let text = fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
    Ok(text.trim().to_string())
}

fn is_public_url_reachable(base_url: &str) -> bool {
    if base_url.trim().is_empty() {
        return false;
    }
    let output = Command::new("curl")
        .arg("-sS")
        .arg("-o")
        .arg("/dev/null")
        .arg("-w")
        .arg("%{http_code}")
        .arg("--max-time")
        .arg("5")
        .arg(base_url)
        .output();
    let Ok(output) = output else {
        return false;
    };
    let code = String::from_utf8_lossy(&output.stdout).trim().to_string();
    !code.is_empty() && code != "000"
}

fn http_get_json(url: &str) -> Result<Value> {
    let mut cmd = Command::new("curl");
    cmd.arg("-fsS").arg(url);
    let output = run_checked(cmd, &format!("curl {url}"))?;
    serde_json::from_str::<Value>(&output.stdout).with_context(|| format!("parse json from {url}"))
}

fn parse_scopes(csv: &str) -> Vec<String> {
    csv.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn apply_setup_answers(cfg: &Config, scopes: &[String]) -> Result<()> {
    if !cfg.public_web_enabled && cfg.public_surface_policy != "disabled" {
        bail!("PUBLIC_SURFACE_POLICY must be disabled when PUBLIC_WEB_ENABLED=false");
    }
    if cfg.public_web_enabled && cfg.public_base_url.trim().is_empty() {
        bail!("PUBLIC_BASE_URL is required when PUBLIC_WEB_ENABLED=true");
    }

    if !cfg.setup_answers_file.exists() {
        let mut cmd = Command::new("gtc");
        cmd.arg("setup")
            .arg("--dry-run")
            .arg("--emit-answers")
            .arg(&cfg.setup_answers_file)
            .arg(&cfg.bundle_dir)
            .arg("--tenant")
            .arg(&cfg.tenant)
            .arg("--team")
            .arg(&cfg.team)
            .arg("--env")
            .arg(&cfg.flow_env)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        apply_command_env(cfg, &mut cmd);
        let _ = run_checked(cmd, "gtc setup --dry-run --emit-answers")?;
    }

    let text = fs::read_to_string(&cfg.setup_answers_file)
        .with_context(|| format!("read {}", cfg.setup_answers_file.display()))?;
    let mut root = serde_json::from_str::<Value>(&text).context("parse setup answers json")?;

    let root_obj = as_object_mut(&mut root, "setup answers root")?;
    root_obj.insert("tenant".to_string(), Value::String(cfg.tenant.clone()));
    root_obj.insert("team".to_string(), Value::String(cfg.team.clone()));
    root_obj.insert("env".to_string(), Value::String(cfg.flow_env.clone()));

    let platform_setup = ensure_object_path(root_obj, &["platform_setup", "static_routes"])?;
    platform_setup.insert(
        "public_web_enabled".to_string(),
        Value::Bool(cfg.public_web_enabled),
    );
    platform_setup.insert(
        "public_surface_policy".to_string(),
        Value::String(cfg.public_surface_policy.clone()),
    );
    if cfg.public_web_enabled {
        platform_setup.insert(
            "public_base_url".to_string(),
            Value::String(cfg.public_base_url.clone()),
        );
    }

    let setup_answers = ensure_object_path(root_obj, &["setup_answers"])?;
    setup_answers.insert(
        "oauth-oidc-executable".to_string(),
        json!({
            "provider_id": cfg.provider,
            "auth_url": cfg.oidc_auth_url,
            "token_url": cfg.oidc_token_url,
            "client_id": if cfg.oidc_client_id.is_empty() { Value::Null } else { Value::String(cfg.oidc_client_id.clone()) },
            "client_secret": if cfg.oidc_client_secret.is_empty() { Value::Null } else { Value::String(cfg.oidc_client_secret.clone()) },
            "client_id_key": cfg.oidc_client_id_key,
            "client_secret_key": cfg.oidc_client_secret_key,
            "public_base_url": cfg.oidc_public_base_url,
            "default_scopes": scopes,
        }),
    );

    write_json_file(&cfg.setup_answers_file, &root)?;

    let mut cmd = Command::new("gtc");
    cmd.arg("setup")
        .arg("--answers")
        .arg(&cfg.setup_answers_file)
        .arg(&cfg.bundle_dir)
        .arg("--tenant")
        .arg(&cfg.tenant)
        .arg("--team")
        .arg(&cfg.team)
        .arg("--env")
        .arg(&cfg.flow_env);
    apply_command_env(cfg, &mut cmd);
    let _ = run_checked(cmd, "gtc setup --answers")?;

    println!("updated: {}", cfg.setup_answers_file.display());
    println!("applied setup for oauth-oidc-executable from env vars");
    Ok(())
}

fn run_setup(cfg: &Config) -> Result<()> {
    let mut cmd = Command::new("gtc");
    cmd.arg("op")
        .arg("demo")
        .arg("setup")
        .arg("--bundle")
        .arg(&cfg.bundle_dir)
        .arg("--tenant")
        .arg(&cfg.tenant)
        .arg("--team")
        .arg(&cfg.team)
        .arg("--domain")
        .arg("oauth")
        .arg("--secrets-env")
        .arg(&cfg.flow_env)
        .arg("--best-effort");
    apply_command_env(cfg, &mut cmd);
    let _ = run_checked(cmd, "gtc op demo setup")?;
    Ok(())
}

fn build_code_verifier() -> String {
    format!(
        "{}{}{}",
        Uuid::new_v4().as_simple(),
        Uuid::new_v4().as_simple(),
        Uuid::new_v4().as_simple()
    )
}

fn code_challenge_from_verifier(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn build_runtime_envelope(cfg: &Config, scopes: &[String], input: Value) -> Value {
    json!({
        "host": {
            "public_base_url": cfg.oidc_public_base_url,
        },
        "provider": {
            "provider_id": cfg.provider,
            "auth_url": cfg.oidc_auth_url,
            "token_url": cfg.oidc_token_url,
            "client_id": if cfg.oidc_client_id.is_empty() { Value::Null } else { Value::String(cfg.oidc_client_id.clone()) },
            "client_secret": if cfg.oidc_client_secret.is_empty() { Value::Null } else { Value::String(cfg.oidc_client_secret.clone()) },
            "client_id_key": if cfg.oidc_client_id_key.is_empty() { Value::Null } else { Value::String(cfg.oidc_client_id_key.clone()) },
            "client_secret_key": if cfg.oidc_client_secret_key.is_empty() { Value::Null } else { Value::String(cfg.oidc_client_secret_key.clone()) },
            "default_scopes": scopes,
        },
        "input": input,
    })
}

fn capability_invoke_json(cfg: &Config, op: &str, payload: &Value) -> Result<Value> {
    let mut cmd = Command::new("gtc");
    cmd.arg("op")
        .arg("demo")
        .arg("capability")
        .arg("invoke")
        .arg("--bundle")
        .arg(&cfg.bundle_dir)
        .arg("--tenant")
        .arg(&cfg.tenant)
        .arg("--team")
        .arg(&cfg.team)
        .arg("--env")
        .arg(&cfg.flow_env)
        .arg("--cap-id")
        .arg(&cfg.oauth_broker_cap_id)
        .arg("--op")
        .arg(op)
        .arg("--payload-json")
        .arg(serde_json::to_string(payload).context("serialize capability payload")?);
    apply_command_env(cfg, &mut cmd);

    let output = run_checked(cmd, &format!("capability invoke {op}"))?;
    extract_json_object(&(output.stdout + &output.stderr))
}

fn extract_json_object(raw: &str) -> Result<Value> {
    let bytes = raw.as_bytes();
    for (start, byte) in bytes.iter().enumerate() {
        if *byte != b'{' {
            continue;
        }
        for end in (start + 1..=bytes.len()).rev() {
            if bytes[end - 1] != b'}' {
                continue;
            }
            let candidate = &raw[start..end];
            if let Ok(value) = serde_json::from_str::<Value>(candidate) {
                return Ok(value);
            }
        }
    }
    bail!("could not extract JSON object from command output")
}

fn strip_origin(uri: &str) -> String {
    if let Some(pos) = uri.find("//") {
        let rest = &uri[(pos + 2)..];
        if let Some(path_start) = rest.find('/') {
            return format!("/{}", &rest[(path_start + 1)..]);
        }
        return "/".to_string();
    }
    uri.to_string()
}

fn build_authorize_url(
    auth_url: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes_space: &str,
    state: &str,
    code_challenge: &str,
) -> String {
    let query = [
        ("client_id", client_id),
        ("response_type", "code"),
        ("redirect_uri", redirect_uri),
        ("scope", scopes_space),
        ("state", state),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
    ]
    .into_iter()
    .map(|(k, v)| format!("{k}={}", url_encode(v)))
    .collect::<Vec<_>>()
    .join("&");
    format!("{}?{query}", auth_url)
}

fn wait_for_callback(
    cfg: &Config,
    expected_state: &str,
    redirect_path: &str,
    deadline: Instant,
) -> Result<CallbackData> {
    let start = Instant::now();
    let mut last_progress = start;
    let mut manual_prompted = false;
    let mut callback = provided_callback(cfg);

    if !callback.state.is_empty() && callback.state != expected_state {
        eprintln!("warning: provided callback state is stale; waiting for fresh callback");
        callback = CallbackData::default();
    }

    if callback.code.is_empty()
        && !cfg.allow_manual_callback_paste
        && !is_ngrok_inspector_available(cfg)
    {
        bail!(
            "ngrok inspector is unavailable at {}; set ALLOW_MANUAL_CALLBACK_PASTE=true for manual fallback",
            cfg.ngrok_req_api_url
        );
    }

    while Instant::now() < deadline {
        if last_progress.elapsed() >= Duration::from_secs(10) {
            println!(
                "still waiting for callback... {}s/{}s",
                start.elapsed().as_secs(),
                cfg.callback_wait_seconds
            );
            last_progress = Instant::now();
        }

        if !callback.code.is_empty() && !callback.state.is_empty() {
            if callback.state == expected_state {
                return Ok(callback);
            }
            callback = CallbackData::default();
        }

        if callback.code.is_empty()
            && let Ok(found) = find_callback_uri_from_ngrok(cfg, redirect_path)
            && !found.is_empty()
        {
            callback = parse_callback_uri(&found);
        }

        if !callback.error.is_empty() {
            bail!(
                "oauth callback returned error={} desc={}",
                callback.error,
                callback.error_description
            );
        }

        if !callback.code.is_empty() && callback.state == expected_state {
            return Ok(callback);
        }

        if cfg.allow_manual_callback_paste
            && !manual_prompted
            && start.elapsed() >= Duration::from_secs(cfg.manual_callback_prompt_after_seconds)
        {
            manual_prompted = true;
            println!("ngrok inspector did not report callback yet.");
            print!("Paste full callback URL from browser (or press Enter to keep waiting): ");
            io::stdout().flush().context("flush stdout")?;
            let mut line = String::new();
            io::stdin()
                .read_line(&mut line)
                .context("read callback URL")?;
            if !line.trim().is_empty() {
                callback = parse_callback_uri(line.trim());
            }
        }

        thread::sleep(Duration::from_secs(cfg.callback_poll_seconds));
    }

    bail!(
        "did not capture oauth callback code before timeout ({}s)",
        cfg.callback_wait_seconds
    )
}

fn provided_callback(cfg: &Config) -> CallbackData {
    if !cfg.oauth_callback_url.is_empty() {
        return parse_callback_uri(&cfg.oauth_callback_url);
    }
    CallbackData {
        uri: String::new(),
        code: cfg.oauth_callback_code.clone(),
        state: cfg.oauth_callback_state.clone(),
        error: String::new(),
        error_description: String::new(),
    }
}

fn parse_callback_uri(uri: &str) -> CallbackData {
    let query = uri.split_once('?').map(|(_, q)| q).unwrap_or_default();
    CallbackData {
        uri: uri.to_string(),
        code: query_value(query, "code").unwrap_or_default(),
        state: query_value(query, "state").unwrap_or_default(),
        error: query_value(query, "error").unwrap_or_default(),
        error_description: query_value(query, "error_description").unwrap_or_default(),
    }
}

fn query_value(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let name = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        if name == key {
            return Some(url_decode(value));
        }
    }
    None
}

fn url_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn url_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = bytes[i + 1];
                let lo = bytes[i + 2];
                let hex = [hi, lo];
                let Ok(hex_str) = std::str::from_utf8(&hex) else {
                    out.push(bytes[i]);
                    i += 1;
                    continue;
                };
                if let Ok(parsed) = u8::from_str_radix(hex_str, 16) {
                    out.push(parsed);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn is_ngrok_inspector_available(cfg: &Config) -> bool {
    Command::new("curl")
        .arg("-fsS")
        .arg("--max-time")
        .arg("3")
        .arg(&cfg.ngrok_req_api_url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn find_callback_uri_from_ngrok(cfg: &Config, redirect_path: &str) -> Result<String> {
    let value = http_get_json(&cfg.ngrok_req_api_url)?;
    let requests = value
        .get("requests")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut found = String::new();
    for request in requests {
        let uri = request
            .get("request")
            .and_then(Value::as_object)
            .and_then(|obj| obj.get("uri"))
            .and_then(Value::as_str)
            .or_else(|| request.get("uri").and_then(Value::as_str))
            .unwrap_or_default()
            .to_string();
        if !uri.is_empty() && uri.contains(redirect_path) {
            found = uri;
        }
    }
    Ok(found)
}

fn fetch_latest_commit(cfg: &Config, owner: &str, repo: &str, token: &str) -> Result<Value> {
    let mut commits_url = format!(
        "{}/repos/{owner}/{repo}/commits?per_page=1",
        cfg.github_api_base.trim_end_matches('/')
    );
    if !cfg.github_ref.trim().is_empty() {
        commits_url = format!("{commits_url}&sha={}", url_encode(&cfg.github_ref));
    }

    let mut cmd = Command::new("curl");
    cmd.arg("-sS")
        .arg("-w")
        .arg("\n%{http_code}")
        .arg("-H")
        .arg(format!("Authorization: Bearer {token}"))
        .arg("-H")
        .arg("Accept: application/vnd.github+json")
        .arg("-H")
        .arg("X-GitHub-Api-Version: 2022-11-28")
        .arg("-H")
        .arg("User-Agent: greentic-oauth-demo")
        .arg(commits_url);

    let output = run_checked(cmd, "call GitHub commits API")?;
    let (body, status) = split_body_and_status(&output.stdout)?;
    if status != 200 {
        if status == 403 && body.contains("OAuth App access restrictions") {
            eprintln!(
                "hint: org has OAuth App access restrictions; an org owner must approve this OAuth app"
            );
            eprintln!("hint: OAuth client id: {}", cfg.oidc_client_id);
        }
        bail!("GitHub commits API failed (http {status}): {body}");
    }

    serde_json::from_str::<Value>(&body).context("parse GitHub commits json")
}

fn split_body_and_status(stdout: &str) -> Result<(String, u16)> {
    let trimmed = stdout.trim_end_matches('\n');
    let Some((body, status_line)) = trimmed.rsplit_once('\n') else {
        bail!("unexpected HTTP output: missing status line");
    };
    let status = status_line
        .trim()
        .parse::<u16>()
        .with_context(|| format!("invalid HTTP status: {status_line}"))?;
    Ok((body.to_string(), status))
}

fn first_commit(commits_json: &Value) -> Result<CommitData> {
    let array = commits_json
        .as_array()
        .with_context(|| format!("expected commit array, got: {commits_json}"))?;
    let Some(first) = array.first() else {
        bail!("github API returned no commits");
    };

    let sha = first
        .get("sha")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if sha.is_empty() {
        bail!("github API returned empty commit sha: {first}");
    }

    let message = first
        .get("commit")
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let author = first
        .get("commit")
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("author"))
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let date = first
        .get("commit")
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("author"))
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("date"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let url = first
        .get("html_url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    Ok(CommitData {
        sha,
        message,
        author,
        date,
        url,
    })
}

fn run_demo_flow(cfg: &Config, run_input: &str) -> Result<String> {
    let mut cmd = Command::new("gtc");
    cmd.arg("op")
        .arg("demo")
        .arg("run")
        .arg("--bundle")
        .arg(&cfg.bundle_dir)
        .arg("--pack")
        .arg(&cfg.pack_file)
        .arg("--tenant")
        .arg(&cfg.tenant)
        .arg("--team")
        .arg(&cfg.team)
        .arg("--flow")
        .arg("github.latest_commit")
        .arg("--input")
        .arg(run_input)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_command_env(cfg, &mut cmd);

    let mut child = cmd.spawn().context("run gtc op demo run")?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(b"@quit\n")
            .context("write @quit to gtc stdin")?;
    }

    let output = child
        .wait_with_output()
        .context("wait for gtc run output")?;
    let mut merged = String::new();
    merged.push_str(&String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        if !merged.ends_with('\n') {
            merged.push('\n');
        }
        merged.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    if !output.status.success() {
        bail!("gtc op demo run failed:\n{merged}");
    }
    Ok(merged)
}

fn write_json_file(path: &Path, value: &Value) -> Result<()> {
    let text = serde_json::to_string_pretty(value).context("serialize json")?;
    fs::write(path, format!("{text}\n")).with_context(|| format!("write {}", path.display()))
}

fn print_json_file(path: &Path) -> Result<()> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| format!("read {}", path.display()))?;
    print!("{text}");
    Ok(())
}

fn trim_slash(value: &str) -> String {
    value.trim_end_matches('/').to_string()
}

fn parse_repo_url(repo_url: &str) -> Result<RepoParts> {
    let mut path = repo_url.trim().to_string();
    if let Some(stripped) = path.strip_prefix("https://github.com/") {
        path = stripped.to_string();
    } else if let Some(stripped) = path.strip_prefix("http://github.com/") {
        path = stripped.to_string();
    }
    if let Some(stripped) = path.strip_suffix(".git") {
        path = stripped.to_string();
    }
    path = path.trim_matches('/').to_string();

    let mut parts = path.split('/');
    let owner = parts.next().unwrap_or_default().to_string();
    let repo = parts.next().unwrap_or_default().to_string();
    if owner.is_empty() || repo.is_empty() {
        bail!("invalid repo url: {repo_url}");
    }

    Ok(RepoParts { owner, repo })
}

fn as_object_mut<'a>(value: &'a mut Value, label: &str) -> Result<&'a mut Map<String, Value>> {
    value
        .as_object_mut()
        .with_context(|| format!("{label} must be an object"))
}

fn ensure_object_path<'a>(
    root: &'a mut Map<String, Value>,
    path: &[&str],
) -> Result<&'a mut Map<String, Value>> {
    let mut current = root;
    for key in path {
        let entry = current
            .entry((*key).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }
        current = entry
            .as_object_mut()
            .with_context(|| format!("path segment {key} must be object"))?;
    }
    Ok(current)
}
