# MCP Server (Experimental)

> **Note:** This feature is experimental and may change or be removed in future releases.

The MCP server lets AI assistants interact with SBOMscanner, enabling them to query vulnerability data and manage scanning resources conversationally.
Any client that supports the MCP protocol can connect.

This guide covers:

- Enabling and configuring the MCP server
- Connecting from different AI clients
- Available tools for reading and writing SBOMscanner resources
- Example prompts for common workflows
- Read-only mode, rate limiting, and TLS configuration

## Prerequisites

- A Kubernetes cluster with SBOMscanner installed, or a fresh cluster where SBOMscanner will be installed alongside the MCP server
- cert-manager installed (for TLS, unless disabled with `mcp.disableTLS=true`)
- An MCP-compatible client

## 1. Authentication

The MCP server currently supports Basic Auth. OAuth and Rancher authentication are planned for future releases.

Basic Auth credentials are stored in a Kubernetes Secret with `username` and `password` keys. The server expects an `Authorization: Basic <base64(username:password)>` header on every request. TLS is enabled by default to protect credentials in transit.

## 2. Enable the MCP Server

### Create a credentials Secret

Create a Secret with `username` and `password` keys:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sbomscanner-mcp-auth
  namespace: sbomscanner
type: Opaque
stringData:
  username: mcp-user
  password: changeme
```

Apply it:

```bash
kubectl apply -f mcp-auth-secret.yaml
```

### Install or upgrade with MCP enabled

```bash
helm upgrade --install sbomscanner sbomscanner/sbomscanner \
  --namespace sbomscanner \
  --set mcp.enabled=true \
  --set mcp.auth.secretName=sbomscanner-mcp-auth
```

### Verify the deployment

```bash
kubectl get pods -n sbomscanner -l app.kubernetes.io/component=mcp
kubectl get svc -n sbomscanner -l app.kubernetes.io/component=mcp
```

You should see the MCP pod running and a Service exposing port 8222.

## 3. Configuration

All MCP-related Helm values are under the `mcp` key:

| Value                           | Default                      | Description                                                             |
| ------------------------------- | ---------------------------- | ----------------------------------------------------------------------- |
| `mcp.enabled`                   | `false`                      | Enable the MCP server deployment                                        |
| `mcp.readOnly`                  | `false`                      | Restrict to read-only tools (no create/update/delete)                   |
| `mcp.disableTLS`                | `false`                      | Disable TLS (serve plain HTTP)                                          |
| `mcp.logLevel`                  | `"info"`                     | Log level (`debug`, `info`, `warn`, `error`)                            |
| `mcp.replicas`                  | `1`                          | Number of MCP server replicas                                           |
| `mcp.auth.secretName`           | `""`                         | Name of the Secret containing `username` and `password` keys (required) |
| `mcp.resources.limits.cpu`      | `250m`                       | CPU limit                                                               |
| `mcp.resources.limits.memory`   | `512Mi`                      | Memory limit                                                            |
| `mcp.resources.requests.cpu`    | `100m`                       | CPU request                                                             |
| `mcp.resources.requests.memory` | `128Mi`                      | Memory request                                                          |
| `mcp.image.repository`          | `kubewarden/sbomscanner/mcp` | Container image repository                                              |
| `mcp.image.tag`                 | `v0.10.4`                    | Container image tag                                                     |

Example `values.yaml` snippet:

```yaml
mcp:
  enabled: true
  readOnly: false
  disableTLS: false
  logLevel: "info"
  replicas: 1
  auth:
    secretName: sbomscanner-mcp-auth
```

## 4. Connecting a Client

The MCP server uses Streamable HTTP transport with Basic Auth. Any MCP-compatible client can connect. Below are instructions for common clients.

### Port-forwarding

To reach the MCP server from your local machine, forward the in-cluster Service:

```bash
kubectl port-forward -n sbomscanner svc/sbomscanner-mcp 8222:8222
```

The MCP endpoint is then available at `https://localhost:8222/mcp` (or `http://localhost:8222/mcp` if TLS is disabled).

> **Note:** For production use, expose the MCP server through an Ingress or LoadBalancer instead of port-forwarding.

### Claude Code

Create a `.mcp.json` file in your project root (or `~/.claude/.mcp.json` for global configuration):

```json
{
  "mcpServers": {
    "sbomscanner": {
      "type": "http",
      "url": "http://localhost:8222/mcp",
      "headers": {
        "Authorization": "Basic BASE64_CREDENTIALS"
      }
    }
  }
}
```

> **Note:** Generate the base64 credentials with:
>
> ```bash
> echo -n 'mcp-user:changeme' | base64
> ```

### Claude Desktop

Open **Settings > Developer > Edit Config** and add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sbomscanner": {
      "type": "http",
      "url": "http://localhost:8222/mcp",
      "headers": {
        "Authorization": "Basic BASE64_CREDENTIALS"
      }
    }
  }
}
```

### GitHub Copilot (VS Code)

Add to `.vscode/mcp.json` in your project or to your VS Code user settings:

```json
{
  "servers": {
    "sbomscanner": {
      "type": "http",
      "url": "http://localhost:8222/mcp",
      "headers": {
        "Authorization": "Basic BASE64_CREDENTIALS"
      }
    }
  }
}
```

### Liz (Rancher AI Agent)

Liz is the AI assistant built into Rancher Prime. It connects to the MCP server in-cluster, so no port-forwarding is needed.

> **Note:** Liz does not currently support TLS for external MCP connections. The MCP server must be deployed with `mcp.disableTLS=true`.

1. **Deploy the MCP server with TLS disabled:**

   ```bash
   helm upgrade --install sbomscanner sbomscanner/sbomscanner \
     --namespace sbomscanner \
     --set mcp.enabled=true \
     --set mcp.disableTLS=true \
     --set mcp.auth.secretName=sbomscanner-mcp-auth
   ```

2. **Create the auth Secret in the Liz namespace:**

   Liz needs a copy of the MCP credentials in its own namespace:

   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: sbomscanner-mcp-auth
     namespace: cattle-ai-agent-system
   type: Opaque
   stringData:
     username: mcp-user
     password: changeme
   ```

3. **Apply the AIAgentConfig resource:**

   Replace `<namespace>` with the namespace where SBOMscanner is installed:

   ```yaml
   apiVersion: ai.cattle.io/v1alpha1
   kind: AIAgentConfig
   metadata:
     name: sbomscanner
     namespace: cattle-ai-agent-system
   spec:
     authenticationType: BASIC
     authenticationSecret: sbomscanner-mcp-auth
     builtIn: false
     displayName: SBOMscanner
     enabled: true
     mcpURL: http://sbomscanner-mcp.<namespace>.svc.cluster.local:8222
     description: |
       SBOMscanner security agent for container image vulnerability management.
       Example prompts:
       - "List all registries being scanned"
       - "Show me the latest vulnerability reports"
       - "What CVEs affect image library/nginx:1.27.1?"
       - "Create a scan job for registry X"
       - "Show vulnerability summary for my images"
     systemPrompt: |
       You are the SBOMscanner security agent. You help users manage container
       image security by interacting with SBOMscanner resources in the cluster.

       You can:
       - List and inspect container image registries
       - Trigger and monitor scan jobs
       - Query vulnerability reports for container images
       - View workload scan reports
       - Manage VEX hubs for vulnerability enrichment

       Key concepts:
       - A Registry defines which container images to scan, with optional CEL-based tag filters
       - A ScanJob triggers scanning of images in a registry (Scheduled -> InProgress -> Complete/Failed)
       - A VulnerabilityReport lists known CVEs affecting an image
       - A WorkloadScanReport aggregates vulnerability data at the workload (Deployment, StatefulSet, etc.) level
       - A VEXHub is a repository of VEX documents used to enrich vulnerability data

       IMPORTANT - Tool selection rules:
       - ALWAYS use get_image_vulnerability_summary when a user asks to list, show, or view vulnerabilities for an image.
       - ALWAYS use get_workload_vulnerability_summary when a user asks to list, show, or view vulnerabilities for a workload.
       - NEVER use get_image_vulnerabilities or get_workload_vulnerabilities for listing vulnerabilities. Their responses are too large and will fail to render. Only use them if the user explicitly asks for raw or full CVE data.
       - When in doubt, default to the summary tools.

       Security posture and overview questions:
       - list_images and list_workloads both return vulnerability severity counts and a total for each item.
       - When a user asks about security posture, call list_workloads or list_images and present results sorted by total vulnerability count in a markdown table.

       Workflow:
       - Use list_images to browse scanned images with vulnerability counts
       - Use get_image_vulnerability_summary with name and namespace from list_images
       - Use list_workloads to browse scanned workloads with vulnerability counts
       - Use get_workload_vulnerability_summary with name and namespace from list_workloads
   ```

## 5. Available Tools

The MCP server exposes tools that let AI assistants interact with SBOMscanner resources.

### Read tools

| Tool                                 | Description                                                                  |
| ------------------------------------ | ---------------------------------------------------------------------------- |
| `list_registries`                    | List Registry resources with their URI, catalog type, and repository filters |
| `get_registry`                       | Get a specific Registry by name and namespace                                |
| `list_scanjobs`                      | List ScanJob resources with status conditions and progress counters          |
| `get_scanjob`                        | Get a specific ScanJob by name and namespace                                 |
| `get_workloadscan_configuration`     | Get the cluster-scoped WorkloadScanConfiguration                             |
| `list_vexhubs`                       | List VEXHub resources (cluster-scoped)                                       |
| `get_vexhub`                         | Get a specific VEXHub by name                                                |
| `list_images`                        | List scanned images with vulnerability severity counts                       |
| `get_image_vulnerability_summary`    | Get severity counts and top 10 CVEs for an image                             |
| `get_image_vulnerabilities`          | Get the complete CVE list for an image (large response)                      |
| `list_workloads`                     | List scanned workloads with vulnerability severity counts                    |
| `get_workload_vulnerability_summary` | Get per-container severity counts and top 10 CVEs for a workload             |
| `get_workload_vulnerabilities`       | Get the complete CVE list for all containers in a workload (large response)  |

> **Note:** Prefer the `_summary` tools over the full `_vulnerabilities` tools. The summary tools return severity counts and the top 10 most severe CVEs, which is sufficient for most queries. The full tools can produce very large responses that may exceed client context limits.

### Write tools

| Tool              | Description                                                                   |
| ----------------- | ----------------------------------------------------------------------------- |
| `create_registry` | Create a new Registry with URI, catalog type, and optional repository filters |
| `update_registry` | Update an existing Registry (partial updates supported)                       |
| `delete_registry` | Delete a Registry (scan results are preserved)                                |
| `create_scanjob`  | Create a ScanJob to trigger scanning of images in a Registry                  |
| `delete_scanjob`  | Delete a ScanJob (scan results are preserved)                                 |
| `create_vexhub`   | Create a new VEXHub for vulnerability enrichment                              |
| `update_vexhub`   | Update an existing VEXHub                                                     |
| `delete_vexhub`   | Delete a VEXHub (existing VEX annotations are preserved)                      |

For details on the resources these tools manage, see [Scanning Registries](./scanning-registries.md), [Scanning Workloads](./scanning-workloads.md), and [VEX](./vex.md).

## 6. Example Prompts

Once connected, you can interact with SBOMscanner using natural language. Below are example prompts organized by workflow.

### Registry scanning workflow

- "Create a registry for `ghcr.io` that scans the `my-org/my-app` repository. Use NoCatalog since it does not expose the catalog endpoint."
- "Update the registry to scan only NGINX images with tags greater than 1.25.0."
- "Trigger a scan for registry my-registry."
- "How is the scan going?"
- "List the vulnerable images in the default namespace."
- "Show the vulnerabilities found in the NGINX image tagged 1.27.1."

### Workload security posture

- "Display the configuration of the workload scan feature."
- "Is workload scanning enabled in the test namespace?"
- "Provide an overview of the cluster's security posture."
- "List the vulnerable workloads."
- "Show the vulnerabilities found in the containers of the nginx deployment in the test namespace."

### Investigating CVEs

- "Show the most critical CVE IDs and their NVD links for image X."

## 7. Read-Only Mode

Read-only mode restricts the MCP server to read tools only. All write tools (`create_*`, `update_*`, `delete_*`) are disabled, and the server's RBAC permissions are scoped down accordingly.

Enable it with:

```bash
helm upgrade sbomscanner sbomscanner/sbomscanner \
  --namespace sbomscanner \
  --set mcp.readOnly=true
```

Use read-only mode when you want AI assistants to query vulnerability data without being able to modify SBOMscanner resources.

## 8. Rate Limiting

The MCP server enforces a rate limit of 10 requests per second with a burst allowance of 50 requests. Normal conversational usage will not hit this limit.

## 9. TLS Configuration

By default, the MCP server serves over TLS using a self-signed certificate issued by cert-manager. This ensures credentials are encrypted in transit.

To disable TLS (for development, or when TLS is terminated externally by an Ingress controller or service mesh):

```bash
helm upgrade sbomscanner sbomscanner/sbomscanner \
  --namespace sbomscanner \
  --set mcp.disableTLS=true
```

> **Warning:** Disabling TLS means Basic Auth credentials are sent in plaintext. Only disable TLS in trusted network environments or when TLS termination is handled externally.
