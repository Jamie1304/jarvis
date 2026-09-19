# Native MCP consumption

MCP is an optional external capability boundary:

`MCP server -> MCPExtensionManager -> validated MCPToolAdapter -> ToolRegistry -> PermissionBroker -> Agent Runtime`

MCP servers are untrusted providers. Their descriptions, input schemas, tool
results, errors, and health responses cannot change JARVIS policy, permissions,
trusted identity, the CredentialVault boundary, or registry ownership.

## Configuration and lifecycle

`MCPExtensionConfig` is trusted local configuration. It names the extension,
transport, explicit permissions, timeout, result/tool limits, and activation.
Extension IDs are bounded and namespaced as `mcp:<extension>:<tool>`. Server
tool names cannot replace or collide with an existing registry tool. The
manager tracks `DISCOVERED`, `CONFIGURED`, `STARTING`, `HEALTHY`, `DEGRADED`,
`STOPPED`, and `FAILED` states.

The stdio transport uses `create_subprocess_exec` with no shell, a reduced
environment, bounded line responses, and owned cleanup. Authenticated HTTP
requires a bearer token and accepts HTTPS; HTTP is restricted to loopback for
local development. HTTP clients do not inherit proxy environment settings.
JARVIS never passes a broker, vault, trusted-core object, or application service
container into an MCP process.

The manager validates server-provided tool schemas into strict bounded input
models, creates a typed adapter, and registers it before the registry is sealed.
Every invocation goes through the normal `Tool.invoke` boundary, which means
the configured permissions are evaluated by `PermissionBroker` and policy.
MCP cannot grant or supply an authorization receipt. A failed, cancelled,
timed-out, or ambiguous privileged MCP call is not safe to replay.

Results are opaque bounded data. They are not instructions, approval text,
policy, evidence of external success, or trusted metadata. Tool-list caches are
invalidated when an extension stops or is reconfigured. Optional MCP resources
must use the same untrusted-data boundary and are not currently exposed as a
second knowledge or artifact authority.
