package sandboxes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
)

const (
	mcpMinimumAPIVersion     = "0.0.18"
	mcpSecretHeadersVersion  = "0.0.22"
	maxMCPCallArgumentsBytes = 1 << 20
	maxMCPCallResultBytes    = 4 << 20
)

type mcpServiceClient struct{ c *client }

type unsupportedMCPService struct{}

func (c *client) MCPService() MCPService { return mcpServiceClient{c: c} }

func (unsupportedMCPService) List(context.Context, string) ([]MCPServer, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "MCP server inventory is not supported by this client"}
}

func (unsupportedMCPService) Call(context.Context, string, string, string, json.RawMessage) (json.RawMessage, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "MCP tool calls are not supported by this client"}
}

func (unsupportedMCPService) ApproveCall(context.Context, string) (json.RawMessage, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "MCP approval is not supported by this client"}
}

func (unsupportedMCPService) Register(context.Context, MCPServerConfig) (*MCPRegistration, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "MCP registration is not supported by this client"}
}

func (unsupportedMCPService) ApproveRegistration(context.Context, string) (*MCPServer, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "MCP registration approval is not supported by this client"}
}

func (unsupportedMCPService) Remove(context.Context, string) (bool, error) {
	return false, &Error{Code: errorCodeUnsupported, Message: "MCP removal is not supported by this client"}
}

func (s mcpServiceClient) Call(ctx context.Context, sandboxID, serverName, toolName string, arguments json.RawMessage) (json.RawMessage, error) {
	if sandboxID == "" || serverName == "" || toolName == "" {
		return nil, errors.New("MCP sandbox, server, and tool names are required")
	}
	arguments, err := validateMCPArguments(arguments)
	if err != nil {
		return nil, err
	}
	if err := s.requireMCPVersion(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.MCPCall(ctx, &localv1.MCPCallRequest{
		SandboxId: sandboxID, ServerName: serverName, ToolName: toolName,
		ArgumentsJson: string(arguments),
	})
	if err != nil {
		return nil, mapError(err)
	}
	if resp.GetApprovalRequired() {
		if resp.GetApprovalId() == "" {
			return nil, errors.New("daemon requested MCP approval without a challenge ID")
		}
		return nil, &MCPApprovalRequiredError{ApprovalID: resp.GetApprovalId(), Reason: resp.GetApprovalReason()}
	}
	result := json.RawMessage(resp.GetResultJson())
	if len(result) > maxMCPCallResultBytes {
		return nil, errors.New("MCP tool result exceeds the 4 MiB limit")
	}
	if len(result) == 0 || !json.Valid(result) || !bytes.HasPrefix(bytes.TrimSpace(result), []byte("{")) {
		return nil, errors.New("daemon returned an invalid MCP tool result")
	}
	return result, nil
}

func validateMCPArguments(arguments json.RawMessage) (json.RawMessage, error) {
	if len(arguments) == 0 {
		arguments = json.RawMessage(`{}`)
	}
	if len(arguments) > maxMCPCallArgumentsBytes {
		return nil, errors.New("MCP arguments exceed the 1 MiB limit")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(arguments, &object); err != nil || object == nil {
		return nil, errors.New("MCP arguments must be a JSON object")
	}
	return arguments, nil
}

func (s mcpServiceClient) ApproveCall(ctx context.Context, approvalID string) (json.RawMessage, error) {
	if approvalID == "" {
		return nil, errors.New("MCP approval ID is required")
	}
	if err := s.requireMCPVersion(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.MCPApproveCall(ctx, &localv1.MCPApproveCallRequest{ApprovalId: approvalID})
	if err != nil {
		return nil, mapError(err)
	}
	return validateMCPResult(resp.GetResultJson())
}

func (s mcpServiceClient) Register(ctx context.Context, server MCPServerConfig) (*MCPRegistration, error) {
	if err := validateMCPRegistration(server); err != nil {
		return nil, err
	}
	if err := s.requireMCPRegistrationVersion(ctx, len(server.SecretHeaders) > 0); err != nil {
		return nil, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.MCPRegisterServer(ctx, &localv1.MCPRegisterServerRequest{
		Name: server.Name, Command: server.Command, Arguments: append([]string(nil), server.Arguments...), WorkingDirectory: server.WorkingDirectory,
		Url: server.URL, SecretHeaders: maps.Clone(server.SecretHeaders),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return convertMCPRegistration(resp)
}

func validateMCPRegistration(server MCPServerConfig) error {
	if server.Name == "" {
		return errors.New("MCP server name is required")
	}
	if server.URL != "" && (server.Command != "" || len(server.Arguments) > 0 || server.WorkingDirectory != "") {
		return errors.New("remote MCP registration must not include stdio fields")
	}
	if server.URL == "" && (server.Command == "" || server.WorkingDirectory == "") {
		return errors.New("MCP name, command, and absolute working directory are required")
	}
	if server.URL == "" && len(server.Headers)+len(server.SecretHeaders) > 0 {
		return errors.New("MCP headers are supported only for remote servers")
	}
	if len(server.Arguments) > 64 || len(server.Headers)+len(server.SecretHeaders) > 16 {
		return errors.New("MCP registration exceeds argument or header limits")
	}
	_, err := validateMCPServerConfig(server)
	return err
}

func (s mcpServiceClient) requireMCPRegistrationVersion(ctx context.Context, needsSecretHeaders bool) error {
	version, err := Version(s.c).Get(ctx)
	if err != nil {
		return fmt.Errorf("verify daemon MCP support: %w", err)
	}
	if !apiVersionAtLeast(version.APIVersion, mcpMinimumAPIVersion) {
		return &Error{Code: errorCodeUnsupported, Message: "MCP requires daemon API v0.0.18 or newer"}
	}
	if needsSecretHeaders && !apiVersionAtLeast(version.APIVersion, mcpSecretHeadersVersion) {
		return &Error{Code: errorCodeUnsupported, Message: "vault-backed MCP headers require daemon API v0.0.22 or newer"}
	}
	return nil
}

func convertMCPRegistration(resp *localv1.MCPRegisterServerResponse) (*MCPRegistration, error) {
	registration := &MCPRegistration{ApprovalID: resp.GetApprovalId(), ApprovalRequired: resp.GetApprovalRequired()}
	if resp.GetServer() != nil {
		converted := convertMCPServer(resp.GetServer())
		registration.Server = &converted
	}
	if registration.ApprovalRequired && registration.ApprovalID == "" {
		return nil, errors.New("daemon requested registration approval without a challenge ID")
	}
	return registration, nil
}

func (s mcpServiceClient) ApproveRegistration(ctx context.Context, approvalID string) (*MCPServer, error) {
	if approvalID == "" {
		return nil, errors.New("MCP approval ID is required")
	}
	if err := s.requireMCPVersion(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.MCPApproveRegistration(ctx, &localv1.MCPApproveRegistrationRequest{ApprovalId: approvalID})
	if err != nil {
		return nil, mapError(err)
	}
	if resp.GetServer() == nil {
		return nil, errors.New("daemon returned no MCP server summary")
	}
	server := convertMCPServer(resp.GetServer())
	return &server, nil
}

func (s mcpServiceClient) Remove(ctx context.Context, name string) (bool, error) {
	if name == "" {
		return false, errors.New("MCP server name is required")
	}
	if err := s.requireMCPVersion(ctx); err != nil {
		return false, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.MCPRemoveServer(ctx, &localv1.MCPRemoveServerRequest{Name: name})
	if err != nil {
		return false, mapError(err)
	}
	return resp.GetRemoved(), nil
}

func (s mcpServiceClient) requireMCPVersion(ctx context.Context) error {
	version, err := Version(s.c).Get(ctx)
	if err != nil {
		return fmt.Errorf("verify daemon MCP support: %w", err)
	}
	if !apiVersionAtLeast(version.APIVersion, mcpMinimumAPIVersion) {
		return &Error{Code: errorCodeUnsupported, Message: "MCP requires daemon API v0.0.18 or newer"}
	}
	return nil
}

func validateMCPResult(raw string) (json.RawMessage, error) {
	result := json.RawMessage(raw)
	if len(result) > maxMCPCallResultBytes {
		return nil, errors.New("MCP tool result exceeds the 4 MiB limit")
	}
	if len(result) == 0 || !json.Valid(result) || !bytes.HasPrefix(bytes.TrimSpace(result), []byte("{")) {
		return nil, errors.New("daemon returned an invalid MCP tool result")
	}
	return result, nil
}

func convertMCPServer(server *localv1.MCPServerSummary) MCPServer {
	return MCPServer{Name: server.GetName(), Gateway: server.GetGateway(), Transport: server.GetTransport(),
		Loaded: server.GetLoaded(), Usable: server.GetUsable(), AuthRequired: server.GetAuthRequired(),
		AuthConfigured: server.GetAuthConfigured(), HasCustomHeaders: server.GetHasCustomHeaders(),
		CustomHeadersSupported: server.GetCustomHeadersSupported(), CustomHeaderSecretsConfigured: server.GetCustomHeaderSecretsConfigured()}
}

func (s mcpServiceClient) List(ctx context.Context, sandboxID string) ([]MCPServer, error) {
	version, err := Version(s.c).Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("verify daemon MCP support: %w", err)
	}
	if !apiVersionAtLeast(version.APIVersion, mcpMinimumAPIVersion) {
		return nil, &Error{Code: errorCodeUnsupported, Message: "MCP server inventory requires daemon API v0.0.18 or newer"}
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.ListMCPServers(ctx, &localv1.ListMCPServersRequest{SandboxId: sandboxID})
	if err != nil {
		return nil, mapError(err)
	}
	servers := make([]MCPServer, 0, len(resp.GetServers()))
	for _, server := range resp.GetServers() {
		if server == nil || server.GetName() == "" {
			return nil, errors.New("daemon returned an invalid MCP server summary")
		}
		servers = append(servers, MCPServer{
			Name: server.GetName(), Gateway: server.GetGateway(), Transport: server.GetTransport(),
			Loaded: server.GetLoaded(), Usable: server.GetUsable(), AuthRequired: server.GetAuthRequired(),
			AuthConfigured: server.GetAuthConfigured(), HasCustomHeaders: server.GetHasCustomHeaders(),
			CustomHeadersSupported:        server.GetCustomHeadersSupported(),
			CustomHeaderSecretsConfigured: server.GetCustomHeaderSecretsConfigured(),
		})
	}
	return servers, nil
}

// validateMCPServerConfig bounds registration size, validates explicit
// host-vault templates, and rejects ambiguous header names before RPC.
func validateMCPServerConfig(server MCPServerConfig) (int, error) {
	total := len(server.Name) + len(server.Command) + len(server.WorkingDirectory) + len(server.URL)
	if len(server.Headers) != 0 {
		return 0, errors.New("static MCP headers are disabled; use SecretHeaders with host-vault references")
	}
	headerNames := make(map[string]struct{}, len(server.Headers)+len(server.SecretHeaders))
	for _, arg := range server.Arguments {
		total += len(arg)
	}
	for key, value := range server.SecretHeaders {
		canonicalName := strings.ToLower(strings.TrimSpace(key))
		if canonicalName == "" || strings.ContainsAny(key, "\r\n:\x00") || strings.ContainsAny(value, "\r\n\x00") {
			return 0, errors.New("invalid secret MCP header name or value")
		}
		if _, exists := headerNames[canonicalName]; exists {
			return 0, errors.New("MCP header names must be unique, ignoring case")
		}
		headerNames[canonicalName] = struct{}{}
		total += len(key) + len(value)
		if strings.ContainsAny(value, "\r\n\x00") || !hasMCPSecretPlaceholder(value) {
			return 0, errors.New("secret MCP header templates must contain valid host-vault ${placeholder} references")
		}
	}
	if total > 16<<10 {
		return 0, errors.New("MCP registration exceeds 16 KiB")
	}
	return total, nil
}

func hasMCPSecretPlaceholder(value string) bool {
	found := false
	for offset := 0; offset < len(value); {
		start := strings.Index(value[offset:], "${")
		if start < 0 {
			if strings.Contains(value[offset:], "}") {
				return false
			}
			return found
		}
		start += offset
		if strings.Contains(value[offset:start], "}") {
			return false
		}
		end := strings.IndexByte(value[start+2:], '}')
		if end < 0 {
			return false
		}
		end += start + 2
		name := value[start+2 : end]
		if !validMCPPlaceholderName(name) {
			return false
		}
		found = true
		offset = end + 1
	}
	return found
}

func validMCPPlaceholderName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for index, char := range name {
		if !validMCPPlaceholderCharacter(char) || index == 0 && (char == '_' || char == '-') {
			return false
		}
	}
	return true
}

func validMCPPlaceholderCharacter(char rune) bool {
	if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-' {
		return true
	}
	return false
}
