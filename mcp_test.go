package sandboxes

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type mcpTestServer struct {
	localv1.UnimplementedSandboxServiceServer
	apiVersion    string
	callCount     int
	request       *localv1.MCPCallRequest
	callErr       error
	callResult    string
	callApproval  *localv1.MCPCallResponse
	listCount     int
	listReq       *localv1.ListMCPServersRequest
	listResp      *localv1.ListMCPServersResponse
	approvalReq   *localv1.MCPApproveCallRequest
	registerReq   *localv1.MCPRegisterServerRequest
	approveRegReq *localv1.MCPApproveRegistrationRequest
	removeReq     *localv1.MCPRemoveServerRequest
}

func (s *mcpTestServer) GetVersion(context.Context, *localv1.GetVersionRequest) (*localv1.GetVersionResponse, error) {
	return &localv1.GetVersionResponse{Version: "test", ApiVersion: s.apiVersion}, nil
}

func (s *mcpTestServer) MCPCall(_ context.Context, request *localv1.MCPCallRequest) (*localv1.MCPCallResponse, error) {
	s.callCount++
	s.request = request
	if s.callErr != nil {
		return nil, s.callErr
	}
	if s.callApproval != nil {
		return s.callApproval, nil
	}
	if s.callResult != "" {
		return &localv1.MCPCallResponse{ResultJson: s.callResult}, nil
	}
	return &localv1.MCPCallResponse{ResultJson: `{"content":[]}`}, nil
}

func (s *mcpTestServer) ListMCPServers(_ context.Context, request *localv1.ListMCPServersRequest) (*localv1.ListMCPServersResponse, error) {
	s.listCount++
	s.listReq = request
	if s.listResp != nil {
		return s.listResp, nil
	}
	return &localv1.ListMCPServersResponse{Servers: []*localv1.MCPServerSummary{{
		Name: "fixture", Gateway: "local", Transport: "stdio", Loaded: true, Usable: true,
		HasCustomHeaders: true, CustomHeadersSupported: true, CustomHeaderSecretsConfigured: true,
	}}}, nil
}

func (s *mcpTestServer) MCPApproveCall(_ context.Context, request *localv1.MCPApproveCallRequest) (*localv1.MCPApproveCallResponse, error) {
	s.approvalReq = request
	return &localv1.MCPApproveCallResponse{ResultJson: `{"content":[]}`}, nil
}

func (s *mcpTestServer) MCPRegisterServer(_ context.Context, request *localv1.MCPRegisterServerRequest) (*localv1.MCPRegisterServerResponse, error) {
	s.registerReq = request
	return &localv1.MCPRegisterServerResponse{ApprovalRequired: true, ApprovalId: "registration-1"}, nil
}

func (s *mcpTestServer) MCPApproveRegistration(_ context.Context, request *localv1.MCPApproveRegistrationRequest) (*localv1.MCPApproveRegistrationResponse, error) {
	s.approveRegReq = request
	return &localv1.MCPApproveRegistrationResponse{Server: &localv1.MCPServerSummary{Name: "fixture", Gateway: "local", Transport: "stdio", Usable: true}}, nil
}

func (s *mcpTestServer) MCPRemoveServer(_ context.Context, request *localv1.MCPRemoveServerRequest) (*localv1.MCPRemoveServerResponse, error) {
	s.removeReq = request
	return &localv1.MCPRemoveServerResponse{Removed: true}, nil
}

func TestMCPListReturnsRedactedServerSummaries(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	defer cleanup()
	got, err := MCP(client).List(context.Background(), "sb-owned")
	if err != nil {
		t.Fatal(err)
	}
	if server.listCount != 1 || server.listReq.GetSandboxId() != "sb-owned" {
		t.Fatalf("list count=%d request=%+v", server.listCount, server.listReq)
	}
	if len(got) != 1 || got[0].Name != "fixture" || got[0].Gateway != "local" || !got[0].Usable ||
		!got[0].CustomHeadersSupported || !got[0].CustomHeaderSecretsConfigured {
		t.Fatalf("summaries=%+v", got)
	}
}

func TestMCPListRejectsInvalidDaemonSummariesAndOldDaemon(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	server.listResp = &localv1.ListMCPServersResponse{Servers: []*localv1.MCPServerSummary{{Gateway: "local"}}}
	_, err := MCP(client).List(context.Background(), "")
	if err == nil || server.listCount != 1 {
		t.Fatalf("invalid summary err=%v list calls=%d", err, server.listCount)
	}
	cleanup()

	client, server, cleanup = newMCPTestClient(t, "0.0.17")
	defer cleanup()
	_, err = MCP(client).List(context.Background(), "")
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != errorCodeUnsupported || server.listCount != 0 {
		t.Fatalf("old daemon err=%v list calls=%d", err, server.listCount)
	}
}

func newMCPTestClient(t *testing.T, apiVersion string) (Client, *mcpTestServer, func()) {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.MaxSendMsgSize(maxRPCResponseBytes))
	implementation := &mcpTestServer{apiVersion: apiVersion}
	localv1.RegisterSandboxServiceServer(server, implementation)
	go func() { _ = server.Serve(listener) }()
	client, err := New(Config{
		Address: "mcp-bufnet",
		Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		},
	})
	if err != nil {
		server.Stop()
		t.Fatal(err)
	}
	return client, implementation, func() {
		_ = client.Close()
		server.Stop()
	}
}

func TestMCPCallSendsValidatedArgumentsAndReturnsJSON(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	defer cleanup()
	arguments := json.RawMessage(`{"query":"synthetic"}`)
	result, err := MCP(client).Call(context.Background(), "sb-owned", "search", "find", arguments)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != `{"content":[]}` || server.callCount != 1 {
		t.Fatalf("result=%s calls=%d", result, server.callCount)
	}
	if server.request.GetSandboxId() != "sb-owned" || server.request.GetServerName() != "search" || server.request.GetToolName() != "find" || server.request.GetArgumentsJson() != string(arguments) {
		t.Fatalf("request=%+v", server.request)
	}
}

func TestMCPCallDefaultsEmptyArgumentsToObject(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	defer cleanup()
	if _, err := MCP(client).Call(context.Background(), "sb-owned", "search", "find", nil); err != nil {
		t.Fatal(err)
	}
	if server.request.GetArgumentsJson() != "{}" {
		t.Fatalf("arguments = %q, want empty object", server.request.GetArgumentsJson())
	}
}

func TestMCPCallRejectsInvalidArgumentsAndOldDaemon(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	_, err := MCP(client).Call(context.Background(), "sb-owned", "search", "find", json.RawMessage(`[]`))
	if err == nil || server.callCount != 0 {
		t.Fatalf("invalid arguments err=%v calls=%d", err, server.callCount)
	}
	cleanup()

	client, server, cleanup = newMCPTestClient(t, "0.0.17")
	defer cleanup()
	_, err = MCP(client).Call(context.Background(), "sb-owned", "search", "find", nil)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != errorCodeUnsupported || server.callCount != 0 {
		t.Fatalf("old daemon err=%v calls=%d", err, server.callCount)
	}
}

func TestMCPCallEnforcesPayloadLimits(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	oversized := json.RawMessage(`{"value":"` + strings.Repeat("x", maxMCPCallArgumentsBytes) + `"}`)
	if _, err := MCP(client).Call(context.Background(), "sb-1", "server", "tool", oversized); err == nil || server.callCount != 0 {
		t.Fatalf("oversized args err=%v calls=%d", err, server.callCount)
	}
	cleanup()

	client, server, cleanup = newMCPTestClient(t, "0.0.18")
	defer cleanup()
	const emptyObject = `{"value":""}`
	server.callResult = `{"value":"` + strings.Repeat("x", maxMCPCallResultBytes-len(emptyObject)) + `"}`
	result, err := MCP(client).Call(context.Background(), "sb-1", "server", "tool", nil)
	if err != nil || len(result) != maxMCPCallResultBytes {
		t.Fatalf("boundary result length=%d err=%v", len(result), err)
	}
	server.callResult += " "
	if _, err := MCP(client).Call(context.Background(), "sb-1", "server", "tool", nil); err == nil || err.Error() != "MCP tool result exceeds the 4 MiB limit" || server.callCount != 2 {
		t.Fatalf("oversized result err=%v calls=%d", err, server.callCount)
	}
}

func TestMCPCallMapsDaemonErrors(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	defer cleanup()
	server.callErr = status.Error(codes.PermissionDenied, "approval denied")
	_, err := MCP(client).Call(context.Background(), "sb-1", "search", "find", nil)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != "permission_denied" {
		t.Fatalf("error = %v", err)
	}
}

func TestMCPCallReturnsDaemonIssuedApprovalChallenge(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	defer cleanup()
	server.callApproval = &localv1.MCPCallResponse{ApprovalRequired: true, ApprovalId: "challenge-1", ApprovalReason: "host approval"}
	_, err := MCP(client).Call(context.Background(), "sb-1", "search", "find", nil)
	var approval *MCPApprovalRequiredError
	if !errors.As(err, &approval) || approval.ApprovalID != "challenge-1" || approval.Reason != "host approval" {
		t.Fatalf("approval error = %#v", err)
	}
}

func TestMCPRegistrationAndOneUseApprovalRPCs(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	defer cleanup()
	mcp := MCP(client)
	registration, err := mcp.Register(context.Background(), MCPServerConfig{Name: "fixture", Command: "/opt/fixture", Arguments: []string{"--stdio"}, WorkingDirectory: "/tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if !registration.ApprovalRequired || registration.ApprovalID != "registration-1" || server.registerReq.GetCommand() != "/opt/fixture" || len(server.registerReq.GetArguments()) != 1 {
		t.Fatalf("registration=%+v request=%+v", registration, server.registerReq)
	}
	if _, err := mcp.ApproveRegistration(context.Background(), registration.ApprovalID); err != nil {
		t.Fatal(err)
	}
	if server.approveRegReq.GetApprovalId() != "registration-1" {
		t.Fatalf("registration approval=%+v", server.approveRegReq)
	}
	removed, err := mcp.Remove(context.Background(), "fixture")
	if err != nil || !removed || server.removeReq.GetName() != "fixture" {
		t.Fatalf("removed=%t request=%+v err=%v", removed, server.removeReq, err)
	}
}

func TestMCPApproveCallUsesDaemonChallengeWithoutClientGrant(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	defer cleanup()
	result, err := MCP(client).ApproveCall(context.Background(), "daemon-challenge")
	if err != nil || string(result) != `{"content":[]}` || server.approvalReq.GetApprovalId() != "daemon-challenge" {
		t.Fatalf("result=%s request=%+v err=%v", result, server.approvalReq, err)
	}
}

func TestMCPRemoteRegistrationSendsURLAndHeaders(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.22")
	defer cleanup()
	mcp := MCP(client)
	registration, err := mcp.Register(context.Background(), MCPServerConfig{
		Name:          "remote-fixture",
		URL:           "https://mcp.example.com/mcp",
		SecretHeaders: map[string]string{"Authorization": "Bearer ${token}", "X-API-Key": "${api_key}"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !registration.ApprovalRequired || server.registerReq.GetUrl() != "https://mcp.example.com/mcp" || len(server.registerReq.GetHeaders()) != 0 || server.registerReq.GetSecretHeaders()["Authorization"] != "Bearer ${token}" || server.registerReq.GetSecretHeaders()["X-API-Key"] != "${api_key}" {
		t.Fatalf("registration=%+v request=%+v", registration, server.registerReq)
	}
	if server.registerReq.GetCommand() != "" {
		t.Fatalf("remote registration carried a command: %+v", server.registerReq)
	}
}

func TestMCPSecretHeadersRequireAPI022(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.21")
	defer cleanup()
	_, err := MCP(client).Register(context.Background(), MCPServerConfig{
		Name: "remote-fixture", URL: "https://mcp.example.com/mcp",
		SecretHeaders: map[string]string{"X-API-Key": "${api_key}"},
	})
	if err == nil || !strings.Contains(err.Error(), "API v0.0.22") {
		t.Fatalf("Register error = %v, want API version rejection", err)
	}
	if server.registerReq != nil {
		t.Fatal("secret headers were sent to an older daemon")
	}
}

func TestMCPRemoteRegistrationRejectsAmbiguousConfig(t *testing.T) {
	client, _, cleanup := newMCPTestClient(t, "0.0.20")
	defer cleanup()
	mcp := MCP(client)
	if _, err := mcp.Register(context.Background(), MCPServerConfig{Name: "fixture", Command: "/opt/fixture", WorkingDirectory: "/tmp", URL: "https://mcp.example.com/mcp"}); err == nil {
		t.Fatal("ambiguous registration was accepted")
	}
	if _, err := mcp.Register(context.Background(), MCPServerConfig{Name: "fixture", URL: "https://mcp.example.com/mcp", Headers: map[string]string{"Authorization": "Bearer x"}}); err == nil {
		t.Fatal("literal secret-bearing registration was accepted client-side")
	}
	if _, err := mcp.Register(context.Background(), MCPServerConfig{Name: "fixture", URL: "https://mcp.example.com/mcp", Headers: map[string]string{"X-API-Key": "literal"}}); err == nil {
		t.Fatal("literal API-key header was accepted in static headers")
	}
	if _, err := mcp.Register(context.Background(), MCPServerConfig{Name: "fixture", URL: "https://mcp.example.com/mcp", Headers: map[string]string{"X-Team": "${team}"}}); err == nil {
		t.Fatal("vault placeholder was accepted in static headers")
	}
	if _, err := mcp.Register(context.Background(), MCPServerConfig{Name: "fixture", URL: "https://mcp.example.com/mcp", Headers: map[string]string{"Authorization": "Bearer ${}"}}); err == nil {
		t.Fatal("invalid MCP vault placeholder was accepted client-side")
	}
	if _, err := mcp.Register(context.Background(), MCPServerConfig{Name: "fixture", URL: "https://mcp.example.com/mcp", Headers: map[string]string{"Authorization": "Bearer } ${token}"}}); err == nil {
		t.Fatal("malformed MCP vault placeholder was accepted client-side")
	}
	if _, err := mcp.Register(context.Background(), MCPServerConfig{Name: "fixture", URL: "https://mcp.example.com/mcp", Headers: map[string]string{"X-Team": "one", "x-team": "two"}}); err == nil {
		t.Fatal("case-insensitive duplicate MCP headers were accepted client-side")
	}
	if _, err := mcp.Register(context.Background(), MCPServerConfig{Name: "fixture", URL: "https://mcp.example.com/mcp", Headers: map[string]string{"X-Team": "one"}, SecretHeaders: map[string]string{"x-team": "${team}"}}); err == nil {
		t.Fatal("case-insensitive duplicate static/secret headers were accepted client-side")
	}
	for _, headers := range []map[string]string{{"X-Team\x00": "${team}"}, {"X-Team": "${team\x00}"}, {"  ": "${team}"}} {
		if _, err := mcp.Register(context.Background(), MCPServerConfig{Name: "fixture", URL: "https://mcp.example.com/mcp", SecretHeaders: headers}); err == nil {
			t.Errorf("invalid secret header was accepted: %#v", headers)
		}
	}
}
