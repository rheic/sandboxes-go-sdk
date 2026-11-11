// Package sandboxes provides the public Go client for the local daemon.
package sandboxes

import (
	"context"
	"encoding/json"
	"net"
	"time"
)

// Config controls the local daemon connection.
type Config struct {
	// Address identifies the local daemon endpoint. Unix-like hosts use a Unix
	// domain socket path; Windows uses the corresponding access-controlled pipe.
	Address string
	// Dialer overrides the default Unix socket dialer.
	Dialer func(ctx context.Context, address string) (net.Conn, error)
	// CallTimeout bounds unary calls. Zero uses the context deadline.
	CallTimeout time.Duration
}

// Client is the root SDK client.
type Client interface {
	Sandboxes() SandboxService
	Operations() OperationService
	RegistryCredentials() RegistryCredentialService
	Close() error
}

// MCPService invokes tools through a daemon-managed MCP gateway. Approval and
// server policy remain daemon responsibilities; callers cannot grant approval.
type MCPService interface {
	List(ctx context.Context, sandboxID string) ([]MCPServer, error)
	Call(ctx context.Context, sandboxID, serverName, toolName string, arguments json.RawMessage) (json.RawMessage, error)
	ApproveCall(ctx context.Context, approvalID string) (json.RawMessage, error)
	Register(ctx context.Context, server MCPServerConfig) (*MCPRegistration, error)
	ApproveRegistration(ctx context.Context, approvalID string) (*MCPServer, error)
	Remove(ctx context.Context, name string) (bool, error)
}

// MCPServerConfig describes a local stdio or remote streamable-HTTP server.
// The daemon validates the registration and asks for explicit host approval.
type MCPServerConfig struct {
	Name, Command, WorkingDirectory string
	Arguments                       []string
	// URL selects the remote streamable-HTTP transport. Exactly one of
	// Command or URL must be set. Remote hosts are constrained by the
	// daemon's fail-closed allowlist.
	URL string
	// Headers is deprecated. Remote request headers must use SecretHeaders.
	Headers map[string]string
	// SecretHeaders contain templates whose ${placeholder} references are
	// resolved from the daemon's host vault for each request.
	SecretHeaders map[string]string
}

// MCPRegistration is either an immediately approved registry summary or a
// daemon-issued, one-use approval challenge.
type MCPRegistration struct {
	Server           *MCPServer
	ApprovalID       string
	ApprovalRequired bool
}

// MCPApprovalRequiredError carries only a daemon-issued challenge identifier.
// It grants no authority by itself and expires on the daemon.
type MCPApprovalRequiredError struct {
	ApprovalID string
	Reason     string
}

func (e *MCPApprovalRequiredError) Error() string { return "MCP approval is required" }

// MCPServer is a redacted daemon-owned registry entry. It contains no command,
// credential, header value, or OAuth identity data.
type MCPServer struct {
	Name                          string
	Gateway                       string
	Transport                     string
	Loaded                        bool
	Usable                        bool
	AuthRequired                  bool
	AuthConfigured                bool
	HasCustomHeaders              bool
	CustomHeadersSupported        bool
	CustomHeaderSecretsConfigured bool
}

// MCPServiceProvider is optionally implemented by clients that support MCP.
type MCPServiceProvider interface {
	MCPService() MCPService
}

// MCP returns the optional MCP gateway client.
func MCP(c Client) MCPService {
	if provider, ok := c.(MCPServiceProvider); ok {
		if service := provider.MCPService(); service != nil {
			return service
		}
	}
	return unsupportedMCPService{}
}

// AccountService performs host-side provider login and logout. Provider names
// are resolved by trusted daemon configuration; tokens never cross the API.
type AccountService interface {
	Login(ctx context.Context, provider string) error
	Logout(ctx context.Context, provider string) (bool, error)
}

// DeviceLoginInfo contains only the public user-facing details needed for a
// provider's device authorization handoff. The daemon retains the device code.
type DeviceLoginInfo struct {
	UserCode        string
	VerificationURI string
}

// InteractiveAccountService exposes the device-code handoff used by terminal
// clients. The callback should return only after the user continues or cancels.
type InteractiveAccountService interface {
	LoginInteractive(ctx context.Context, provider string, handoff func(context.Context, DeviceLoginInfo) error) error
}

type InteractiveAccountServiceProvider interface {
	InteractiveAccountService() InteractiveAccountService
}

// AccountCredentialStatus reports only presence metadata for local account
// credentials. It never returns account names, tokens, expiry values or
// credential fingerprints.
type AccountCredentialStatus struct {
	Present            bool
	RefreshPresent     bool
	RefreshCoordinated bool
}

// AccountStatusService reports only whether local credentials are stored. It
// never returns account names, tokens, or credential fingerprints.
type AccountStatusService interface {
	Status(ctx context.Context, provider string) (bool, error)
	// StatusDetail reports presence-only credential and refresh metadata.
	StatusDetail(ctx context.Context, provider string) (AccountCredentialStatus, error)
}

type AccountStatusServiceProvider interface {
	AccountStatusService() AccountStatusService
}

// AccountStatus returns the optional local credential-status capability.
func AccountStatus(c Client) AccountStatusService {
	if provider, ok := c.(AccountStatusServiceProvider); ok {
		if service := provider.AccountStatusService(); service != nil {
			return service
		}
	}
	return unsupportedAccountStatusService{}
}

// InteractiveAccounts returns the optional device-code account capability.
func InteractiveAccounts(c Client) InteractiveAccountService {
	if provider, ok := c.(InteractiveAccountServiceProvider); ok {
		if service := provider.InteractiveAccountService(); service != nil {
			return service
		}
	}
	return unsupportedInteractiveAccountService{}
}

// Accounts returns the optional local account service for clients that support
// the OAuth account RPC. It does not change the root Client interface.
func Accounts(c Client) AccountService {
	if provider, ok := c.(AccountServiceProvider); ok {
		if service := provider.AccountService(); service != nil {
			return service
		}
	}
	return unsupportedAccountService{}
}

// AccountServiceProvider is optionally implemented by root clients that expose
// account OAuth. It preserves compatibility for existing Client implementers.
type AccountServiceProvider interface {
	AccountService() AccountService
}

// DockerPATAccountService handles Docker's documented non-interactive account
// login. Password bytes are sent only to the local daemon and never returned.
type DockerPATAccountService interface {
	LoginWithPAT(ctx context.Context, username string, password []byte) error
}

// DockerPATAccountServiceProvider is an optional capability that keeps the
// root Client and existing AccountService implementations source compatible.
type DockerPATAccountServiceProvider interface {
	DockerPATAccountService() DockerPATAccountService
}

// DockerPATAccounts returns the optional Docker PAT login capability.
func DockerPATAccounts(c Client) DockerPATAccountService {
	if provider, ok := c.(DockerPATAccountServiceProvider); ok {
		if service := provider.DockerPATAccountService(); service != nil {
			return service
		}
	}
	return unsupportedDockerPATAccountService{}
}

type unsupportedDockerPATAccountService struct{}

func (unsupportedDockerPATAccountService) LoginWithPAT(context.Context, string, []byte) error {
	return &Error{Code: errorCodeUnsupported, Message: "Docker PAT account login is not supported by this client"}
}

type unsupportedAccountService struct{}

type unsupportedInteractiveAccountService struct{}
type unsupportedAccountStatusService struct{}

func (unsupportedInteractiveAccountService) LoginInteractive(context.Context, string, func(context.Context, DeviceLoginInfo) error) error {
	return &Error{Code: errorCodeUnsupported, Message: "interactive account service is not supported by this client"}
}

func (unsupportedAccountStatusService) Status(context.Context, string) (bool, error) {
	return false, &Error{Code: errorCodeUnsupported, Message: "account status is not supported by this client"}
}

func (unsupportedAccountStatusService) StatusDetail(context.Context, string) (AccountCredentialStatus, error) {
	return AccountCredentialStatus{}, &Error{Code: errorCodeUnsupported, Message: "account status is not supported by this client"}
}

func (unsupportedAccountService) Login(context.Context, string) error {
	return &Error{Code: errorCodeUnsupported, Message: "account service is not supported by this client"}
}

func (unsupportedAccountService) Logout(context.Context, string) (bool, error) {
	return false, &Error{Code: errorCodeUnsupported, Message: "account service is not supported by this client"}
}

// PolicyService replaces a sandbox egress policy.
type PolicyService interface {
	UpdatePolicy(ctx context.Context, id string, allow, deny []NetworkRule) (*Sandbox, error)
	MutatePolicy(ctx context.Context, id, action string, rule NetworkRule) (*Sandbox, error)
	GetPolicyProfile(ctx context.Context) (string, error)
	SetPolicyProfile(ctx context.Context, profile string) (string, error)
	GetGlobalPolicy(ctx context.Context) (allow, deny []NetworkRule, err error)
	MutateGlobalPolicy(ctx context.Context, action string, rule NetworkRule) (allow, deny []NetworkRule, err error)
	Check(ctx context.Context, id, protocol, address, domain string, port uint16) (PolicyDecision, error)
	Refresh(ctx context.Context) (applied int, err error)
	ResetGlobal(ctx context.Context) (allow, deny []NetworkRule, profile string, err error)
}

// PolicyDecision is a gateway-consistent policy result.
type PolicyDecision struct {
	Allowed bool
	RuleID  string
	Reason  string
}

// PolicyServiceProvider is optionally implemented by root clients that expose
// live policy updates without changing the root Client interface.
type PolicyServiceProvider interface {
	PolicyService() PolicyService
}

// Policies returns the optional policy service.
func Policies(c Client) PolicyService {
	if provider, ok := c.(PolicyServiceProvider); ok {
		if service := provider.PolicyService(); service != nil {
			return service
		}
	}
	return unsupportedPolicyService{}
}

type unsupportedPolicyService struct{}

func (unsupportedPolicyService) UpdatePolicy(context.Context, string, []NetworkRule, []NetworkRule) (*Sandbox, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "live policy updates are not supported by this client"}
}

func (unsupportedPolicyService) MutatePolicy(context.Context, string, string, NetworkRule) (*Sandbox, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "atomic policy updates are not supported by this client"}
}

func (unsupportedPolicyService) GetPolicyProfile(context.Context) (string, error) {
	return "", &Error{Code: errorCodeUnsupported, Message: "policy profiles are not supported by this client"}
}

func (unsupportedPolicyService) SetPolicyProfile(context.Context, string) (string, error) {
	return "", &Error{Code: errorCodeUnsupported, Message: "policy profiles are not supported by this client"}
}

func (unsupportedPolicyService) GetGlobalPolicy(context.Context) ([]NetworkRule, []NetworkRule, error) {
	return nil, nil, &Error{Code: errorCodeUnsupported, Message: "global policy is not supported by this client"}
}

func (unsupportedPolicyService) MutateGlobalPolicy(context.Context, string, NetworkRule) ([]NetworkRule, []NetworkRule, error) {
	return nil, nil, &Error{Code: errorCodeUnsupported, Message: "global policy is not supported by this client"}
}

func (unsupportedPolicyService) Check(context.Context, string, string, string, string, uint16) (PolicyDecision, error) {
	return PolicyDecision{}, &Error{Code: errorCodeUnsupported, Message: "policy checks are not supported by this client"}
}

func (unsupportedPolicyService) Refresh(context.Context) (int, error) {
	return 0, &Error{Code: errorCodeUnsupported, Message: "policy refresh is not supported by this client"}
}

func (unsupportedPolicyService) ResetGlobal(context.Context) ([]NetworkRule, []NetworkRule, string, error) {
	return nil, nil, "", &Error{Code: errorCodeUnsupported, Message: "global policy reset is not supported by this client"}
}

// PortService replaces a sandbox's published ports.
type PortService interface {
	UpdatePorts(ctx context.Context, id string, ports []Port) (*Sandbox, error)
}

// PortServiceProvider is optionally implemented by root clients that expose
// live port updates without changing the root Client interface.
type PortServiceProvider interface {
	PortService() PortService
}

// Ports returns the optional port service.
func Ports(c Client) PortService {
	if provider, ok := c.(PortServiceProvider); ok {
		if service := provider.PortService(); service != nil {
			return service
		}
	}
	return unsupportedPortService{}
}

type unsupportedPortService struct{}

func (unsupportedPortService) UpdatePorts(context.Context, string, []Port) (*Sandbox, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "live port updates are not supported by this client"}
}

// RegistryCredentialSummary is non-secret metadata for a stored registry login.
type RegistryCredentialSummary struct {
	Registry    string
	Username    string
	Scope       string
	SandboxName string
}

// RegistryCredentialLister is an optional capability for listing stored
// registry logins without exposing secrets.
type RegistryCredentialLister interface {
	ListRegistryCredentials(ctx context.Context) ([]RegistryCredentialSummary, error)
}

// RegistryCredentialList returns the optional lister.
func RegistryCredentialList(c Client) (RegistryCredentialLister, bool) {
	lister, ok := c.(RegistryCredentialLister)
	return lister, ok
}

// RegistryCredentialService stores host-side registry credentials.
type RegistryCredentialService interface {
	Login(ctx context.Context, req RegistryLoginRequest) (*RegistryLoginResponse, error)
	Logout(ctx context.Context, req RegistryLogoutRequest) (*RegistryLogoutResponse, error)
}

// RegistryLoginRequest contains a registry credential. Password is sent only
// to the local daemon and must never be logged or placed in process arguments.
type RegistryLoginRequest struct {
	Registry    string
	Username    string
	Password    []byte
	Scope       RegistryCredentialScope
	SandboxName string
}

// RegistryCredentialScope limits which registry operations may use a login.
type RegistryCredentialScope string

const (
	RegistryScopeHostOnly     RegistryCredentialScope = "host-only"
	RegistryScopeAllSandboxes RegistryCredentialScope = "all-sandboxes"
	RegistryScopeSandbox      RegistryCredentialScope = "sandbox"
)

// RegistryLoginResponse reports the non-secret login metadata.
type RegistryLoginResponse struct {
	Registry    string
	Username    string
	Scope       RegistryCredentialScope
	SandboxName string
}

// RegistryLogoutRequest selects one host-side registry credential entry.
type RegistryLogoutRequest struct {
	Registry    string
	Scope       RegistryCredentialScope
	SandboxName string
}

// RegistryLogoutResponse reports whether an entry was removed.
type RegistryLogoutResponse struct{ Removed bool }

// SandboxService manages sandbox lifecycle.
type SandboxService interface {
	Create(ctx context.Context, req CreateRequest) (*Operation, error)
	Get(ctx context.Context, id string) (*Sandbox, error)
	List(ctx context.Context, opts ListOptions) (*Page[Sandbox], error)
	Start(ctx context.Context, id string) (*Operation, error)
	Stop(ctx context.Context, id string, opts StopOptions) (*Operation, error)
	Delete(ctx context.Context, id string, opts DeleteOptions) (*Operation, error)
	Watch(ctx context.Context, opts WatchOptions) (EventStream, error)
}

// OperationService observes long-running operations.
type OperationService interface {
	Get(ctx context.Context, id string) (*Operation, error)
	Wait(ctx context.Context, id string) (*Operation, error)
}

// CreateRequest describes a sandbox create request.
// NetworkRule is a CIDR/protocol/port egress rule.
type NetworkRule struct {
	Protocol string
	CIDR     string
	Port     uint16
	Domain   string
	RuleID   string
}

// Port maps a host loopback address/port to a guest port.
type Port struct {
	Host     uint16
	Guest    uint16
	Protocol string
	HostIP   string
}

// Workspace is a host path mounted at the same absolute path in the guest.
type Workspace struct {
	Path     string
	ReadOnly bool
}

type CreateRequest struct {
	Name           string
	Image          string
	Workspace      string
	IdempotencyKey string
	// Zero selects the daemon default for each resource.
	CPUs          uint32
	MemoryMiB     uint32
	Workspaces    []Workspace
	Ports         []Port
	Allow         []NetworkRule
	Deny          []NetworkRule
	Agent         string
	Detached      bool
	PolicyProfile string
	// Privileged enables the dedicated Docker profile. It is never implicit.
	Privileged bool
	// Env is baked into the sandbox for every process, including exec.
	Env map[string]string
	// OAuthCredentials carries declaration-only kit metadata. Create verifies
	// the daemon API version before sending it and fails closed for older APIs.
	OAuthCredentials []OAuthCredential
}

// OAuthCredential mirrors the OAuth portion of a Docker Sandboxes v2 kit.
type OAuthCredential struct {
	Service        string
	TokenEndpoint  *OAuthTokenEndpoint
	ResourceHosts  []string
	Sentinels      *OAuthSentinels
	CredentialFile *OAuthCredentialFile
	ResponseFields *OAuthResponseFields
	Passthrough    bool
	SkipIfEnv      []string
}

type OAuthTokenEndpoint struct {
	Host string
	Path string
}
type OAuthSentinels struct {
	AccessToken  string
	RefreshToken string
}
type OAuthCredentialFile struct {
	Path          string
	StructureJSON string
	Template      string
}
type OAuthResponseFields struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    string
	Scope        string
	IDToken      string
}

// StopOptions controls graceful shutdown. Zero selects the daemon default;
// positive durations are rounded up to seconds, up to one hour.
type StopOptions struct {
	Grace time.Duration
}

// DeleteOptions controls deletion.
type DeleteOptions struct {
	Force bool
}

// Sandbox is the public sandbox representation.
type Sandbox struct {
	ID            string
	Name          string
	State         string
	Generation    int64
	Image         string
	Workspace     string
	Workspaces    []Workspace
	Ports         []Port
	Allow         []NetworkRule
	Deny          []NetworkRule
	Agent         string
	Detached      bool
	PolicyProfile string
	LastUsedAt    time.Time
	CPUs          uint32
	MemoryMiB     uint32
	StoppedAt     time.Time
	Error         string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Operation is the public operation representation.
type Operation struct {
	ID         string
	SandboxID  string
	Kind       string
	State      string
	Generation int64
	Error      string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// WatchOptions controls an event stream.
type WatchOptions struct {
	SandboxID     string
	AfterRevision int64
}

// Event is one streamed state change.
type Event struct {
	Type      string
	Sandbox   *Sandbox
	Operation *Operation
	Revision  int64
}

// EventStream receives state changes until closed. Close cancels the underlying
// watch and unblocks any pending Recv; callers should close streams they no
// longer need.
type EventStream interface {
	Recv() (*Event, error)
	Close() error
}

// ListOptions controls pagination.
type ListOptions struct {
	PageSize  int
	PageToken string
}

// Page is one page of results.
type Page[T any] struct {
	Items         []T
	NextPageToken string
}

// Error is a typed SDK error.
type Error struct {
	Code      string
	Message   string
	Retryable bool
	Operation string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }
