package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/adminapi"
	"github.com/TrueOpen/cortex/internal/auditduty"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/modelregistry"
	"github.com/TrueOpen/cortex/internal/txclient/txclienttest"
)

// auditOnlyKeeper is a chain that assigns one panel round to this node.
type auditOnlyKeeper struct {
	*recordingKeeperClient
	asked atomic.Int32
}

const auditOnlyTask = "ab00000000000000000000000000000000000000000000000000000000000000"

func (k *auditOnlyKeeper) PanelAssignments(_ context.Context, operator string) ([]chainclient.PanelAssignment, error) {
	k.asked.Add(1)
	return []chainclient.PanelAssignment{{
		TaskID: auditOnlyTask, PanelRound: 2, Kind: 1, AssignmentHeight: 10, VoteDeadlineHeight: 70,
		Audit: []byte{1, 2, 3}, ModelID: strings.Repeat("1c", 32), ProfileVersion: 1, RegistrationHash: strings.Repeat("2d", 32),
	}}, nil
}

func (k *auditOnlyKeeper) VerifierCandidateMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	return chainclient.VerifierCandidateMemberSnapshot{}, chainclient.ErrVerifierWindowNotReady
}

// auditOnlyConfig is a real-mode node with no model service at all: no
// model_management section and no local_identity.model_service_id.
func auditOnlyConfig(t *testing.T, kvPath, spool string) string {
	t.Helper()
	cfg := realDaemonConfigWithKeeperPolling("__ADMIN_SOCKET__", kvPath)
	cfg = regexp.MustCompile(`(?m)^model_management:\n(  .*\n)+`).ReplaceAllString(cfg, "")
	cfg = regexp.MustCompile(`(?m)^  model_service_id: .*\n`).ReplaceAllString(cfg, "")
	if strings.Contains(cfg, "model_management") || strings.Contains(cfg, "model_service_id") {
		t.Fatalf("the audit-only test config still names a model service:\n%s", cfg)
	}
	return cfg + "\nverifier:\n  audit:\n    enabled: true\n    only: true\n    spool_dir: " + spool + "\n    poll_ms: 10\n"
}

// A node with no model service starts in real mode with verifier.audit.only
// and serves the audit duty: the panel round the chain assigned reaches the
// spool, and the operator's support declaration carries the audit capability
// alone.
func TestDaemonStartsAuditOnlyWithoutAModelService(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool")
	keeper := &auditOnlyKeeper{recordingKeeperClient: &recordingKeeperClient{pages: []chainclient.KeeperEventsPage{{
		ChainHeight: 20, FinalizedHeight: 12, LastEventHeight: 12, LastPosition: chainclient.BlockEndPosition(12),
	}}}}
	previousHost := auditHost
	auditHost = cleanHost
	t.Cleanup(func() { auditHost = previousHost })

	var runtime *daemon.Runtime
	socketPath := startDaemonWithRuntimeBuilder(t, auditOnlyConfig(t, filepath.Join(dir, "runtime.db"), spool),
		func(ctx context.Context, cfg config.Config) (*daemon.Runtime, error) {
			if !cfg.AuditOnly() || cfg.LocalIdentity.ModelServiceID != "" || cfg.ModelManagement.Endpoint != "" {
				t.Errorf("the test must run with no model service configured: %+v", cfg.ModelManagement)
			}
			var err error
			// No ModelClient and no ModelTransport are injected.
			runtime, err = daemon.BuildRuntimeWithOptions(ctx, cfg, daemon.RuntimeOptions{
				SigningClient: stubSigner{}, TrustInjectedSignerForTests: true,
				TxClient: txclienttest.NewFake(), Keeper: keeper, KeeperEvents: keeper,
				TaskInputResolver: mainTaskInputResolver{},
			})
			return runtime, err
		})

	assignment := filepath.Join(spool, "assignments", auditOnlyTask+"-2.json")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(assignment); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the assigned panel round never reached the spool (assignments read %d times)", keeper.asked.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
	body, err := os.ReadFile(assignment)
	if err != nil {
		t.Fatal(err)
	}
	var a auditduty.AssignmentFile
	if err := json.Unmarshal(body, &a); err != nil || a.PanelRound != 2 || a.TaskID != auditOnlyTask ||
		a.VerifierOperator != "trueopen1n76x6eelp8s6nx737vnmp29rdme7peaypql50k" {
		t.Fatalf("assignment file %s: %v", body, err)
	}
	if runtime.Dependencies.Model != nil {
		t.Fatalf("an audit-only node must not build a model service client, got %T", runtime.Dependencies.Model)
	}

	// The Builder streams are up and answer panel rounds, with no model.
	if runtime.Dispatch == nil || !runtime.Dispatch.Plane().ServesPanelRounds() {
		t.Fatal("an audit-only node must serve panel rounds on its Builder streams")
	}

	// The declaration the operator signs is audit-only.
	intent, err := adminapi.NewClient(socketPath).ModelSupport(context.Background(), modelregistry.SupportRequest{
		ModelID: strings.Repeat("1c", 32), Supported: true,
	})
	if err != nil {
		t.Fatalf("support intent: %v", err)
	}
	if !intent.Message.AuditCapability || intent.Message.InferenceCapability || intent.Message.VerificationCapability {
		t.Fatalf("support intent %+v, want the audit capability alone", intent.Message)
	}
}
