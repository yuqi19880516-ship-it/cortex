package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// wireDispatchRunnerConfig points the TaskRunner at the runtime's Builder
// streams: the Verifier FrameSender and NoticeSender are the fan-out over
// the active streams (S7), and the dispatch effects and lease release go
// through a link the plane binds before any runner starts (S5, S6, S8).
func wireDispatchRunnerConfig(cfg *daemon.TaskRunnerConfig, rt *daemon.Runtime) *daemon.DispatchLink {
	if rt == nil || rt.Dispatch == nil {
		return nil
	}
	link := daemon.NewDispatchLink()
	cfg.VerifierSender, cfg.VerifyNotices = rt.Dispatch.Fanout(), rt.Dispatch.Fanout()
	cfg.DispatchRecords, cfg.DispatchEvents, cfg.ReleaseDispatchLease = link, link, link.ReleaseTaskLease
	cfg.ReleaseFailedInferLease = link.ReleaseFailedInferLease
	cfg.TaskBuilders = rt.SelectedTaskBuilders
	if r, ok := rt.Dependencies.Keeper.(chainclient.VerifyCommitReader); ok {
		cfg.VerifyCommitReader = r
	}
	return link
}

func newDispatchPlane(cfg config.Config, rt *daemon.Runtime, runner *daemon.TaskRunner, ev *evidence.Store) (*daemon.DispatchPlane, error) {
	chain, ok := rt.Dependencies.Keeper.(daemon.DispatchPlaneChain)
	if !ok {
		return nil, fmt.Errorf("dispatch.builders needs a Keeper client that serves the Phase 1 dispatch reads")
	}
	profiles, err := cfg.LocalIdentity.ModelProfiles()
	if err != nil {
		return nil, err
	}
	// Without tx.enabled the node has no direct transaction path: claims,
	// receipt rescues and omission challenges are not submitted (config
	// accepts a real-mode node without one).
	var submitter func() (txclient.Client, string)
	if cfg.Tx.Enabled {
		submitter = rt.WorkloadSubmitter
	} else {
		slog.Warn("dispatch is configured but tx.enabled is false: compensation claims, receipt rescue and omission challenges are off on this node",
			"builders", cfg.Dispatch.AllBuilders())
	}
	var pause *daemon.ChainPause
	if cfg.Dispatch.HonourChainPause {
		reader, ok := rt.Dependencies.Keeper.(daemon.WorkerQuotaReader)
		if !ok {
			return nil, fmt.Errorf("dispatch.honour_chain_pause needs a Keeper client that reads the Worker quota")
		}
		pause = daemon.NewChainPause(reader, cfg.LocalIdentity.OperatorAddress,
			time.Duration(cfg.Dispatch.ChainPauseRefreshMS)*time.Millisecond, nil, slog.Default())
	}
	// An audit-only node has no engine and so no concurrency setting; the
	// lease ledger still needs a size, and no lease is ever taken (every offer
	// is refused).
	capacity := cfg.ModelManagement.MaxConcurrency
	if cfg.AuditOnly() && capacity == 0 {
		capacity = 1
	}
	panel, err := newPanelHandraiser(cfg, rt)
	if err != nil {
		return nil, err
	}
	return daemon.NewDispatchPlane(context.Background(), daemon.DispatchPlaneConfig{
		Streams: rt.Dispatch, Runner: runner, Evidence: ev, Store: rt.Store,
		ChainID: cfg.ChainID, Operator: cfg.LocalIdentity.OperatorAddress, FeeDenom: cfg.Tx.FeeDenom,
		Profiles: profiles, Dispatch: cfg.Dispatch, Capacity: capacity,
		Local: rt.HandraiseLocal(), Anchor: daemon.AnchorProberOf(rt.Dependencies.Model), AnchorAdmission: rt.AnchorAdmission(), ChainPause: pause,
		Panel: panel, AuditOnly: cfg.AuditOnly(),
		Sign: rt.DispatchSigner(), Submitter: submitter,
		HandraiseChain: chain, DispatchChain: chain, VerifierChain: chain, OmissionChain: chain,
		Rosters: rt.DispatchRosters(),
	})
}

// registerDispatchHealth adds the stream rows before any readiness lands:
// per-Builder rows optional, the aggregate row gating /readyz (S9 Q4).
func registerDispatchHealth(health *observability.Health, rt *daemon.Runtime) {
	if health == nil || rt == nil || rt.Dispatch == nil {
		return
	}
	for _, s := range rt.Dispatch.Statuses() {
		health.RegisterDependency(s.Name, s.Name == daemon.DependencyDispatchStreams)
	}
}

// newPanelHandraiser builds the answer to OPEN_VERIFY for Verifier panel rounds
// of anchor audits, or nil when the audit capability is off. It needs the
// Builder streams, the chain's candidate window and the node's service key:
// no model service.
func newPanelHandraiser(cfg config.Config, rt *daemon.Runtime) (*daemon.PanelHandraiser, error) {
	if !cfg.Verifier.Audit.Enabled {
		return nil, nil
	}
	members, ok := rt.Dependencies.Keeper.(daemon.PanelMemberReader)
	if !ok {
		return nil, fmt.Errorf("verifier.audit needs a Keeper client that reads the Verifier candidate window")
	}
	keys, ok := rt.Dependencies.Keeper.(daemon.VerifierStreamChain)
	if !ok || rt.Dispatch == nil {
		return nil, fmt.Errorf("verifier.audit needs the node's service key on chain and its Builder streams (dispatch.builders)")
	}
	operator := cfg.LocalIdentity.OperatorAddress
	return daemon.NewPanelHandraiser(daemon.PanelHandraiserConfig{
		ChainID: cfg.ChainID, Operator: operator, Members: members,
		// The node's own current service key, from one committed read.
		Binding: func(ctx context.Context) (uint64, error) {
			key, _, err := keys.CommittedCurrentServiceKey(ctx, chainclient.ParticipantTypeCortexNode, operator)
			if err != nil {
				return 0, err
			}
			if key.Status != "ACTIVE" {
				return 0, fmt.Errorf("this node's service key is %s", key.Status)
			}
			return key.AuthorizationNonce.Uint64(), nil
		},
		Sign: rt.DispatchSigner(), Sender: rt.Dispatch.Fanout(), Logger: slog.Default(),
	})
}
