package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/nodewire"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// A Verifier panel round of an anchor audit is one more verify round of the
// task: round 1 of an anchor-only task has no Verifier, the first panel is
// round 2, and every later round (retry, re-audit) takes the next number. The
// Builder opens it with an ordinary OPEN_VERIFY that names that round, and a
// node with the audit capability answers with an ordinary VerifierHandraiseV1.
//
// PanelHandraiser is that answer. It is separate from the logprob Verifier
// path on purpose: a panel member recomputes nothing with a model, fetches
// nothing from the Builder and needs no local task record, so the hand-raise
// needs only the chain's candidate window (this node's slot in it) and the
// node's service key. A node with no model service can run it.
//
// What it does not decide: whether this node may serve (the audit capability,
// its bond, the separation from block producers). The chain's window lists
// only eligible members, so a node that is not in it sends nothing.

// PanelMemberReader reads this node's slot in a round's candidate window.
type PanelMemberReader interface {
	VerifierCandidateMember(ctx context.Context, taskID string, verifyRound uint32, operatorAddress string) (chainclient.VerifierCandidateMemberSnapshot, error)
}

// PanelHandraiseSender queues a signed hand-raise to the Builders.
type PanelHandraiseSender interface {
	SendVerifierHandraise(ctx context.Context, h *taskv1.VerifierHandraiseV1) error
}

// PanelHandraiserConfig is what a PanelHandraiser needs.
type PanelHandraiserConfig struct {
	ChainID  string
	Operator string
	Members  PanelMemberReader
	// Binding returns the node's current service_authorization_nonce.
	Binding func(ctx context.Context) (nonce uint64, err error)
	Sign    dispatchwire.DigestSigner
	Sender  PanelHandraiseSender
	// Every paces the retries of rounds whose window is not READY yet.
	Every  time.Duration
	Logger *slog.Logger
}

// firstPanelRound is the lowest verify round that is a panel round.
const firstPanelRound = 2

// maxPanelAttempts bounds the retries of a round whose window cannot be read.
const maxPanelAttempts = 600

// maxPanelPending bounds the rounds waiting for their window.
const maxPanelPending = 4096

type panelOpen struct {
	taskID, worker   string
	round            uint32
	modelID          []byte
	profileVersion   uint32
	outputHash       []byte
	inferReceiptHash []byte
	attempts         int
}

// PanelHandraiser answers OPEN_VERIFY for panel rounds.
type PanelHandraiser struct {
	cfg PanelHandraiserConfig
	log *slog.Logger

	mu      sync.Mutex
	pending map[string]*panelOpen
	done    map[string]struct{}
}

// NewPanelHandraiser checks the configuration.
func NewPanelHandraiser(cfg PanelHandraiserConfig) (*PanelHandraiser, error) {
	if cfg.ChainID == "" || cfg.Operator == "" || cfg.Members == nil || cfg.Binding == nil || cfg.Sign == nil || cfg.Sender == nil {
		return nil, errors.New("panel handraiser: chain id, operator, window reader, service binding, signer and sender are required")
	}
	if cfg.Every <= 0 {
		cfg.Every = 2 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &PanelHandraiser{cfg: cfg, log: cfg.Logger.With("component", "panel-handraise"),
		pending: map[string]*panelOpen{}, done: map[string]struct{}{}}, nil
}

func panelKey(taskID string, round uint32) string { return fmt.Sprintf("%s/%d", taskID, round) }

// IsPanelRound reports whether an OPEN_VERIFY names a panel round.
func IsPanelRound(m *nexusv1.OpenVerifyV1) bool { return m.GetVerifyRound() >= firstPanelRound }

// OpenVerify takes an OPEN_VERIFY for a panel round. The caller has checked the
// Builder's signature and binding. A malformed message is a permanent error; a
// well-formed one is remembered and answered by Step.
func (p *PanelHandraiser) OpenVerify(m *nexusv1.OpenVerifyV1) error {
	switch {
	case !IsPanelRound(m):
		return builderclient.Permanent(fmt.Errorf("OPEN_VERIFY verify_round %d is not a panel round", m.GetVerifyRound()))
	case len(m.GetTaskId()) != 32 || len(m.GetModelId()) != 32 || len(m.GetOutputHash()) != 32 || len(m.GetInferReceiptHash()) != 32:
		return builderclient.Permanent(errors.New("panel OPEN_VERIFY: task_id, model_id, output_hash and infer_receipt_hash must be 32 bytes"))
	case m.GetProfileVersion() == 0 || m.GetWorkerOperatorAddress() == "":
		return builderclient.Permanent(errors.New("panel OPEN_VERIFY: profile_version and worker are required"))
	}
	if m.GetWorkerOperatorAddress() == p.cfg.Operator {
		return nil // the Worker of the task never sits on its own panel
	}
	taskID := hex.EncodeToString(m.GetTaskId())
	key := panelKey(taskID, m.GetVerifyRound())
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.done[key]; ok {
		return nil
	}
	if _, ok := p.pending[key]; ok {
		return nil
	}
	if len(p.pending) >= maxPanelPending {
		return builderclient.Retryable(errors.New("panel handraiser: too many rounds are waiting for their window"))
	}
	p.pending[key] = &panelOpen{
		taskID: taskID, worker: m.GetWorkerOperatorAddress(), round: m.GetVerifyRound(),
		modelID: append([]byte(nil), m.GetModelId()...), profileVersion: m.GetProfileVersion(),
		outputHash: append([]byte(nil), m.GetOutputHash()...), inferReceiptHash: append([]byte(nil), m.GetInferReceiptHash()...),
	}
	return nil
}

// Run answers pending rounds until ctx ends.
func (p *PanelHandraiser) Run(ctx context.Context) error {
	t := time.NewTicker(p.cfg.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			p.Step(ctx)
		}
	}
}

// Step tries every pending round once.
func (p *PanelHandraiser) Step(ctx context.Context) {
	p.mu.Lock()
	keys := make([]string, 0, len(p.pending))
	for key := range p.pending {
		keys = append(keys, key)
	}
	p.mu.Unlock()
	sort.Strings(keys)
	for _, key := range keys {
		if ctx.Err() != nil {
			return
		}
		p.mu.Lock()
		open := p.pending[key]
		p.mu.Unlock()
		if open == nil {
			continue
		}
		finished, err := p.raise(ctx, open)
		p.mu.Lock()
		open.attempts++
		if finished {
			delete(p.pending, key)
			p.done[key] = struct{}{}
			if len(p.done) > 4*maxPanelPending {
				p.done = map[string]struct{}{key: {}}
			}
		}
		p.mu.Unlock()
		switch {
		case err != nil && finished:
			p.log.Warn("panel handraise abandoned", "task_id", open.taskID, "panel_round", open.round, "error", err)
		case err != nil:
			p.log.Debug("panel handraise not sent yet", "task_id", open.taskID, "panel_round", open.round, "attempts", open.attempts, "error", err)
		}
	}
}

// raise sends the hand-raise of one round. finished is true when nothing more
// is to be tried for it: sent, the window closed, or this node is not in it.
func (p *PanelHandraiser) raise(ctx context.Context, open *panelOpen) (finished bool, err error) {
	member, err := p.cfg.Members.VerifierCandidateMember(ctx, open.taskID, open.round, p.cfg.Operator)
	switch {
	case errors.Is(err, chainclient.ErrVerifierWindowNotReady):
		return false, err
	case errors.Is(err, chainclient.ErrVerifierWindowClosed):
		p.log.Info("panel round closed before this node raised its hand", "task_id", open.taskID, "panel_round", open.round)
		return true, nil
	case errors.Is(err, chainclient.ErrNotVerifierCandidate):
		// Not in the window: no audit capability for the model, not effective
		// yet, excluded, or simply not among the candidates.
		p.log.Debug("this node is not a candidate of the panel round", "task_id", open.taskID, "panel_round", open.round)
		return true, nil
	case err != nil:
		// The window may not exist yet (the Builder can be ahead of this
		// node's view of the chain) or the node may be unreachable: retried,
		// but not for ever.
		if open.attempts >= maxPanelAttempts {
			p.log.Warn("panel round given up: its candidate window was never readable", "task_id", open.taskID, "panel_round", open.round, "error", err)
			return true, nil
		}
		return false, err
	}
	if member.OperatorAddress != p.cfg.Operator {
		return true, fmt.Errorf("candidate window answered for %s, not this node", member.OperatorAddress)
	}
	receipt := []byte(member.InferReceiptHash)
	if len(receipt) != 32 || !bytes.Equal(receipt, open.inferReceiptHash) {
		// The Builder's message disagrees with the chain: never sign it.
		p.log.Warn("panel OPEN_VERIFY names another infer receipt than the chain's window; no hand-raise", "task_id", open.taskID, "panel_round", open.round)
		return true, nil
	}
	snapshotID := []byte(member.CandidatePoolSnapshotID)
	taskID, _ := hex.DecodeString(open.taskID)
	nonce, err := p.cfg.Binding(ctx)
	if err != nil {
		return false, fmt.Errorf("current service binding: %w", err)
	}
	handraise := nodewire.VerifierHandraiseV1{
		SchemaVersion: nodewire.VerifierHandraiseSchemaVersionV1, ChainID: p.cfg.ChainID,
		TaskID: taskID, VerifyRound: open.round,
		InferReceiptHash: receipt, OutputHash: open.outputHash,
		ModelID: open.modelID, ProfileVersion: open.profileVersion,
		Member: nodewire.CandidateMemberRefV1{
			CandidatePoolSnapshotID: snapshotID, Slot: member.Slot, SlotVersion: member.SlotVersion, OperatorAddress: member.OperatorAddress,
		},
		Duty: nodewire.DutyVerifier, ServiceAuthorizationNonce: nonce, ExpiryHeight: member.ExpiryHeight,
	}
	digest, err := nodewire.VerifierHandraiseSigningDigest(handraise)
	if err != nil {
		return true, err
	}
	signature, err := p.cfg.Sign(ctx, digest)
	if err != nil {
		return false, fmt.Errorf("sign panel handraise: %w", err)
	}
	handraise.ServiceSignature = signature
	message, err := builderclient.VerifierHandraiseProto(handraise)
	if err != nil {
		return true, err
	}
	if err := p.cfg.Sender.SendVerifierHandraise(ctx, message); err != nil {
		if builderclient.IsPermanent(err) {
			return true, err
		}
		return false, err
	}
	p.log.Info("panel handraise sent", "task_id", open.taskID, "panel_round", open.round, "slot", member.Slot, "expiry_height", member.ExpiryHeight)
	return true, nil
}
