package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

const panelOperator = hrCortex

type fakePanelMembers struct {
	mu    sync.Mutex
	err   error
	snap  chainclient.VerifierCandidateMemberSnapshot
	calls []string
}

func (f *fakePanelMembers) VerifierCandidateMember(_ context.Context, taskID string, round uint32, operator string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("%s/%d/%s", taskID, round, operator))
	return f.snap, f.err
}

func (f *fakePanelMembers) set(snap chainclient.VerifierCandidateMemberSnapshot, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snap, f.err = snap, err
}

type fakePanelSender struct {
	sent []*taskv1.VerifierHandraiseV1
	err  error
}

func (f *fakePanelSender) SendVerifierHandraise(_ context.Context, h *taskv1.VerifierHandraiseV1) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, h)
	return nil
}

func panelHash(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func panelOpenVerify(round uint32) *nexusv1.OpenVerifyV1 {
	return &nexusv1.OpenVerifyV1{TaskId: panelHash(0xa1), TaskHash: panelHash(0xa2), ModelId: panelHash(0xa3), ProfileVersion: 2,
		InferReceiptHash: panelHash(0xa4), OutputHash: panelHash(0xa5), WorkerOperatorAddress: "trueopen1worker", VerifyRound: round}
}

func panelMember() chainclient.VerifierCandidateMemberSnapshot {
	return chainclient.VerifierCandidateMemberSnapshot{
		CandidateMemberRefSnapshot: chainclient.CandidateMemberRefSnapshot{
			CandidatePoolSnapshotID: chainclient.ProtoBytes32(panelHash(0xb1)), Slot: 7, SlotVersion: 3, OperatorAddress: panelOperator,
		},
		InferReceiptHash: chainclient.ProtoBytes32(panelHash(0xa4)), ExpiryHeight: 500,
	}
}

type panelHarness struct {
	p       *PanelHandraiser
	members *fakePanelMembers
	sender  *fakePanelSender
	signed  [][32]byte
}

func newPanelHarness(t *testing.T) *panelHarness {
	t.Helper()
	h := &panelHarness{members: &fakePanelMembers{snap: panelMember()}, sender: &fakePanelSender{}}
	p, err := NewPanelHandraiser(PanelHandraiserConfig{
		ChainID: "chain-1", Operator: panelOperator, Members: h.members, Sender: h.sender, Every: time.Millisecond,
		Binding: func(context.Context) (uint64, error) { return 9, nil },
		Sign: func(_ context.Context, d [32]byte) ([]byte, error) {
			h.signed = append(h.signed, d)
			return bytes.Repeat([]byte{0x5a}, 64), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.p = p
	return h
}

func TestPanelHandraiseIsSignedForThePanelRound(t *testing.T) {
	h := newPanelHarness(t)
	if err := h.p.OpenVerify(panelOpenVerify(2)); err != nil {
		t.Fatal(err)
	}
	h.p.Step(context.Background())
	if len(h.sender.sent) != 1 {
		t.Fatalf("sent %d hand-raises, want 1", len(h.sender.sent))
	}
	hr := h.sender.sent[0]
	if hr.GetVerifyRound() != 2 || hr.GetChainId() != "chain-1" || !bytes.Equal(hr.GetTaskId(), panelHash(0xa1)) ||
		!bytes.Equal(hr.GetInferReceiptHash(), panelHash(0xa4)) || !bytes.Equal(hr.GetOutputHash(), panelHash(0xa5)) ||
		!bytes.Equal(hr.GetModelId(), panelHash(0xa3)) || hr.GetProfileVersion() != 2 ||
		hr.GetMember().GetOperatorAddress() != panelOperator || hr.GetMember().GetSlot() != 7 || hr.GetMember().GetSlotVersion() != 3 ||
		hr.GetServiceAuthorizationNonce() != 9 || hr.GetExpiryHeight() != 500 || len(hr.GetServiceSignature()) != 64 {
		t.Fatalf("hand-raise %+v", hr)
	}
	// The signature is over the wire digest of exactly this hand-raise.
	want, err := nodewire.VerifierHandraiseSigningDigest(nodewire.VerifierHandraiseV1{
		SchemaVersion: 1, ChainID: "chain-1", TaskID: panelHash(0xa1), VerifyRound: 2, InferReceiptHash: panelHash(0xa4), OutputHash: panelHash(0xa5),
		ModelID: panelHash(0xa3), ProfileVersion: 2, Duty: nodewire.DutyVerifier, ServiceAuthorizationNonce: 9, ExpiryHeight: 500,
		Member: nodewire.CandidateMemberRefV1{CandidatePoolSnapshotID: panelHash(0xb1), Slot: 7, SlotVersion: 3, OperatorAddress: panelOperator},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.signed) != 1 || h.signed[0] != [32]byte(want) {
		t.Fatal("the signed digest is not the hand-raise's wire digest")
	}
	// The same OPEN_VERIFY again (another Builder, a reconnect) sends nothing more.
	if err := h.p.OpenVerify(panelOpenVerify(2)); err != nil {
		t.Fatal(err)
	}
	h.p.Step(context.Background())
	if len(h.sender.sent) != 1 {
		t.Fatal("one hand-raise per round")
	}
	// The retry is a new round with its own hand-raise.
	if err := h.p.OpenVerify(panelOpenVerify(3)); err != nil {
		t.Fatal(err)
	}
	h.p.Step(context.Background())
	if len(h.sender.sent) != 2 || h.sender.sent[1].GetVerifyRound() != 3 {
		t.Fatalf("round 3 must get its own hand-raise, sent %d", len(h.sender.sent))
	}
}

func TestPanelHandraiseWaitsForTheWindowAndStopsWhenItCloses(t *testing.T) {
	h := newPanelHarness(t)
	h.members.set(chainclient.VerifierCandidateMemberSnapshot{}, fmt.Errorf("%w: beacon pending", chainclient.ErrVerifierWindowNotReady))
	if err := h.p.OpenVerify(panelOpenVerify(2)); err != nil {
		t.Fatal(err)
	}
	h.p.Step(context.Background())
	h.p.Step(context.Background())
	if len(h.sender.sent) != 0 {
		t.Fatal("nothing is sent before the window is READY")
	}
	h.members.set(panelMember(), nil)
	h.p.Step(context.Background())
	if len(h.sender.sent) != 1 {
		t.Fatal("the hand-raise goes out once the window is READY")
	}

	closed := newPanelHarness(t)
	closed.members.set(chainclient.VerifierCandidateMemberSnapshot{}, fmt.Errorf("%w: late", chainclient.ErrVerifierWindowClosed))
	_ = closed.p.OpenVerify(panelOpenVerify(2))
	closed.p.Step(context.Background())
	closed.members.set(panelMember(), nil)
	closed.p.Step(context.Background())
	if len(closed.sender.sent) != 0 {
		t.Fatal("a closed round is dropped, not retried")
	}
}

func TestPanelHandraiseIsNotSentWhenTheNodeMayNotServe(t *testing.T) {
	// Not in the window: no audit capability for the model, or excluded.
	h := newPanelHarness(t)
	h.members.set(chainclient.VerifierCandidateMemberSnapshot{}, fmt.Errorf("wrapped: %w", chainclient.ErrNotVerifierCandidate))
	_ = h.p.OpenVerify(panelOpenVerify(2))
	h.p.Step(context.Background())
	h.p.Step(context.Background())
	if len(h.sender.sent) != 0 || len(h.members.calls) != 1 {
		t.Fatalf("a node outside the window sends nothing and asks once: sent %d, reads %d", len(h.sender.sent), len(h.members.calls))
	}

	// The task's own Worker.
	own := newPanelHarness(t)
	m := panelOpenVerify(2)
	m.WorkerOperatorAddress = panelOperator
	if err := own.p.OpenVerify(m); err != nil {
		t.Fatal(err)
	}
	own.p.Step(context.Background())
	if len(own.sender.sent) != 0 || len(own.members.calls) != 0 {
		t.Fatal("the Worker never raises its hand for its own panel")
	}

	// The Builder's receipt hash differs from the chain's window.
	forged := newPanelHarness(t)
	f := panelOpenVerify(2)
	f.InferReceiptHash = panelHash(0xff)
	_ = forged.p.OpenVerify(f)
	forged.p.Step(context.Background())
	if len(forged.sender.sent) != 0 || len(forged.signed) != 0 {
		t.Fatal("a hand-raise for a receipt the chain does not hold must not be signed")
	}
}

func TestPanelOpenVerifyRefusals(t *testing.T) {
	h := newPanelHarness(t)
	if err := h.p.OpenVerify(panelOpenVerify(1)); err == nil || !builderclient.IsPermanent(err) {
		t.Fatalf("round 1 is not a panel round: %v", err)
	}
	short := panelOpenVerify(2)
	short.OutputHash = []byte{1}
	if err := h.p.OpenVerify(short); err == nil {
		t.Fatal("a malformed OPEN_VERIFY is refused")
	}
	// A transient sender failure keeps the round for the next step.
	h.sender.err = errors.New("stream down")
	_ = h.p.OpenVerify(panelOpenVerify(2))
	h.p.Step(context.Background())
	h.sender.err = nil
	h.p.Step(context.Background())
	if len(h.sender.sent) != 1 {
		t.Fatal("a failed send is retried")
	}
}

func TestStandingHandraiseOffersNothingOnAnAuditOnlyNode(t *testing.T) {
	x := newHRHarness(t, nil)
	x.warm()
	x.tweak = func(c *StandingHandraiseConfig) { c.AuditOnly = true }
	x.open()
	x.step(100*time.Millisecond, 102)
	x.step(10*time.Second, 106)
	x.step(10*time.Second, 110)
	for _, b := range []*fakeEnqueuer{x.a, x.b} {
		hs := b.handraises()
		// What the harness sent before the node was reopened as audit-only is
		// withdrawn, and nothing is offered after.
		if last := hs[len(hs)-1]; last.GetFreeSlotCount() != 0 || len(last.GetProfiles()) != 0 {
			t.Fatalf("an audit-only node advertises inference: %v", last)
		}
	}
}

func TestDispatcherRefusesEveryOfferOnAnAuditOnlyNode(t *testing.T) {
	x := newDispatchHarness(t, 2, func(c *DispatcherConfig) { c.AuditOnly = true })
	if err := x.handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := x.record(t)
	if rec.State != layout.DispatchRejected || rec.RejectClass != classAuditOnly || rec.RejectReason != int32(reasonNoCapacity) {
		t.Fatalf("record = %s %s %d, want a NO_CAPACITY reject of class %s", rec.State, rec.RejectClass, rec.RejectReason, classAuditOnly)
	}
	if len(x.infer.starts()) != 0 {
		t.Fatal("no inference starts on an audit-only node")
	}
}

// The Verifier stream hands a panel round to the panel handraiser only when
// one is configured; without it a round above 1 is refused as before, and
// round 1 never reaches the panel handraiser.
func TestVerifierStreamRoutesPanelRounds(t *testing.T) {
	binding := &nexusv1.BuilderMessageBindingV1{ChainId: "chain", BuilderAddress: "builder-1", ServiceAuthorizationNonce: 1}
	frame := func(round uint32) *nexusv1.DispatchStreamFrameV1 {
		m := panelOpenVerify(round)
		m.Binding = binding
		return &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_OpenVerify{OpenVerify: m}}
	}
	legacy := newVSHarness(t)
	if err := legacy.stream.HandleFrame(context.Background(), "builder-1", frame(2)); err == nil {
		t.Fatal("without the audit capability a round 2 OPEN_VERIFY is refused, as before")
	}

	h := newPanelHarness(t)
	with := newVSHarness(t)
	with.stream.cfg.Panel = h.p
	if err := with.stream.HandleFrame(context.Background(), "builder-1", frame(2)); err != nil {
		t.Fatal(err)
	}
	h.p.Step(context.Background())
	if len(h.sender.sent) != 1 || h.sender.sent[0].GetVerifyRound() != 2 {
		t.Fatalf("the panel round must be answered by the panel handraiser, sent %d", len(h.sender.sent))
	}
	if with.wakes.Load() != 0 {
		t.Fatal("a panel round does not enter the logprob Verifier inbox")
	}
	// Round 1 still takes the logprob path.
	if err := with.stream.HandleFrame(context.Background(), "builder-1", frame(1)); err != nil {
		t.Fatal(err)
	}
	if len(h.sender.sent) != 1 || with.wakes.Load() != 1 {
		t.Fatalf("round 1 must go to the logprob inbox: panel sent %d, wakes %d", len(h.sender.sent), with.wakes.Load())
	}
}
