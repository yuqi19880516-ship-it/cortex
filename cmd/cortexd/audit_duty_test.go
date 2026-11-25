package main

import (
	"context"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/auditduty"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/txclient"
)

type auditKeeper struct{ daemon.KeeperClient }

func (auditKeeper) PanelAssignments(context.Context, string) ([]chainclient.PanelAssignment, error) {
	return nil, chainclient.ErrQueryUnsupported
}

func cleanHost() auditduty.Host {
	return auditduty.Host{Env: func(string) string { return "" }, Exists: func(string) bool { return false }}
}

func TestAuditDutyIsOffByDefault(t *testing.T) {
	r, err := newAuditDuty(config.Config{}, &daemon.Runtime{}, cleanHost())
	if r != nil || err != nil {
		t.Fatalf("an unconfigured node must not build the audit duty: %v %v", r, err)
	}
}

func TestAuditDutyRefusesABlockProducersMachine(t *testing.T) {
	cfg := config.Config{}
	cfg.Verifier.Audit = config.AuditDutyConfig{Enabled: true, SpoolDir: t.TempDir(), NodeHomes: []string{"/srv/node"}}
	host := auditduty.Host{Env: func(string) string { return "" },
		Exists: func(p string) bool { return p == "/srv/node/config/priv_validator_key.json" }}
	rt := &daemon.Runtime{}
	rt.Dependencies.Keeper = auditKeeper{}
	_, err := newAuditDuty(cfg, rt, host)
	if err == nil || !strings.Contains(err.Error(), "block producer") {
		t.Fatalf("want a refusal, got %v", err)
	}
}

func TestAuditDutyStartsOnACleanMachine(t *testing.T) {
	cfg := config.Config{ChainID: "chain-1"}
	cfg.LocalIdentity.OperatorAddress = "op"
	cfg.Verifier.Audit = config.AuditDutyConfig{Enabled: true, SpoolDir: t.TempDir()}
	rt := &daemon.Runtime{}
	rt.Dependencies.Keeper = auditKeeper{}
	r, err := newAuditDuty(cfg, rt, cleanHost())
	if err != nil || r == nil {
		t.Fatalf("got %v %v", r, err)
	}
	if err := r.Step(context.Background()); err != nil {
		t.Fatalf("a chain without panels leaves the duty idle: %v", err)
	}
}

type fakeTx struct {
	reqs   []txclient.Request
	reject string
}

func (f *fakeTx) Submit(_ context.Context, r txclient.Request) (txclient.Observation, error) {
	f.reqs = append(f.reqs, r)
	if f.reject != "" {
		return txclient.Observation{Rejected: true, RejectReason: f.reject}, nil
	}
	return txclient.Observation{Accepted: true}, nil
}

func TestPanelVoteSubmitterBroadcastsTheSpoolVote(t *testing.T) {
	const task = "aa00000000000000000000000000000000000000000000000000000000000000"
	const h1 = "0100000000000000000000000000000000000000000000000000000000000000"
	tx := &fakeTx{}
	ready := false
	s := &panelVoteSubmitter{operator: "op", workload: func() (txclient.Client, string) {
		if !ready {
			return nil, ""
		}
		return tx, "svc"
	}}
	vote := auditduty.VoteFile{TaskID: task, PanelRound: 2, Vote: auditduty.VoteReject, OpeningHash: h1, ProofHash: h1,
		Positions: []auditduty.PositionVerdict{{Position: 4, Verdict: auditduty.VotePass}, {Position: 9, Verdict: auditduty.VoteReject}}}
	if err := s.SubmitPanelVote(context.Background(), vote); err == nil {
		t.Fatal("before the service identity is confirmed nothing can be sent")
	}
	ready = true
	if err := s.SubmitPanelVote(context.Background(), vote); err != nil {
		t.Fatal(err)
	}
	if len(tx.reqs) != 1 || tx.reqs[0].Kind != txclient.MsgSubmitAnchorPanelVote || tx.reqs[0].GasPayer != "svc" {
		t.Fatalf("requests %+v", tx.reqs)
	}
	payload := string(tx.reqs[0].Payload)
	for _, want := range []string{`"panel_round":2`, `"verdict":"ANCHOR_VERDICT_V1_REJECT"`, `"verifier_operator_address":"op"`, `"submitter_address":"svc"`, `"position":"9"`} {
		if !strings.Contains(payload, want) {
			t.Fatalf("payload %s lacks %s", payload, want)
		}
	}
	tx.reject = "panel round is closed"
	if err := s.SubmitPanelVote(context.Background(), vote); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("a refusal must be reported, got %v", err)
	}
}

func TestVoteSubmissionIsOptIn(t *testing.T) {
	cfg := config.Config{ChainID: "chain-1"}
	cfg.LocalIdentity.OperatorAddress = "op"
	cfg.Verifier.Audit = config.AuditDutyConfig{Enabled: true, SpoolDir: t.TempDir()}
	rt := &daemon.Runtime{}
	rt.Dependencies.Keeper = auditKeeper{}
	if _, err := newAuditDuty(cfg, rt, cleanHost()); err != nil {
		t.Fatal(err)
	}
	var c config.Config
	c.Verifier.Audit = config.AuditDutyConfig{Enabled: true, SpoolDir: "/x", SubmitVotes: true}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "submit_votes needs tx.enabled") {
		t.Fatalf("submit_votes without a transaction path must be refused, got %v", err)
	}
}
