package txclient

import (
	"strings"
	"testing"
)

const (
	voteTask = "aa00000000000000000000000000000000000000000000000000000000000000"
	voteOpen = "0100000000000000000000000000000000000000000000000000000000000000"
	voteProf = "0200000000000000000000000000000000000000000000000000000000000000"
)

func panelVote(verdict string, positions ...string) SubmitAnchorPanelVoteMessage {
	m := SubmitAnchorPanelVoteMessage{TaskID: voteTask, PanelRound: 2, Verdict: verdict,
		VerifierOperatorAddress: "op", SubmitterAddress: "svc"}
	if verdict != AnchorVerdictUnavailable {
		m.OpeningHash, m.ProofHash = voteOpen, voteProf
	}
	for i, p := range positions {
		m.Verdicts = append(m.Verdicts, AnchorPositionVerdictMessage{Position: ProtoUint64(i), Verdict: p})
	}
	return m
}

func TestPanelVotePayload(t *testing.T) {
	if !MsgSubmitAnchorPanelVote.Valid() {
		t.Fatal("MsgSubmitAnchorPanelVote is not a valid kind")
	}
	for _, m := range []SubmitAnchorPanelVoteMessage{
		panelVote(AnchorVerdictPass, AnchorVerdictPass, AnchorVerdictPass),
		panelVote(AnchorVerdictReject, AnchorVerdictPass, AnchorVerdictReject),
		panelVote(AnchorVerdictUnavailable),
	} {
		payload, err := MarshalMessage(MsgSubmitAnchorPanelVote, m)
		if err != nil {
			t.Fatalf("%s: %v", m.Verdict, err)
		}
		if err := ValidateMessagePayload(MsgSubmitAnchorPanelVote, payload); err != nil {
			t.Fatalf("%s payload: %v", m.Verdict, err)
		}
		for _, field := range []string{`"task_id"`, `"panel_round"`, `"verdict"`, `"verifier_operator_address"`, `"submitter_address"`} {
			if !strings.Contains(string(payload), field) {
				t.Fatalf("payload %s lacks %s", payload, field)
			}
		}
	}
}

func TestPanelVoteRefusals(t *testing.T) {
	round1 := panelVote(AnchorVerdictUnavailable)
	round1.PanelRound = 1
	noHash := panelVote(AnchorVerdictPass, AnchorVerdictPass)
	noHash.ProofHash = ""
	noSubmitter := panelVote(AnchorVerdictUnavailable)
	noSubmitter.SubmitterAddress = ""
	for name, m := range map[string]SubmitAnchorPanelVoteMessage{
		"round 1":                   round1,
		"no proof hash":             noHash,
		"no submitter":              noSubmitter,
		"NO_VERDICT":                panelVote("ANCHOR_VERDICT_V1_NO_VERDICT"),
		"pass with a reject":        panelVote(AnchorVerdictPass, AnchorVerdictReject),
		"reject without one":        panelVote(AnchorVerdictReject, AnchorVerdictPass),
		"pass without positions":    panelVote(AnchorVerdictPass),
		"unavailable with position": {TaskID: voteTask, PanelRound: 2, Verdict: AnchorVerdictUnavailable, VerifierOperatorAddress: "op", SubmitterAddress: "svc", Verdicts: []AnchorPositionVerdictMessage{{Verdict: AnchorVerdictPass}}},
	} {
		if _, err := MarshalMessage(MsgSubmitAnchorPanelVote, m); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

func TestSupportDeclarationWithAuditCapability(t *testing.T) {
	model := ProtoBytes32(voteTask)
	legacy, err := MarshalMessage(MsgDeclareModelSupport, DeclareModelSupportMessage{OperatorAddress: "op", ModelID: model, InferenceCapability: true, VerificationCapability: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(legacy), "audit_capability") {
		t.Fatalf("a declaration without the audit capability must be unchanged, got %s", legacy)
	}
	auditOnly, err := MarshalMessage(MsgDeclareModelSupport, DeclareModelSupportMessage{OperatorAddress: "op", ModelID: model, AuditCapability: true})
	if err != nil {
		t.Fatalf("an audit-only declaration is valid: %v", err)
	}
	if !strings.Contains(string(auditOnly), `"audit_capability":true`) {
		t.Fatalf("payload %s", auditOnly)
	}
	if err := ValidateMessagePayload(MsgDeclareModelSupport, auditOnly); err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalMessage(MsgDeclareModelSupport, DeclareModelSupportMessage{OperatorAddress: "op", ModelID: model}); err == nil {
		t.Fatal("a declaration with no capability is refused")
	}
}
