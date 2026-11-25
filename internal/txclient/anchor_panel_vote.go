package txclient

import "fmt"

// MsgSubmitAnchorPanelVote is a panel member's vote on an anchor audit (wire
// v0.6.3-verifier-flow.1, task/v1/anchor_panel.proto). The Cosmos signer is
// submitter_address: the Verifier's current service address.
//
// The generated bindings in proto/ predate the message, so this is a
// hand-mirrored payload like ReportDataUnavailableMessage: the JSON field
// names are the proto field names and the enums are their ProtoJSON names.
const MsgSubmitAnchorPanelVote Kind = "/task.v1.MsgSubmitAnchorPanelVote"

// The AnchorVerdictV1 names a panel member may cast.
const (
	AnchorVerdictPass        = "ANCHOR_VERDICT_V1_PASS"
	AnchorVerdictReject      = "ANCHOR_VERDICT_V1_REJECT"
	AnchorVerdictUnavailable = "ANCHOR_VERDICT_V1_UNAVAILABLE"
)

// AnchorPositionVerdictMessage mirrors task.v1.AnchorPositionVerdictV1.
type AnchorPositionVerdictMessage struct {
	Position ProtoUint64 `json:"position"`
	Verdict  string      `json:"verdict"`
	Reason   string      `json:"reason,omitempty"`
}

// SubmitAnchorPanelVoteMessage mirrors task.v1.MsgSubmitAnchorPanelVote.
// panel_round is the verify-round number of the panel round (2 for the first
// panel of a task whose round 1 selected nobody).
type SubmitAnchorPanelVoteMessage struct {
	TaskID                  ProtoBytes32                   `json:"task_id"`
	PanelRound              ProtoUint32                    `json:"panel_round"`
	OpeningHash             ProtoBytes32                   `json:"opening_hash,omitempty"`
	ProofHash               ProtoBytes32                   `json:"proof_hash,omitempty"`
	Verdict                 string                         `json:"verdict"`
	Verdicts                []AnchorPositionVerdictMessage `json:"verdicts,omitempty"`
	VerifierOperatorAddress string                         `json:"verifier_operator_address"`
	SubmitterAddress        string                         `json:"submitter_address"`
}

func validateSubmitAnchorPanelVote(m SubmitAnchorPanelVoteMessage) error {
	if err := requireStrings(m.VerifierOperatorAddress, m.SubmitterAddress); err != nil {
		return err
	}
	if err := validateHashHex(m.TaskID.Hex()); err != nil {
		return fmt.Errorf("panel vote task_id: %w", err)
	}
	if m.PanelRound < 2 {
		return fmt.Errorf("panel vote panel_round must be at least 2: round 1 of an anchor-only task has no Verifier")
	}
	switch m.Verdict {
	case AnchorVerdictPass, AnchorVerdictReject:
		if err := validateHashHex(m.OpeningHash.Hex()); err != nil {
			return fmt.Errorf("panel vote opening_hash: %w", err)
		}
		if err := validateHashHex(m.ProofHash.Hex()); err != nil {
			return fmt.Errorf("panel vote proof_hash: %w", err)
		}
		if len(m.Verdicts) == 0 {
			return fmt.Errorf("a PASS or REJECT panel vote lists the sampled positions")
		}
		rejects := 0
		for _, v := range m.Verdicts {
			switch v.Verdict {
			case AnchorVerdictPass:
			case AnchorVerdictReject:
				rejects++
			default:
				return fmt.Errorf("panel vote position %d has verdict %q, not PASS or REJECT", v.Position, v.Verdict)
			}
		}
		if (m.Verdict == AnchorVerdictPass) != (rejects == 0) {
			return fmt.Errorf("panel vote %s disagrees with its position verdicts", m.Verdict)
		}
	case AnchorVerdictUnavailable:
		if len(m.Verdicts) != 0 {
			return fmt.Errorf("an UNAVAILABLE panel vote lists no positions")
		}
	default:
		return fmt.Errorf("panel vote verdict %q is not PASS, REJECT or UNAVAILABLE", m.Verdict)
	}
	return nil
}
