package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/TrueOpen/cortex/internal/auditduty"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// newAuditDuty builds the audit capability, or returns nil when it is off. It
// refuses a machine that holds a block producer's key material: a block
// producer may not also vote on audits.
//
// By default the node only moves assignments and votes between the chain and
// the local Verifier program, and the program broadcasts its own vote. With
// verifier.audit.submit_votes the node broadcasts the vote it reads from the
// spool instead (panelVoteSubmitter).
func newAuditDuty(cfg config.Config, rt *daemon.Runtime, host auditduty.Host) (*auditduty.Runner, error) {
	audit := cfg.Verifier.Audit
	if !audit.Enabled {
		return nil, nil
	}
	if err := auditduty.RefuseIfBlockProducer(audit.NodeHomes, host); err != nil {
		return nil, err
	}
	source, ok := rt.Dependencies.Keeper.(auditduty.AssignmentSource)
	if !ok {
		return nil, fmt.Errorf("verifier.audit needs a Keeper client that reads panel assignments")
	}
	spool, err := auditduty.OpenSpool(audit.SpoolDir)
	if err != nil {
		return nil, err
	}
	var submitter auditduty.VoteSubmitter
	if audit.SubmitVotes {
		submitter = &panelVoteSubmitter{
			operator: cfg.LocalIdentity.OperatorAddress, workload: rt.WorkloadSubmitter,
			feeCap: txclient.Coin{Denom: cfg.Tx.FeeDenom, Amount: cfg.Tx.MaxFeeAmount},
		}
	}
	return auditduty.NewRunner(auditduty.Config{
		ChainID: cfg.ChainID, Operator: cfg.LocalIdentity.OperatorAddress, Source: source, Spool: spool,
		Submitter: submitter,
		PollEvery: time.Duration(audit.PollMS) * time.Millisecond, Logger: slog.Default(),
	})
}

// panelVoteSubmitter broadcasts a spool vote as MsgSubmitAnchorPanelVote,
// signed by this node's current service address.
type panelVoteSubmitter struct {
	operator string
	// workload resolves the tx client and the Keeper-confirmed service address
	// at call time; both are empty until the node's identity is confirmed.
	workload func() (txclient.Client, string)
	feeCap   txclient.Coin
}

// panelVoteMessage maps a spool vote to the chain message.
func panelVoteMessage(vote auditduty.VoteFile, operator, submitter string) (txclient.SubmitAnchorPanelVoteMessage, error) {
	verdicts := map[string]string{
		auditduty.VotePass: txclient.AnchorVerdictPass, auditduty.VoteReject: txclient.AnchorVerdictReject,
		auditduty.VoteUnavailable: txclient.AnchorVerdictUnavailable,
	}
	if err := vote.Validate(); err != nil {
		return txclient.SubmitAnchorPanelVoteMessage{}, err
	}
	msg := txclient.SubmitAnchorPanelVoteMessage{
		TaskID: txclient.ProtoBytes32(vote.TaskID), PanelRound: txclient.ProtoUint32(vote.PanelRound),
		OpeningHash: txclient.ProtoBytes32(vote.OpeningHash), ProofHash: txclient.ProtoBytes32(vote.ProofHash),
		Verdict: verdicts[vote.Vote], VerifierOperatorAddress: operator, SubmitterAddress: submitter,
	}
	for _, p := range vote.Positions {
		msg.Verdicts = append(msg.Verdicts, txclient.AnchorPositionVerdictMessage{
			Position: txclient.ProtoUint64(p.Position), Verdict: verdicts[p.Verdict],
		})
	}
	return msg, nil
}

func (s *panelVoteSubmitter) SubmitPanelVote(ctx context.Context, vote auditduty.VoteFile) error {
	client, address := s.workload()
	if client == nil || address == "" {
		return fmt.Errorf("the transaction path is not ready (service identity not confirmed yet)")
	}
	msg, err := panelVoteMessage(vote, s.operator, address)
	if err != nil {
		return err
	}
	payload, err := txclient.MarshalMessage(txclient.MsgSubmitAnchorPanelVote, msg)
	if err != nil {
		return err
	}
	observation, err := client.Submit(ctx, txclient.Request{
		TaskID: vote.TaskID, Kind: txclient.MsgSubmitAnchorPanelVote, Payload: payload,
		GasPayer: address, FeeCap: s.feeCap,
	})
	if err != nil {
		return err
	}
	if observation.Rejected {
		return fmt.Errorf("the chain refused the panel vote: %s", observation.RejectReason)
	}
	return nil
}
