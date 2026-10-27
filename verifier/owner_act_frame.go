package verifier

import (
	"bytes"
	"encoding/binary"

	"github.com/relux-works/swarma-envelope/owneracts"
)

// OwnerActRequestFrame is ordinary caller-mutable, grammar-only request data.
// Body and Arguments own their bytes. Correlation and EnrollmentSelector retain
// all 32 opaque bytes, including zeroes; neither establishes identity, freshness
// or independently protected enrollment. A value copy shares its byte slices.
type OwnerActRequestFrame struct {
	Correlation        [32]byte
	EnrollmentSelector [32]byte
	Body               []byte
	Arguments          []byte
}

// OwnerActFrameError is a fixed local framing refusal with no received data,
// native diagnostic or consumer verdict. Every failure spells frame_invalid.
type OwnerActFrameError struct{}

func (*OwnerActFrameError) Error() string { return "frame_invalid" }

// OwnerActResultStatus is the explicit local result status, not a wire verdict
// or an inference from an error. Only the five named values are supported.
type OwnerActResultStatus uint32

const (
	OwnerActResultSuccess     OwnerActResultStatus = 0
	OwnerActResultRejected    OwnerActResultStatus = 1
	OwnerActResultCanceled    OwnerActResultStatus = 2
	OwnerActResultBusy        OwnerActResultStatus = 3
	OwnerActResultUnavailable OwnerActResultStatus = 4
)

// ParseOwnerActRequestFrame admits exactly one complete SEACT001 slice. All
// header/total/declared bounds precede parsing, copying or input-dependent
// allocation. Body and arguments then use the existing strict canonical
// owner-acts/1 parsers. Failure returns entirely zero data and a fixed local
// *OwnerActFrameError. Input bytes must remain stable during this synchronous
// call; no caller storage is retained or changed.
//
// Admission does not observe pipe EOF or prove body/argument digest or text
// consistency, protected key/owner/audience/epoch selection, confirmation,
// presence or authority. PrepareOwnerAct must independently check all those
// preparation associations using protected selection. Native bounded frame+EOF
// collection before UI, enrollment resolution and later provider stages remain
// separate unimplemented integration obligations.
func ParseOwnerActRequestFrame(raw []byte) (OwnerActRequestFrame, error) {
	fail := func() (OwnerActRequestFrame, error) { return OwnerActRequestFrame{}, &OwnerActFrameError{} }
	if len(raw) < 80 || len(raw) > 16464 || string(raw[:8]) != "SEACT001" {
		return fail()
	}
	bodyLen := binary.BigEndian.Uint32(raw[72:76])
	argsLen := binary.BigEndian.Uint32(raw[76:80])
	if bodyLen < 1 || bodyLen > 8192 || argsLen < 1 || argsLen > 8192 || argsLen > 2048 {
		return fail()
	}
	// Widen BEFORE addition; conversion to int follows the small explicit caps
	// and exact total check, so offsets are safe on both 32- and 64-bit hosts.
	total := uint64(80) + uint64(bodyLen) + uint64(argsLen)
	if total != uint64(len(raw)) {
		return fail()
	}
	endBody := 80 + int(bodyLen)
	body, args := raw[80:endBody], raw[endBody:]
	b, err := owneracts.ParseBody(body)
	if err != nil {
		return fail()
	}
	if _, err := owneracts.Parse(b.Operation, args); err != nil {
		return fail()
	}
	var out OwnerActRequestFrame
	copy(out.Correlation[:], raw[8:40])
	copy(out.EnrollmentSelector[:], raw[40:72])
	out.Body, out.Arguments = bytes.Clone(body), bytes.Clone(args)
	return out, nil
}

// EncodeOwnerActResultFrame returns a fresh complete SEOUT001 frame. Success
// requires a usable immutable envelope from the existing assembly path; ordinary
// request data, detached snapshots and raw signature bytes cannot construct it.
// Rejected/canceled/busy/unavailable require a nil envelope and emit exactly
// 48 bytes with zero payload length. Unknown or inconsistent statuses return
// nil and *OwnerActFrameError. No failure returns partial bytes or echoes data.
//
// Correlation is copied verbatim, not authenticated. Result bytes remain signed
// intent only, without native origin, confirmation, presence, current rights or
// consumer effect permission. Repeated pure encoding consumes no attempt and
// authorizes no native key reuse; this is not once-consuming Finalize or IO.
func EncodeOwnerActResultFrame(correlation [32]byte, status OwnerActResultStatus, envelope *VerifiedOwnerActEnvelope) ([]byte, error) {
	var wire []byte
	switch status {
	case OwnerActResultSuccess:
		var ok bool
		wire, ok = envelope.Bytes()
		if !ok || len(wire) < 1 || len(wire) > 8192 {
			return nil, &OwnerActFrameError{}
		}
	case OwnerActResultRejected, OwnerActResultCanceled, OwnerActResultBusy, OwnerActResultUnavailable:
		if envelope != nil {
			return nil, &OwnerActFrameError{}
		}
	default:
		return nil, &OwnerActFrameError{}
	}
	out := make([]byte, 48+len(wire))
	copy(out[:8], "SEOUT001")
	copy(out[8:40], correlation[:])
	binary.BigEndian.PutUint32(out[40:44], uint32(status))
	binary.BigEndian.PutUint32(out[44:48], uint32(len(wire)))
	copy(out[48:], wire)
	return out, nil
}
