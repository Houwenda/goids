package analyzer

type PktRule struct {
	Action   string
	Protocol string
	Source   string // can be ipv4, ipv6, "any"
	SrcPort  struct {
		Start int32
		End   int32
	}
	Destination string // can be ipv4, ipv6, "any"
	DstPort     struct {
		Start int32
		End   int32
	}
	Message        string
	Detection      DetectionRule
	Metadata       []string
	Reference      []string
	Classification string
	SignatureId    struct {
		Sid int32
		Rev int32
	}
}

// detection rules are in 'and' relation
// only when all conditions are satisfied
// can a packet match this rule
type DetectionRule struct {
	Content []struct {
		content  string
		inverse  bool
		nocase   bool
		depth    int32
		offset   int32
		distance int32
		within   int32
	}
	ProtectedContent []struct {
		content string
		inverse bool
		offset  int32
		length  int32
		hash    string
	}
}

type StreamRule struct {
	Action    string // log alert
	Sid       int32
	Frequency struct {
		interval string // hour minute second
		value    int32  // number of packets per interval
	}
}
