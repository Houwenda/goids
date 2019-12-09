package analyzer

type PktRule struct {
	Action   string
	Protocol string
	Source   string // can be ipv4, ipv6, "any"
	SrcPort  struct {
		start int32
		end   int32
	}
	Destination string // can be ipv4, ipv6, "any"
	DstPort     struct {
		start int32
		end   int32
	}
	Message        string
	Flow           []string
	Detection      DetectionRule
	Metadata       []string
	Reference      []string
	Classification string
	SignatureId    struct {
		Sid int32
		Rev int32
	}
}

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
	Sid       int32
	Frequency int32
}
