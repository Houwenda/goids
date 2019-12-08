package analyzer

import "net"

type PktRule struct {
	Action   string
	Protocol string
	Source   net.IP
	SrcPort  struct {
		start int32
		end   int32
	}
	Destination net.IP
	DstPort     struct {
		start int32
		end   int32
	}
	Message        string
	Flow           []string
	Detection      []DetectionRule
	Metadata       []string
	Reference      []string
	Classification string
	SignatureId    struct {
		Sid int32
		Rev int32
	}
}

type DetectionRule struct {
	Content string
	Offset  int32
	Depth   int32
}

type StreamRule struct {
}
