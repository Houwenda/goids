package analyzer

type PktRule struct {
	Action         string
	Protocol       string
	Source         string
	SourcePort     int32
	Target         string
	TargetPort     int32
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
