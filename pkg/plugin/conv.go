package plugin

import (
	"github.com/TensorGreed/tg-proxy/pkg/api"
	pb "github.com/TensorGreed/tg-proxy/pkg/plugin/proto"
)

// HintsToProto converts an api.Hints into its proto representation.
func HintsToProto(h api.Hints) *pb.Hints {
	return &pb.Hints{
		ContentType: h.ContentType,
		Url:         h.URL,
		Method:      h.Method,
		Direction:   pb.Direction(h.Direction),
	}
}

// HintsFromProto is the inverse of HintsToProto.
func HintsFromProto(h *pb.Hints) api.Hints {
	if h == nil {
		return api.Hints{}
	}
	return api.Hints{
		ContentType: h.ContentType,
		URL:         h.Url,
		Method:      h.Method,
		Direction:   api.Direction(h.Direction),
	}
}

// FindingToProto converts an api.Finding into its proto representation. The
// Metadata map is shallow-copied with all values stringified; richer types
// don't cross the wire today.
func FindingToProto(f api.Finding) *pb.Finding {
	var meta map[string]string
	if len(f.Metadata) > 0 {
		meta = make(map[string]string, len(f.Metadata))
		for k, v := range f.Metadata {
			meta[k] = anyToString(v)
		}
	}
	return &pb.Finding{
		Type:       f.Type,
		Severity:   pb.Severity(f.Severity),
		Start:      int32(f.Start),
		End:        int32(f.End),
		Confidence: f.Confidence,
		Scanner:    f.Scanner,
		Metadata:   meta,
	}
}

// FindingFromProto is the inverse of FindingToProto.
func FindingFromProto(p *pb.Finding) api.Finding {
	if p == nil {
		return api.Finding{}
	}
	var meta map[string]any
	if len(p.Metadata) > 0 {
		meta = make(map[string]any, len(p.Metadata))
		for k, v := range p.Metadata {
			meta[k] = v
		}
	}
	return api.Finding{
		Type:       p.Type,
		Severity:   api.Severity(p.Severity),
		Start:      int(p.Start),
		End:        int(p.End),
		Confidence: p.Confidence,
		Scanner:    p.Scanner,
		Metadata:   meta,
	}
}

// FindingsToProto / FindingsFromProto convenience wrappers.
func FindingsToProto(fs []api.Finding) []*pb.Finding {
	if len(fs) == 0 {
		return nil
	}
	out := make([]*pb.Finding, len(fs))
	for i, f := range fs {
		out[i] = FindingToProto(f)
	}
	return out
}

func FindingsFromProto(ps []*pb.Finding) []api.Finding {
	if len(ps) == 0 {
		return nil
	}
	out := make([]api.Finding, len(ps))
	for i, p := range ps {
		out[i] = FindingFromProto(p)
	}
	return out
}

func anyToString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	default:
		return ""
	}
}
