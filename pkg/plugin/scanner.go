package plugin

import (
	"context"

	hcplug "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/TensorGreed/tg-proxy/pkg/api"
	pb "github.com/TensorGreed/tg-proxy/pkg/plugin/proto"
)

// ScannerPlugin is the hashicorp/go-plugin descriptor for a Scanner. The
// plugin author passes one of these to plugin.Serve with Impl populated;
// the host gets back a *grpcScannerClient from Dispense, which satisfies
// api.Scanner via the wire protocol.
type ScannerPlugin struct {
	hcplug.NetRPCUnsupportedPlugin
	Impl api.Scanner
}

func (p *ScannerPlugin) GRPCServer(_ *hcplug.GRPCBroker, s *grpc.Server) error {
	pb.RegisterScannerServer(s, &grpcScannerServer{impl: p.Impl})
	return nil
}

func (p *ScannerPlugin) GRPCClient(_ context.Context, _ *hcplug.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &grpcScannerClient{client: pb.NewScannerClient(c)}, nil
}

// grpcScannerServer wraps a Go-side api.Scanner implementation and exposes
// it over the gRPC interface defined in proto/plugin.proto.
type grpcScannerServer struct {
	pb.UnimplementedScannerServer
	impl api.Scanner
}

func (s *grpcScannerServer) Info(_ context.Context, _ *pb.Empty) (*pb.PluginInfo, error) {
	return &pb.PluginInfo{Name: s.impl.Name(), Version: pluginVersion}, nil
}

func (s *grpcScannerServer) Scan(ctx context.Context, req *pb.ScanRequest) (*pb.ScanResponse, error) {
	findings, err := s.impl.Scan(ctx, req.GetData(), HintsFromProto(req.GetHints()))
	if err != nil {
		return nil, err
	}
	return &pb.ScanResponse{Findings: FindingsToProto(findings)}, nil
}

// grpcScannerClient is the host-side adapter. It implements api.Scanner by
// translating each call into a gRPC round-trip to the plugin process.
type grpcScannerClient struct {
	client pb.ScannerClient
	name   string
}

func (c *grpcScannerClient) Name() string { return c.name }

// Info queries the plugin once for its identity; the host caches the
// returned name so Name() can stay synchronous.
func (c *grpcScannerClient) Info(ctx context.Context) (*pb.PluginInfo, error) {
	info, err := c.client.Info(ctx, &pb.Empty{})
	if err != nil {
		return nil, err
	}
	if info != nil {
		c.name = info.Name
	}
	return info, nil
}

func (c *grpcScannerClient) Scan(ctx context.Context, data []byte, hints api.Hints) ([]api.Finding, error) {
	resp, err := c.client.Scan(ctx, &pb.ScanRequest{
		Data:  data,
		Hints: HintsToProto(hints),
	})
	if err != nil {
		return nil, err
	}
	return FindingsFromProto(resp.GetFindings()), nil
}

// pluginVersion is reported by Info() for Go-side plugins built with this
// SDK. Override per-plugin by wrapping ServeScanner.
const pluginVersion = "dev"

// Compile-time assurances.
var (
	_ hcplug.GRPCPlugin = (*ScannerPlugin)(nil)
	_ api.Scanner       = (*grpcScannerClient)(nil)
)
