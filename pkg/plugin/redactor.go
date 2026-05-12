package plugin

import (
	"context"

	hcplug "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/TensorGreed/tg-proxy/pkg/api"
	pb "github.com/TensorGreed/tg-proxy/pkg/plugin/proto"
)

// RedactorPlugin is the hashicorp/go-plugin descriptor for a Redactor.
type RedactorPlugin struct {
	hcplug.NetRPCUnsupportedPlugin
	Impl api.Redactor
}

func (p *RedactorPlugin) GRPCServer(_ *hcplug.GRPCBroker, s *grpc.Server) error {
	pb.RegisterRedactorServer(s, &grpcRedactorServer{impl: p.Impl})
	return nil
}

func (p *RedactorPlugin) GRPCClient(_ context.Context, _ *hcplug.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &grpcRedactorClient{client: pb.NewRedactorClient(c)}, nil
}

type grpcRedactorServer struct {
	pb.UnimplementedRedactorServer
	impl api.Redactor
}

func (s *grpcRedactorServer) Info(_ context.Context, _ *pb.Empty) (*pb.PluginInfo, error) {
	return &pb.PluginInfo{Name: s.impl.Name(), Version: pluginVersion}, nil
}

func (s *grpcRedactorServer) Redact(ctx context.Context, req *pb.RedactRequest) (*pb.RedactResponse, error) {
	out, err := s.impl.Redact(ctx, req.GetData(), FindingsFromProto(req.GetFindings()))
	if err != nil {
		return nil, err
	}
	return &pb.RedactResponse{Data: out}, nil
}

type grpcRedactorClient struct {
	client pb.RedactorClient
	name   string
}

func (c *grpcRedactorClient) Name() string { return c.name }

func (c *grpcRedactorClient) Info(ctx context.Context) (*pb.PluginInfo, error) {
	info, err := c.client.Info(ctx, &pb.Empty{})
	if err != nil {
		return nil, err
	}
	if info != nil {
		c.name = info.Name
	}
	return info, nil
}

func (c *grpcRedactorClient) Redact(ctx context.Context, data []byte, findings []api.Finding) ([]byte, error) {
	resp, err := c.client.Redact(ctx, &pb.RedactRequest{
		Data:     data,
		Findings: FindingsToProto(findings),
	})
	if err != nil {
		return nil, err
	}
	return resp.GetData(), nil
}

var (
	_ hcplug.GRPCPlugin = (*RedactorPlugin)(nil)
	_ api.Redactor      = (*grpcRedactorClient)(nil)
)
