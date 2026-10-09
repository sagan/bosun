package v2stats

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/core/grpcraw"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
)

// Exercise the real wire boundary. The two servers deliberately honor
// different filter fields; filtering only the decoded response is too late
// once QueryStats(reset=true) has consumed other categories' counters.
func TestSelectiveResetAcrossStatsDialects(t *testing.T) {
	for _, field := range []protowire.Number{1, 3} {
		t.Run(map[protowire.Number]string{1: "xray", 3: "singbox"}[field], func(t *testing.T) {
			counters := map[string]int64{"user>>>alice>>>traffic>>>uplink": 100, "inbound>>>ssh>>>traffic>>>uplink": 200, "outbound>>>direct>>>traffic>>>downlink": 300}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := grpc.NewServer(grpc.ForceServerCodec(grpcraw.Codec{}), grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
				var req []byte
				if err := stream.RecvMsg(&req); err != nil {
					return err
				}
				filter := ""
				reset := false
				for len(req) > 0 {
					n, typ, k := protowire.ConsumeTag(req)
					req = req[k:]
					if typ == protowire.BytesType {
						v, k := protowire.ConsumeString(req)
						req = req[k:]
						if n == field {
							filter = v
						}
					} else {
						v, k := protowire.ConsumeVarint(req)
						req = req[k:]
						if n == 2 {
							reset = v != 0
						}
					}
				}
				var out []byte
				for name, n := range counters {
					if strings.Contains(name, filter) {
						out = protowire.AppendTag(out, 1, protowire.BytesType)
						out = protowire.AppendBytes(out, encodeStat(name, n))
						if reset {
							counters[name] = 0
						}
					}
				}
				return stream.SendMsg(out)
			}))
			go server.Serve(listener)
			defer server.Stop()
			conn, err := grpcraw.Dial(listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			method := "/stats/QueryStats"
			users, err := QueryUsers(ctx, conn, method, "user>>>", true)
			if err != nil || users["alice"].Up != 100 {
				t.Fatal(users, err)
			}
			in, err := QueryInbounds(ctx, conn, method, "inbound>>>", true)
			if err != nil || in["ssh"].Up != 200 {
				t.Fatal("user reset consumed inbound", in, err)
			}
			out, err := QueryOutbounds(ctx, conn, method, "outbound>>>", true)
			if err != nil || out["direct"].Down != 300 {
				t.Fatal("earlier reset consumed outbound", out, err)
			}
			users, err = QueryUsers(ctx, conn, method, "user>>>", true)
			if err != nil || users["alice"].Up != 0 {
				t.Fatal("reset counted twice", users, err)
			}
		})
	}
}
