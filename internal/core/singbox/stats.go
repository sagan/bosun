package singbox

import (
	"context"

	"google.golang.org/grpc"

	"github.com/zeptop-dev/bosun/internal/core/v2stats"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// sing-box registers its stats service under the original V2Ray name for
// compatibility (see experimental/v2rayapi/stats.go), so that is the name on
// the wire, not the proto's experimental.v2rayapi package.
const queryStatsMethod = "/v2ray.core.app.stats.command.StatsService/QueryStats"

// queryUserStats resets only user counters. sing-box matches patterns (field 3),
// not the legacy pattern field; an empty filter would also consume the inbound
// and outbound counters before their collectors can read them.
func queryUserStats(ctx context.Context, conn *grpc.ClientConn, reset bool) (map[string]spec.Traffic, error) {
	return v2stats.QueryUsers(ctx, conn, queryStatsMethod, "user>>>", reset)
}
