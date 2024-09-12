package dns

import (
	"context"
	"net"
	"net/netip"
	"sort"

	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/miekg/dns"
)

func init() {
	RegisterTransport([]string{"local"}, func(options TransportOptions) (Transport, error) {
		return NewLocalTransport(options), nil
	})
}

var _ Transport = (*LocalTransport)(nil)

type LocalTransport struct {
	name     string
	address  string //karing
	resolver net.Resolver
}

func NewLocalTransport(options TransportOptions) *LocalTransport {
	return &LocalTransport{
		name:    options.Name,
		address: options.Address, //karing
		resolver: net.Resolver{
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return options.Dialer.DialContext(ctx, N.NetworkName(network), M.ParseSocksaddr(address))
			},
		},
	}
}

func (t *LocalTransport) Name() string {
	return t.name
}

func (t *LocalTransport) Address() string { //karing
	return t.address
}

func (t *LocalTransport) Start() error {
	return nil
}

func (t *LocalTransport) Reset() {
}

func (t *LocalTransport) Close() error {
	return nil
}

func (t *LocalTransport) Raw() bool {
	return true //karing
	//return false //karing
}

func (t *LocalTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) { //karing
	question := message.Question[0]
	domain := question.Name
	var strategy DomainStrategy
	if question.Qtype == dns.TypeA {
		strategy = DomainStrategyUseIPv4
	} else {
		strategy = DomainStrategyUseIPv6
	}
	var network string
	switch strategy {
	case DomainStrategyAsIS, DomainStrategyPreferIPv4, DomainStrategyPreferIPv6:
		network = "ip"
	case DomainStrategyUseIPv4:
		network = "ip4"
	case DomainStrategyUseIPv6:
		network = "ip6"
	}
	result, err := t.resolver.LookupNetIP(ctx, network, domain)
	if err != nil {
		return nil, err
	}
	response := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       message.Id,
			Rcode:    dns.RcodeSuccess,
			Response: true,
		},
		Question: message.Question,
	}
	var timeToLive uint32
	if rewriteTTL, loaded := RewriteTTLFromContext(ctx); loaded {
		timeToLive = rewriteTTL
	} else {
		timeToLive = DefaultTTL
	}
	for _, address := range result {
		if address.Is4In6() {
			address = netip.AddrFrom4(address.As4())
		}
		if address.Is4() {
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    timeToLive,
				},
				A: address.AsSlice(),
			})
		} else {
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    timeToLive,
				},
				AAAA: address.AsSlice(),
			})
		}
	}
	return &response, nil
}

func (t *LocalTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	var network string
	switch strategy {
	case DomainStrategyAsIS, DomainStrategyPreferIPv4, DomainStrategyPreferIPv6:
		network = "ip"
	case DomainStrategyUseIPv4:
		network = "ip4"
	case DomainStrategyUseIPv6:
		network = "ip6"
	}
	addrs, err := t.resolver.LookupNetIP(ctx, network, domain)
	if err != nil {
		return nil, err
	}
	addrs = common.Map(addrs, func(it netip.Addr) netip.Addr {
		if it.Is4In6() {
			return netip.AddrFrom4(it.As4())
		}
		return it
	})
	switch strategy {
	case DomainStrategyPreferIPv4:
		sort.Slice(addrs, func(i, j int) bool {
			return addrs[i].Is4() && addrs[j].Is6()
		})
	case DomainStrategyPreferIPv6:
		sort.Slice(addrs, func(i, j int) bool {
			return addrs[i].Is6() && addrs[j].Is4()
		})
	}
	return addrs, nil
}
