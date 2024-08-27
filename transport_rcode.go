package dns

import (
	"context"
	"net/netip"
	"net/url"
	"os"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/miekg/dns"
)

var _ Transport = (*RCodeTransport)(nil)

func init() {
	RegisterTransport([]string{"rcode"}, func(options TransportOptions) (Transport, error) {
		return NewRCodeTransport(options)
	})
}

type RCodeTransport struct {
	name    string
	address string //karing
	code    RCodeError
}

func NewRCodeTransport(options TransportOptions) (*RCodeTransport, error) {
	serverURL, err := url.Parse(options.Address)
	if err != nil {
		return nil, err
	}
	switch serverURL.Host {
	case "success":
		return &RCodeTransport{options.Name, options.Address, RCodeSuccess}, nil //karing
	case "format_error":
		return &RCodeTransport{options.Name, options.Address, RCodeFormatError}, nil //karing
	case "server_failure":
		return &RCodeTransport{options.Name, options.Address, RCodeServerFailure}, nil //karing
	case "name_error":
		return &RCodeTransport{options.Name, options.Address, RCodeNameError}, nil //karing
	case "not_implemented":
		return &RCodeTransport{options.Name, options.Address, RCodeNotImplemented}, nil //karing
	case "refused":
		return &RCodeTransport{options.Name, options.Address, RCodeRefused}, nil //karing
	default:
		return nil, E.New("unknown rcode: " + options.Name)
	}
}

func (t *RCodeTransport) Name() string {
	return t.name
}

func (t *RCodeTransport) Address() string { //karing
	return t.address
}

func (t *RCodeTransport) Start() error {
	return nil
}

func (t *RCodeTransport) Reset() {
}

func (t *RCodeTransport) Close() error {
	return nil
}

func (t *RCodeTransport) Raw() bool {
	return true
}

func (t *RCodeTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	message.Response = true
	message.Rcode = int(t.code)
	return message, nil
}

func (t *RCodeTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}
