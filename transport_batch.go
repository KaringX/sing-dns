package dns

//karing
import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	E "github.com/sagernet/sing/common/exceptions"
)


var _ Transport = (*BatchTransport)(nil)

type BatchTransport struct {
	name     string
	transports []Transport
}

func NewBatchTransport(name string, transports []Transport) *BatchTransport {
	return &BatchTransport{
		name: name,
		transports: transports,
	}
}

func (t *BatchTransport) Name() string {
	return t.name
}

func (t *BatchTransport) Start() error {
	for _, transport := range t.transports {
		err := transport.Start()
		if err != nil{
			return err
		}
	}
	return nil
}

func (t *BatchTransport) Reset() {
	for _, transport := range t.transports {
		transport.Reset()
	}
}

func (t *BatchTransport) Close() error {
	for _, transport := range t.transports {
		err := transport.Close()
		if err != nil{
			return err
		}
	}
	return nil
}

func (t *BatchTransport) Raw() bool {
	for _, transport := range t.transports {
		if transport.Raw(){
			return true
		}
	}
	return false
}

func (t *BatchTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	var count atomic.Int64 
	var result  *dns.Msg
	var errResult error
	var once    sync.Once
	var errOnce sync.Once
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(ctx)
	for _, transport := range t.transports {
		if !transport.Raw(){
			continue
		}
		count.Add(1)
		transport := transport
		go func(){
			ret, err := transport.Exchange(ctx, message)
			count.Add(-1)
			if err == nil {
				once.Do(func() {
					result = ret
					done <- struct{}{}
				})
			} else {
				errOnce.Do(func() {
					errResult = err
				})
				if count.Load() == 0 {
					once.Do(func() {
						done <- struct{}{}
					})
				}
			}
		}()
	}
	<-done
	cancel()
	close(done)
	if(result == nil && errResult == nil){
		errResult = E.New("dns batch Exchange: all failed")
	}
	return result, errResult
}

func (t *BatchTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	var count atomic.Int64 
	var result  []netip.Addr
	var errResult error
	var once    sync.Once
	var errOnce sync.Once
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(ctx)
	for _, transport := range t.transports {
		if transport.Raw(){
			continue
		}
		count.Add(1)
		transport := transport
		go func(){
			ret, err := transport.Lookup(ctx, domain, strategy)
			count.Add(-1)
			if err == nil {
				once.Do(func() {
					result = ret
					done <- struct{}{}
				})
			} else {
				errOnce.Do(func() {
					errResult = err
				})
				
				if count.Load() == 0{
					once.Do(func() {
						done <- struct{}{}
					})
				}
			}
		}()
	}
	<-done
	cancel()
	close(done)
	if(result == nil && errResult == nil){
		errResult = E.New("dns batch Lookup: all failed:", domain)
	}
	return result, errResult
}