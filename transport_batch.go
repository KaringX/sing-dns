package dns

//karing
import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
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
	
	for _, transport := range t.transports {
		if !transport.Raw(){
			continue
		}
		count.Add(1)
		transport := transport
		go func(){
			var send = false
			if ret, err := transport.Exchange(ctx, message); err == nil {
				once.Do(func() {
					result = ret
					send = true
					done <- struct{}{}
				})
			} else {
				errOnce.Do(func() {
					errResult = err
				})
			}
			count.Add(-1)
			if count.Load() == 0 && !send{
				done <- struct{}{}
			}
		}()
	}
	<-done
	ctx.Done()
	close(done)
	done = nil
	return result, errResult
}

func (t *BatchTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	var count atomic.Int64 
	var result  []netip.Addr
	var errResult error
	var once    sync.Once
	var errOnce sync.Once
	done := make(chan struct{})
	
	for _, transport := range t.transports {
		if transport.Raw(){
			continue
		}
		count.Add(1)
		transport := transport
		go func(){
			var send = false
			if ret, err := transport.Lookup(ctx, domain, strategy); err == nil {
				once.Do(func() {
					result = ret
					send = true
					done <- struct{}{}
				})
			} else {
				errOnce.Do(func() {
					errResult = err
				})
			}
			count.Add(-1)
			if count.Load() == 0 && !send{
				done <- struct{}{}
			}
		}()
	}
	<-done
	ctx.Done()
	close(done)
	done = nil
	return result, errResult
}
