package loader


import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Hook struct{
	Name string
	Prog *ebpf.Program

};

type Attacher struct{
	links []link.Link
}
func (a *Attacher) Attach(h Hook) error {
	l, err := link.AttachLSM(link.LSMOptions{Program: h.Prog})
	if err != nil {
		return fmt.Errorf("attach %s: %w", h.Name, err)
	}
	a.links = append(a.links, l)
	return nil
}

func (a *Attacher) AttachAll(hooks []Hook) error {
	for _, h := range hooks {
		if err := a.Attach(h); err != nil {
			return err
		}
	}
	return nil
}

func (a *Attacher) Close() {
	for _, l := range a.links {
		l.Close()
	}
}

