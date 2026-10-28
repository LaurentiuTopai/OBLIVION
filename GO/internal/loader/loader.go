package loader

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"github.com/cilium/ebpf/ringbuf"
	"oblivion/internal/events"
)

func Run(ctx context.Context,fn func(*events.Event)) error {
	var objs oblivionObjects
	if err := loadOblivionObjects(&objs, nil); err != nil {
		return fmt.Errorf("load: %+v", err)
	}
	defer objs.Close()
	
	key := uint32(0)
	self := uint32(os.Getpid())
	if err := objs.SelfTgid.Put(&key, &self); err != nil {
    		return fmt.Errorf("self_tgid: %w", err)
	}


	var att Attacher
	defer att.Close()

	for _, group := range [][]Hook{fileHooks(&objs), inodeHooks(&objs),memHooks(&objs),pathHooks(&objs),procHooks(&objs),netHooks(&objs)} {
		if err := att.AttachAll(group); err != nil {
			return err
		}
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("ringbuf: %w", err)
	}
	defer rd.Close()

	go func() { <-ctx.Done(); rd.Close() }()

	for {
		rec, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			log.Printf("read: %v", err)
			continue
		}
		var raw oblivionEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample),binary.NativeEndian,&raw);err !=nil{
		log.Printf("decode: %v",err)
		continue
		}
		ev := toEvent(&raw)
		fn(&ev)
	}
}
