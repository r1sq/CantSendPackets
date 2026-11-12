// Package npcap is a small binding to Npcap's wpcap.dll, loaded at run time so
// the app works without it and needs no cgo.
//
// Npcap's licence doesn't allow bundling it, so it's an optional install the app
// detects. Only functions from libpcap's stable API are used.
package npcap

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	snapLen     = 2048
	readTimeout = 100 // ms; also bounds how long Next can block
	errBufSize  = 256 // PCAP_ERRBUF_SIZE
	netmaskAny  = 0xffffffff
)

var (
	loadOnce sync.Once
	loadErr  error
	procs    struct {
		openLive, close, compile, setFilter, freeCode, nextEx, sendPacket, geterr, libVersion *windows.LazyProc
	}
)

func load() error {
	loadOnce.Do(func() {
		sys, err := windows.GetSystemDirectory()
		if err != nil {
			loadErr = err
			return
		}
		// Npcap's documented way to resolve its DLLs. The absolute path also
		// means a wpcap.dll planted beside this exe can never be picked up.
		dir := filepath.Join(sys, "Npcap")
		if err := windows.SetDllDirectory(dir); err != nil {
			loadErr = err
			return
		}
		dll := windows.NewLazyDLL(filepath.Join(dir, "wpcap.dll"))
		if err := dll.Load(); err != nil {
			loadErr = fmt.Errorf("Npcap isn't installed: %w", err)
			return
		}
		procs.openLive = dll.NewProc("pcap_open_live")
		procs.close = dll.NewProc("pcap_close")
		procs.compile = dll.NewProc("pcap_compile")
		procs.setFilter = dll.NewProc("pcap_setfilter")
		procs.freeCode = dll.NewProc("pcap_freecode")
		procs.nextEx = dll.NewProc("pcap_next_ex")
		procs.sendPacket = dll.NewProc("pcap_sendpacket")
		procs.geterr = dll.NewProc("pcap_geterr")
		procs.libVersion = dll.NewProc("pcap_lib_version")
		for _, p := range []*windows.LazyProc{
			procs.openLive, procs.close, procs.compile, procs.setFilter, procs.freeCode,
			procs.nextEx, procs.sendPacket, procs.geterr, procs.libVersion,
		} {
			if err := p.Find(); err != nil {
				loadErr = fmt.Errorf("unsupported wpcap.dll: %w", err)
				return
			}
		}
	})
	return loadErr
}

// Version returns Npcap's version string, or an error if it isn't usable.
func Version() (string, error) {
	if err := load(); err != nil {
		return "", err
	}
	r, _, _ := procs.libVersion.Call()
	return cString(r), nil
}

// cString reads a NUL-terminated string the DLL owns. The double indirection
// reinterprets the returned address without an integer-to-pointer conversion.
func cString(addr uintptr) string {
	return windows.BytePtrToString(*(**byte)(unsafe.Pointer(&addr)))
}

// Handle is an open capture. It must be used from one goroutine at a time.
type Handle struct {
	p uintptr
}

// pcapHeader is struct pcap_pkthdr on Windows, where timeval uses 32-bit longs.
type pcapHeader struct {
	Sec, Usec, CapLen, Len int32
}

// bpfProgram is struct bpf_program.
type bpfProgram struct {
	Len   uint32
	Insns uintptr
}

// Open starts a non-promiscuous capture on the adapter with the given internal
// name. Promiscuous mode isn't needed: everything looked at here is addressed to
// broadcast, multicast or this adapter.
func Open(deviceName string) (*Handle, error) {
	if err := load(); err != nil {
		return nil, err
	}
	dev, err := windows.BytePtrFromString(`\Device\NPF_` + deviceName)
	if err != nil {
		return nil, err
	}
	var errBuf [errBufSize]byte
	p, _, _ := procs.openLive.Call(
		uintptr(unsafe.Pointer(dev)), snapLen, 0, readTimeout, uintptr(unsafe.Pointer(&errBuf[0])),
	)
	if p == 0 {
		return nil, fmt.Errorf("opening capture: %s", windows.ByteSliceToString(errBuf[:]))
	}
	return &Handle{p: p}, nil
}

func (h *Handle) lastError() error {
	r, _, _ := procs.geterr.Call(h.p)
	if r == 0 {
		return errors.New("unknown capture error")
	}
	return errors.New(cString(r))
}

// SetFilter applies a BPF filter in the driver, so a storm doesn't have to reach
// this process to be dropped.
func (h *Handle) SetFilter(expr string) error {
	cexpr, err := windows.BytePtrFromString(expr)
	if err != nil {
		return err
	}
	var prog bpfProgram
	r, _, _ := procs.compile.Call(h.p, uintptr(unsafe.Pointer(&prog)), uintptr(unsafe.Pointer(cexpr)), 1, netmaskAny)
	if int32(r) != 0 {
		return fmt.Errorf("compiling filter: %w", h.lastError())
	}
	defer procs.freeCode.Call(uintptr(unsafe.Pointer(&prog)))
	r, _, _ = procs.setFilter.Call(h.p, uintptr(unsafe.Pointer(&prog)))
	if int32(r) != 0 {
		return fmt.Errorf("setting filter: %w", h.lastError())
	}
	return nil
}

// Send transmits one raw frame.
func (h *Handle) Send(frame []byte) error {
	r, _, _ := procs.sendPacket.Call(h.p, uintptr(unsafe.Pointer(&frame[0])), uintptr(len(frame)))
	if int32(r) != 0 {
		return fmt.Errorf("sending frame: %w", h.lastError())
	}
	return nil
}

// Next returns one captured frame, copied, or a nil frame if the read timed out.
func (h *Handle) Next() ([]byte, time.Time, error) {
	var hdr *pcapHeader
	var data *byte
	r, _, _ := procs.nextEx.Call(h.p, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data)))
	switch int32(r) {
	case 1:
		if hdr == nil || data == nil || hdr.CapLen <= 0 {
			return nil, time.Time{}, nil
		}
		frame := append([]byte(nil), unsafe.Slice(data, hdr.CapLen)...)
		return frame, time.Unix(int64(hdr.Sec), int64(hdr.Usec)*1000), nil
	case 0:
		return nil, time.Time{}, nil
	default:
		return nil, time.Time{}, h.lastError()
	}
}

// Close releases the capture.
func (h *Handle) Close() {
	if h.p != 0 {
		procs.close.Call(h.p)
		h.p = 0
	}
}
