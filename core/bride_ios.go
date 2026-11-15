//go:build ios && cgo

package main

//#include "bride.h"
import "C"
import (
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tailscale/net/netmon"
)

var (
	dnsUpdateMu  sync.Mutex
	dnsUpdateSeq atomic.Uint64
)

func protect(callback unsafe.Pointer, fd int) bool {
	return C.protect(callback, C.int(fd)) != 0
}

func resolveUid(callback unsafe.Pointer, protocol int, source, target string) int {
	s := C.CString(source)
	defer C.free(unsafe.Pointer(s))
	t := C.CString(target)
	defer C.free(unsafe.Pointer(t))
	return int(C.resolve_uid(callback, C.int(protocol), s, t))
}

func resolvePackage(callback unsafe.Pointer, uid int) string {
	return takeCString(C.resolve_package(callback, C.int(uid)))
}

func invokeResult(callback unsafe.Pointer, data string) {
	s := C.CString(data)
	defer C.free(unsafe.Pointer(s))
	C.result(callback, s)
}

func releaseObject(callback unsafe.Pointer) {
	C.release_object(callback)
}

func retainObject(callback unsafe.Pointer) unsafe.Pointer {
	return C.retain_object(callback)
}

func writeSystemLog(level, message string) {
	l := C.CString(level)
	defer C.free(unsafe.Pointer(l))
	m := C.CString(message)
	defer C.free(unsafe.Pointer(m))
	C.system_log(l, m)
}

func handleUpdateDns(value string) {
	// The host DNS list is deliberately not installed. Android needs the
	// push because it has no readable resolv.conf; on iOS mihomo's system
	// resolver re-reads /etc/resolv.conf itself (at most every 5 minutes)
	// and the tunnel's own DNS is blacklisted from it. The list would only
	// feed proxy hostname resolution anyway — app DNS is captured by the
	// tunnel.
	seq := dnsUpdateSeq.Add(1)
	safeGoDetached("updateDns", func() {
		dnsUpdateMu.Lock()
		defer dnsUpdateMu.Unlock()
		if seq != dnsUpdateSeq.Load() {
			return
		}
		log.Infoln("[DNS] updateDns %s", value)
		resolver.ClearCache()
		resolver.ResetConnection()
	})
}

func handleUpdateNetwork(interfaceName, gateway string) {
	defer func() {
		if r := recover(); r != nil {
			logError("panic in updateNetwork: %v\n%s", r, stackTrace())
		}
	}()
	netmon.UpdateLastKnownDefaultRouteInterface(interfaceName)
}

func takeCString(s *C.char) string {
	defer C.free_string(s)
	return C.GoString(s)
}
