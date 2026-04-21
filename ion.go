package goion

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Buffer node — tracks every live allocation
// ---------------------------------------------------------------------------

type bufferNode struct {
	phy      uintptr
	vir      uintptr
	userVirt uintptr
	size     uint32
	tee      uintptr
	fdData   ionFdData
}

// ---------------------------------------------------------------------------
// Allocator context
// ---------------------------------------------------------------------------

// Allocator is the top-level handle. Create one with Open(), release with Close().
type Allocator struct {
	mu      sync.Mutex
	fd      int
	cedarFd int
	refCnt  int
	buffers []*bufferNode

	isModern     bool   // true → kernel 5.4+ new ION interface
	hasIommu     bool   // true → use cedar_dev for phys addr / cache flush
	heapMaskNorm uint32 // heap mask for normal allocations, detected at open
}

var (
	globalMu  sync.Mutex
	globalCtx *Allocator
)

// Open opens /dev/ion and returns a shared, reference-counted Allocator.
//
// It automatically tries to open /dev/cedar_dev as well. On most Allwinner
// SoCs physical addresses are only obtainable via the IOMMU/cedar path, so
// cedar_dev is required for Alloc() to work. If cedar_dev is absent the
// allocator opens successfully but falls back to the legacy PHYS_ADDR ioctl.
func Open() (*Allocator, error) {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalCtx != nil {
		globalCtx.refCnt++
		return globalCtx, nil
	}

	a := &Allocator{cedarFd: -1}

	fd, err := openRaw(devName)
	if err != nil {
		return nil, fmt.Errorf("ion: open %s: %w", devName, err)
	}
	a.fd = fd

	// Detect kernel ABI: ION_IOC_ABI_VERSION is only present on 5.4+.
	var abiVer uint32
	if ioctlErr := ioctl(a.fd, awIonIOCABIVer, uintptr(unsafe.Pointer(&abiVer))); ioctlErr == nil {
		a.isModern = true
	}

	// Try cedar_dev — non-fatal if absent (e.g. desktop cross-compile testing).
	if cfd, cerr := openRaw(cedarDevName); cerr == nil {
		a.cedarFd = cfd
		a.hasIommu = true
	}

	// Choose heap mask: IOMMU path needs system+carveout; otherwise detect.
	if a.hasIommu {
		a.heapMaskNorm = awIonSystemHeapMask | awIonCarveoutHeapMask
	} else {
		mask, _ := detectHeapMask(a.fd, a.isModern)
		a.heapMaskNorm = mask
	}

	globalCtx = a
	globalCtx.refCnt = 1
	return globalCtx, nil
}

// Close decrements the refcount; resources are freed when it reaches zero.
func (a *Allocator) Close() {
	globalMu.Lock()
	defer globalMu.Unlock()

	a.refCnt--
	if a.refCnt > 0 {
		return
	}

	for _, b := range a.buffers {
		_ = munmapBuffer(b)
		syscall.Close(int(b.fdData.Fd))
	}
	a.buffers = nil
	syscall.Close(a.fd)
	a.fd = -1
	if a.cedarFd != -1 {
		syscall.Close(a.cedarFd)
		a.cedarFd = -1
	}
	globalCtx = nil
}

// ---------------------------------------------------------------------------
// AllocResult
// ---------------------------------------------------------------------------

// AllocResult is returned by Alloc and AllocSecure.
type AllocResult struct {
	VirtAddr uintptr
	PhysAddr uintptr
	Size     uint32
}

// Bytes returns a []byte view of the allocation. Valid until Free() is called.
func (r *AllocResult) Bytes() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(r.VirtAddr)), r.Size)
}

// ---------------------------------------------------------------------------
// Alloc
// ---------------------------------------------------------------------------

// Alloc allocates size bytes of ION memory and maps it into the process.
// cached=true enables CPU cache (you must call FlushCache before DMA).
func (a *Allocator) Alloc(size int, cached bool) (*AllocResult, error) {
	if size <= 0 {
		return nil, errors.New("ion: size must be > 0")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	flags := uint32(0)
	if cached {
		flags = awIonCachedFlag | awIonCachedNeedsSyncFlag
	}

	var dmaBufFd int32
	var handle int32

	if a.isModern {
		// Try detected mask first, then fall back to system-heap-only mask.
		fd, err := a.allocModern(uint64(size), a.heapMaskNorm, flags)
		if err != nil {
			fd, err = a.allocModern(uint64(size), awIonNewSystemHeapMask, flags)
			if err != nil {
				return nil, fmt.Errorf("ion: NEW_ALLOC (masks 0x%x / 0x%x): %w",
					a.heapMaskNorm, awIonNewSystemHeapMask, err)
			}
		}
		dmaBufFd = fd
	} else {
		h, fd, err := a.allocLegacy(uintptr(size), a.heapMaskNorm, flags)
		if err != nil {
			return nil, fmt.Errorf("ion: ION_IOC_ALLOC: %w", err)
		}
		handle, dmaBufFd = h, fd
	}

	addrVir, err := mmapFd(dmaBufFd, size)
	if err != nil {
		syscall.Close(int(dmaBufFd))
		return nil, err
	}

	addrPhy, err := a.getPhysAddr(handle, int32(size), dmaBufFd)
	if err != nil {
		_, _, _ = syscall.Syscall(syscall.SYS_MUNMAP, addrVir, uintptr(size), 0)
		syscall.Close(int(dmaBufFd))
		return nil, err
	}

	a.buffers = append(a.buffers, &bufferNode{
		phy: addrPhy, vir: addrVir, userVirt: addrVir,
		size:   uint32(size),
		fdData: ionFdData{Handle: handle, Fd: dmaBufFd},
	})
	return &AllocResult{VirtAddr: addrVir, PhysAddr: addrPhy, Size: uint32(size)}, nil
}

// AllocSecure allocates from the secure (TEE/DRM) heap. Legacy kernels only.
func (a *Allocator) AllocSecure(size int) (*AllocResult, error) {
	if size <= 0 {
		return nil, errors.New("ion: size must be > 0")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	handle, dmaBufFd, err := a.allocLegacy(uintptr(size), awIonSecureHeapMask,
		awIonCachedFlag|awIonCachedNeedsSyncFlag)
	if err != nil {
		return nil, fmt.Errorf("ion: AllocSecure: %w", err)
	}

	addrVir, err := mmapFd(dmaBufFd, size)
	if err != nil {
		syscall.Close(int(dmaBufFd))
		return nil, err
	}

	phys := sunxiPhysData{Handle: handle, Size: uint32(size)}
	custom := ionCustomData{Cmd: ionIOCSunxiPhysAddr, Arg: uintptr(unsafe.Pointer(&phys))}
	if err := ioctl(a.fd, awMemIonIOCCustom, uintptr(unsafe.Pointer(&custom))); err != nil {
		_, _, _ = syscall.Syscall(syscall.SYS_MUNMAP, addrVir, uintptr(size), 0)
		return nil, fmt.Errorf("ion: AllocSecure PHYS_ADDR: %w", err)
	}

	a.buffers = append(a.buffers, &bufferNode{
		phy: uintptr(phys.PhysAddr), vir: addrVir, userVirt: addrVir, tee: addrVir,
		size:   uint32(size),
		fdData: ionFdData{Handle: handle, Fd: dmaBufFd},
	})
	return &AllocResult{VirtAddr: addrVir, PhysAddr: uintptr(phys.PhysAddr), Size: uint32(size)}, nil
}

// ---------------------------------------------------------------------------
// Free
// ---------------------------------------------------------------------------

// Free releases an ION buffer by its virtual address.
func (a *Allocator) Free(virtAddr uintptr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	idx, node := a.findByVirt(virtAddr)
	if node == nil {
		return fmt.Errorf("ion: Free: unknown virtual address 0x%x", virtAddr)
	}

	if err := munmapBuffer(node); err != nil {
		return err
	}

	if a.hasIommu {
		err := ioctl(a.cedarFd, awMemEngineREL, 0)
		if err != nil {
			return fmt.Errorf("ion: ENGINE_REL: %w", err)
		}
		ip := userIommuParam{Fd: node.fdData.Fd}
		err = ioctl(a.cedarFd, awMemFreeIommuAddr, uintptr(unsafe.Pointer(&ip)))
		if err != nil {
			return fmt.Errorf("ion: FREE_IOMMU_ADDR: %w", err)
		}
	}

	syscall.Close(int(node.fdData.Fd))

	if !a.isModern && node.fdData.Handle != 0 {
		hd := ionHandleData{Handle: node.fdData.Handle}
		err := ioctl(a.fd, awMemIonIOCFree, uintptr(unsafe.Pointer(&hd)))
		if err != nil {
			return fmt.Errorf("ion: ION_IOC_FREE: %w", err)
		}
	}

	a.buffers = append(a.buffers[:idx], a.buffers[idx+1:]...)
	return nil
}

// ---------------------------------------------------------------------------
// Address translation
// ---------------------------------------------------------------------------

// VirtToPhys translates a virtual address (may be interior to an allocation)
// to its physical counterpart.
func (a *Allocator) VirtToPhys(virt uintptr) (uintptr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, b := range a.buffers {
		if virt >= b.vir && virt < b.vir+uintptr(b.size) {
			return b.phy + (virt - b.vir), nil
		}
	}
	return 0, fmt.Errorf("ion: VirtToPhys: 0x%x not found", virt)
}

// PhysToVirt translates a physical address to its virtual counterpart.
func (a *Allocator) PhysToVirt(phys uintptr) (uintptr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, b := range a.buffers {
		if phys >= b.phy && phys < b.phy+uintptr(b.size) {
			return b.vir + (phys - b.phy), nil
		}
	}
	return 0, fmt.Errorf("ion: PhysToVirt: 0x%x not found", phys)
}

// ---------------------------------------------------------------------------
// DMA-buf fd helpers
// ---------------------------------------------------------------------------

// GetBufferFd returns the DMA-buf fd for the buffer containing virtAddr.
func (a *Allocator) GetBufferFd(virtAddr uintptr) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, b := range a.buffers {
		if virtAddr >= b.vir && virtAddr < b.vir+uintptr(b.size) {
			return int(b.fdData.Fd), nil
		}
	}
	return 0, fmt.Errorf("ion: GetBufferFd: 0x%x not found", virtAddr)
}

// GetVirtAddrByFd returns the virtual address for a given DMA-buf fd.
func (a *Allocator) GetVirtAddrByFd(shareFd int) (uintptr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, b := range a.buffers {
		if int(b.fdData.Fd) == shareFd {
			return b.vir, nil
		}
	}
	return 0, fmt.Errorf("ion: GetVirtAddrByFd: fd %d not found", shareFd)
}

// ---------------------------------------------------------------------------
// Cache management
// ---------------------------------------------------------------------------

// FlushCache flushes the CPU cache for [startAddr, startAddr+size).
func (a *Allocator) FlushCache(startAddr uintptr, size int) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	r := sunxiCacheRange{Start: int64(startAddr), End: int64(startAddr) + int64(size)}

	if a.isModern {
		// 5.4+: flush goes through cedar_dev with AW_MEM_FLUSH_CACHE_RANGE.
		if a.cedarFd == -1 {
			return errors.New("ion: FlushCache on kernel 5.4+ requires cedar_fd — use OpenWithCedar()")
		}
		return ioctl(a.cedarFd, awMemFlushCacheRange, uintptr(unsafe.Pointer(&r)))
	}
	// Legacy: ION_IOC_CUSTOM(FLUSH_RANGE)
	custom := ionCustomData{Cmd: ionIOCSunxiFlushRange, Arg: uintptr(unsafe.Pointer(&r))}
	return ioctl(a.fd, awMemIonIOCCustom, uintptr(unsafe.Pointer(&custom)))
}

// FlushCacheAll flushes the entire ION cache.
func (a *Allocator) FlushCacheAll() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return ioctl(a.fd, ionIOCSunxiFlushAll, 0)
}

// ---------------------------------------------------------------------------
// Pool info
// ---------------------------------------------------------------------------

// PoolInfo describes the ION carveout pool.
type PoolInfo struct {
	TotalKB uint32
	FreeKB  uint32
	FreeMB  uint32
}

// GetPoolInfo queries the ION driver for pool size information via
// ION_IOC_CUSTOM(POOL_INFO). On kernels where ION_IOC_CUSTOM is not
// implemented (ENOTTY) it falls back to /proc/meminfo CmaTotal/CmaFree.
func GetPoolInfo() (*PoolInfo, error) {
	fd, err := openRaw(devName)
	if err != nil {
		return nil, fmt.Errorf("ion: GetPoolInfo open: %w", err)
	}
	defer syscall.Close(fd)

	var info sunxiPoolInfo
	custom := ionCustomData{
		Cmd: ionIOCSunxiPoolInfo,
		Arg: uintptr(unsafe.Pointer(&info)),
	}
	if err := ioctl(fd, awMemIonIOCCustom, uintptr(unsafe.Pointer(&custom))); err == nil {
		return &PoolInfo{TotalKB: info.Total, FreeKB: info.FreeKB, FreeMB: info.FreeMB}, nil
	}

	// ION_IOC_CUSTOM not available — fall back to /proc/meminfo CMA fields.
	return poolInfoFromProcMeminfo()
}

// poolInfoFromProcMeminfo reads CmaTotal and CmaFree from /proc/meminfo.
func poolInfoFromProcMeminfo() (*PoolInfo, error) {
	data, err := readSmallFile("/proc/meminfo")
	if err != nil {
		return nil, fmt.Errorf("ion: GetPoolInfo fallback: %w", err)
	}

	var totalKB, freeKB uint32
	for _, line := range splitLines(data) {
		matchMemField(line, "CmaTotal:", &totalKB)
		matchMemField(line, "CmaFree:", &freeKB)
	}

	if totalKB == 0 && freeKB == 0 {
		return nil, errors.New("ion: GetPoolInfo: ION_IOC_CUSTOM unsupported and CMA absent in /proc/meminfo")
	}
	return &PoolInfo{TotalKB: totalKB, FreeKB: freeKB, FreeMB: freeKB / 1024}, nil
}

// readSmallFile reads an entire small file using only syscalls.
func readSmallFile(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	var buf [8192]byte
	var out []byte
	for {
		n, err := syscall.Read(fd, buf[:])
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if n == 0 || err != nil {
			break
		}
	}
	return out, nil
}

// splitLines splits bytes on newlines without importing bytes or strings.
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// matchMemField parses "CmaTotal:    524288 kB" and fills val. Returns true on match.
func matchMemField(line []byte, key string, val *uint32) bool {
	if len(line) < len(key) {
		return false
	}
	for i := range key {
		if line[i] != key[i] {
			return false
		}
	}
	rest := line[len(key):]
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	var n uint32
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		n = n*10 + uint32(rest[i]-'0')
		i++
	}
	*val = n
	return true
}

// ---------------------------------------------------------------------------
// Heap detection (5.4+)
// ---------------------------------------------------------------------------

// detectHeapMask runs ION_IOC_HEAP_QUERY to enumerate available heaps and
// returns the best mask for normal (non-secure) allocations.
func detectHeapMask(fd int, isModern bool) (uint32, error) {
	if !isModern {
		return awIonDMAHeapMask | awIonCarveoutHeapMask, nil
	}

	// Step 1: ask how many heaps exist.
	q := awIonHeapQuery{}
	if err := ioctl(fd, awIonIOCHeapQuery, uintptr(unsafe.Pointer(&q))); err != nil {
		// HEAP_QUERY not supported — fall back to system heap.
		return awIonNewSystemHeapMask, nil
	}
	if q.Cnt == 0 {
		return awIonNewSystemHeapMask, nil
	}

	// Step 2: fetch heap descriptors.
	heaps := make([]awIonHeapData, q.Cnt)
	q.Heaps = uint64(uintptr(unsafe.Pointer(&heaps[0])))
	if err := ioctl(fd, awIonIOCHeapQuery, uintptr(unsafe.Pointer(&q))); err != nil {
		return awIonNewSystemHeapMask, nil
	}

	// Build mask from all non-secure heaps.
	var mask uint32
	for _, h := range heaps {
		if h.Type != uint32(awIonTypeHeapSecure) {
			mask |= 1 << (h.HeapID & 31)
		}
	}
	if mask == 0 {
		return awIonNewSystemHeapMask, nil
	}
	return mask, nil
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

func (a *Allocator) allocModern(length uint64, heapMask uint32, flags uint32) (int32, error) {
	data := awIonNewAllocData{Len: length, HeapIDMask: heapMask, Flags: flags}
	if err := ioctl(a.fd, awIonIOCNewAlloc, uintptr(unsafe.Pointer(&data))); err != nil {
		return 0, err
	}
	return int32(data.Fd), nil
}

func (a *Allocator) allocLegacy(length uintptr, heapMask uint32, flags uint32) (int32, int32, error) {
	alloc := awIonAllocationInfo{
		Len: length, Align: ionAllocAlign,
		HeapIDMask: heapMask, Flags: flags,
	}
	if err := ioctl(a.fd, awMemIonIOCAlloc, uintptr(unsafe.Pointer(&alloc))); err != nil {
		return 0, 0, err
	}
	fdData := ionFdData{Handle: alloc.Handle}
	if err := ioctl(a.fd, awMemIonIOCMap, uintptr(unsafe.Pointer(&fdData))); err != nil {
		return 0, 0, err
	}
	return alloc.Handle, fdData.Fd, nil
}

func (a *Allocator) getPhysAddr(handle int32, size int32, dmaBufFd int32) (uintptr, error) {
	if a.hasIommu {
		iommu := userIommuParam{Fd: dmaBufFd}
		if err := ioctl(a.cedarFd, awMemEngineREQ, 0); err != nil {
			return 0, fmt.Errorf("ion: ENGINE_REQ: %w", err)
		}
		if err := ioctl(a.cedarFd, awMemGetIommuAddr, uintptr(unsafe.Pointer(&iommu))); err != nil {
			return 0, fmt.Errorf("ion: GET_IOMMU_ADDR: %w", err)
		}
		return uintptr(iommu.IommuAddr), nil
	}
	phys := sunxiPhysData{Handle: handle, Size: uint32(size)}
	custom := ionCustomData{Cmd: ionIOCSunxiPhysAddr, Arg: uintptr(unsafe.Pointer(&phys))}
	if err := ioctl(a.fd, awMemIonIOCCustom, uintptr(unsafe.Pointer(&custom))); err != nil {
		return 0, fmt.Errorf("ion: ION_IOC_CUSTOM(PHYS_ADDR): %w", err)
	}
	return uintptr(phys.PhysAddr), nil
}

func (a *Allocator) findByVirt(virt uintptr) (int, *bufferNode) {
	for i, b := range a.buffers {
		if b.vir == virt {
			return i, b
		}
	}
	return -1, nil
}

func munmapBuffer(b *bufferNode) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MUNMAP, b.userVirt, uintptr(b.size), 0)
	if errno != 0 {
		return fmt.Errorf("ion: munmap: %w", errno)
	}
	return nil
}

func mmapFd(fd int32, size int) (uintptr, error) {
	addr, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP, 0, uintptr(size),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED, uintptr(fd), 0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("ion: mmap: %w", errno)
	}
	return addr, nil
}

// openRaw opens path with O_RDONLY and returns a raw fd that the Go runtime
// will NOT close automatically (unlike os.File).
func openRaw(path string) (int, error) {
	return syscall.Open(path, syscall.O_RDONLY, 0)
}

// ioctl wraps SYS_IOCTL.
func ioctl(fd int, req uintptr, arg uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, arg)
	if errno != 0 {
		return errno
	}
	return nil
}
