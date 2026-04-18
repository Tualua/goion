// Package ion provides a userspace Go library for the Allwinner (Sunxi) ION
// memory allocator. It supports both legacy kernels (3.4 / 3.10 / 4.4 / 4.9)
// and the modern 5.4+ ION interface — selected at runtime via feature detection.
package goion

import (
	"unsafe"
)

// ---------------------------------------------------------------------------
// Size constants (mirror C macros)
// ---------------------------------------------------------------------------

const (
	SZ64M = 0x04000000
	SZ4M  = 0x00400000
	SZ1M  = 0x00100000
	SZ64K = 0x00010000
	SZ4K  = 0x00001000
	SZ1K  = 0x00000400

	ionAllocAlign = SZ4K
	devName       = "/dev/ion"
	cedarDevName  = "/dev/cedar_dev"
)

// ---------------------------------------------------------------------------
// Heap types / masks (legacy interface)
// ---------------------------------------------------------------------------

type heapType uint32

const (
	awIonSystemHeapType   heapType = 0
	awIonSystemContigHeap heapType = 1
	awIonCarveoutHeap     heapType = 2
	awIonTypeHeapChunk    heapType = 3
	awIonTypeHeapDMA      heapType = 4
	awIonTypeHeapCustom   heapType = 5
	awIonTypeHeapSecure   heapType = 6
)

const (
	awIonSystemHeapMask   = uint32(1) << uint32(awIonSystemHeapType)
	awIonSystemContigMask = uint32(1) << uint32(awIonSystemContigHeap)
	awIonCarveoutHeapMask = uint32(1) << uint32(awIonCarveoutHeap)
	awIonDMAHeapMask      = uint32(1) << uint32(awIonTypeHeapDMA)
	awIonSecureHeapMask   = uint32(1) << uint32(awIonTypeHeapSecure)

	// Modern (5.4+): system heap always sits at heap_id=0 → bit 0.
	awIonNewSystemHeapMask = uint32(1) << 0
)

// ---------------------------------------------------------------------------
// Cache flags
// ---------------------------------------------------------------------------

const (
	awIonCachedFlag          = uint32(1)
	awIonCachedNeedsSyncFlag = uint32(2)
)

// ---------------------------------------------------------------------------
// ION ioctl magic and command numbers
//
// ioctl encoding: _IOWR(magic, nr, type) — computed manually so we stay
// pure-Go with no cgo.  Formula (Linux):
//   (direction<<30) | (size<<16) | (magic<<8) | nr
//   _IOWR => direction = 0b11 = 3
//   _IOR  => direction = 0b10 = 2
// ---------------------------------------------------------------------------

const iocMagic = 'I'

func iocNR(dir, size, nr uintptr) uintptr {
	return (dir << 30) | (size << 16) | (iocMagic << 8) | nr
}

const (
	iocDirWR uintptr = 3
	iocDirR  uintptr = 2
)

// Legacy ioctl commands
var (
	awMemIonIOCAlloc  = iocNR(iocDirWR, unsafe.Sizeof(awIonAllocationInfo{}), 0)
	awMemIonIOCFree   = iocNR(iocDirWR, unsafe.Sizeof(ionHandleData{}), 1)
	awMemIonIOCMap    = iocNR(iocDirWR, unsafe.Sizeof(ionFdData{}), 2)
	awMemIonIOCCustom = iocNR(iocDirWR, unsafe.Sizeof(ionCustomData{}), 6)

	// Modern (5.4+) ioctl commands
	awIonIOCNewAlloc  = iocNR(iocDirWR, unsafe.Sizeof(awIonNewAllocData{}), 0)
	awIonIOCHeapQuery = iocNR(iocDirWR, unsafe.Sizeof(awIonHeapQuery{}), 8)
	awIonIOCABIVer    = iocNR(iocDirR, unsafe.Sizeof(uint32(0)), 9)
)

// Sunxi custom ioctl commands (passed inside ionCustomData.cmd)
const (
	ionIOCSunxiFlushRange = 5
	ionIOCSunxiFlushAll   = 6
	ionIOCSunxiPhysAddr   = 7
	ionIOCSunxiPoolInfo   = 10
	ionIOCSunxiTEEAddr    = 17

	// Cedar / IOMMU commands
	awMemEngineREQ       = 0x206
	awMemEngineREL       = 0x207
	awMemGetIommuAddr    = 0x502
	awMemFreeIommuAddr   = 0x503
	awMemFlushCacheRange = 0x506
)

// ---------------------------------------------------------------------------
// C-layout structs used in ioctl calls.
// All fields must match the kernel ABI exactly.
// ---------------------------------------------------------------------------

// awIonAllocationInfo mirrors struct aw_ion_allocation_info (legacy kernel).
type awIonAllocationInfo struct {
	Len        uintptr // size_t
	Align      uintptr // size_t
	HeapIDMask uint32
	Flags      uint32
	Handle     int32 // aw_ion_user_handle_t (int for non-3.4 kernels)
}

// ionHandleData mirrors struct ion_handle_data.
type ionHandleData struct {
	Handle int32
}

// ionFdData mirrors struct aw_ion_fd_data.
type ionFdData struct {
	Handle int32
	Fd     int32
}

// ionCustomData mirrors struct aw_ion_custom_info.
type ionCustomData struct {
	Cmd uint32
	Arg uintptr // unsigned long
}

// sunxiPhysData mirrors struct SUNXI_PHYS_DATA.
type sunxiPhysData struct {
	Handle   int32
	PhysAddr uint32
	Size     uint32
}

// sunxiCacheRange mirrors struct sunxi_cache_range (64-bit variant for 5.4+).
type sunxiCacheRange struct {
	Start int64
	End   int64
}

// sunxiPoolInfo mirrors struct sunxi_pool_info.
type sunxiPoolInfo struct {
	Total  uint32
	FreeKB uint32
	FreeMB uint32
}

// ---------------------------------------------------------------------------
// Modern (5.4+) structs
// ---------------------------------------------------------------------------

// awIonNewAllocData mirrors struct aw_ion_new_alloc_data.
type awIonNewAllocData struct {
	Len        uint64
	HeapIDMask uint32
	Flags      uint32
	Fd         uint32
	Unused     uint32
}

// awIonHeapData mirrors struct aw_ion_heap_data.
type awIonHeapData struct {
	Name      [32]byte
	Type      uint32
	HeapID    uint32
	Reserved0 uint32
	Reserved1 uint32
	Reserved2 uint32
}

// awIonHeapQuery mirrors struct aw_ion_heap_query.
type awIonHeapQuery struct {
	Cnt      uint32
	Reserved uint32
	Heaps    uint64
	Res1     uint32
	Res2     uint32
}

// userIommuParam mirrors struct user_iommu_param.
type userIommuParam struct {
	Fd        int32
	IommuAddr uint32
}
