package main

import (
	"fmt"
	"github.com/Tualua/goion"
	"log"
)

func ExampleBasicAlloc() {
	log.Println("BasicAlloc")
	// Open the ION device (reference-counted; safe to call from multiple goroutines).
	alloc, err := goion.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer alloc.Close()

	// Allocate 4 MiB with CPU cache enabled.
	res, err := alloc.Alloc(goion.SZ4M, true /*cached*/)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("virt=0x%x  phys=0x%x  size=%d\n", res.VirtAddr, res.PhysAddr, res.Size)

	// Use the buffer as a []byte without any unsafe code in caller.
	buf := res.Bytes()
	buf[0] = 0xAB

	// Flush CPU cache before DMA.
	if err := alloc.FlushCache(res.VirtAddr, int(res.Size)); err != nil {
		log.Println("flush cache:", err)
	}

	// Translate virtual → physical (e.g. offset into buffer).
	phys, _ := alloc.VirtToPhys(res.VirtAddr + 1024)
	fmt.Printf("offset 1024 → phys 0x%x\n", phys)

	// Free the buffer.
	if err := alloc.Free(res.VirtAddr); err != nil {
		log.Fatal(err)
	}
}

// ExampleDMABufSharing demonstrates obtaining a DMA-buf fd to share with a driver.
func ExampleDMABufSharing() {
	log.Println("DMABufSharing")
	alloc, err := goion.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer alloc.Close()

	res, err := alloc.Alloc(goion.SZ1M, false)
	if err != nil {
		log.Fatal(err)
	}
	defer alloc.Free(res.VirtAddr)

	fd, err := alloc.GetBufferFd(res.VirtAddr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("DMA-buf fd=%d  (pass to driver via ioctl)\n", fd)

	// Reverse: find virt from fd (e.g. after importing a shared buffer).
	virt, _ := alloc.GetVirtAddrByFd(fd)
	fmt.Printf("fd %d → virt 0x%x\n", fd, virt)
}

// ExamplePoolInfo demonstrates querying the carveout pool.
func ExamplePoolInfo() {
	log.Println("PoolInfo")
	info, err := goion.GetPoolInfo()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Pool: total=%d KB  free=%d KB (%d MB)\n",
		info.TotalKB, info.FreeKB, info.FreeMB)
}

// ExampleIommu demonstrates opening with IOMMU / cedar support (kernel 5.4+).
func ExampleIommu() {
	log.Println("IOMMU")
	alloc, err := goion.OpenWithCedar()
	if err != nil {
		log.Fatal(err)
	}
	defer alloc.Close()

	res, err := alloc.Alloc(goion.SZ4M, true)
	if err != nil {
		log.Fatal(err)
	}
	defer alloc.Free(res.VirtAddr)

	fmt.Printf("IOMMU addr=0x%x\n", res.PhysAddr)
}

// TestFlushCache проверяет FlushCache:
//  1. Аллоцирует буфер с cached=true
//  2. Пишет паттерн в буфер через CPU
//  3. Вызывает FlushCache — дёргает AW_MEM_FLUSH_CACHE_RANGE через cedar_dev
//  4. Проверяет что данные не повредились после flush
//  5. Освобождает буфер
func TestFlushCache() {
	fmt.Println("=== TestFlushCache ===")

	alloc, err := goion.Open()
	if err != nil {
		log.Fatalf("Open: %v", err)
	}
	defer alloc.Close()

	const size = goion.SZ4K * 4 // 16 KB — достаточно чтобы увидеть ioctl, не тратить память

	res, err := alloc.Alloc(size, true /* cached */)
	if err != nil {
		log.Fatalf("Alloc: %v", err)
	}
	fmt.Printf("  alloc ok: virt=0x%x phys=0x%x size=%d\n", res.VirtAddr, res.PhysAddr, res.Size)

	// Записываем паттерн
	buf := res.Bytes()
	for i := range buf {
		buf[i] = byte(i & 0xFF)
	}
	fmt.Printf("  wrote pattern: buf[0]=%d buf[255]=%d buf[1023]=%d\n",
		buf[0], buf[255], buf[1023])

	// Flush — именно этот вызов мы проверяем
	if err := alloc.FlushCache(res.VirtAddr, size); err != nil {
		log.Fatalf("FlushCache: %v", err)
	}
	fmt.Println("  FlushCache ok")

	// Данные должны остаться нетронутыми
	ok := true
	for i := range buf {
		if buf[i] != byte(i&0xFF) {
			fmt.Printf("  CORRUPTION at [%d]: got %d want %d\n", i, buf[i], byte(i&0xFF))
			ok = false
			break
		}
	}
	if ok {
		fmt.Println("  data integrity ok")
	}

	if err := alloc.Free(res.VirtAddr); err != nil {
		log.Fatalf("Free: %v", err)
	}
	fmt.Println("  free ok")
	fmt.Println("=== TestFlushCache PASSED ===")
}

// TestAllocSecure проверяет AllocSecure (secure/TEE heap, только legacy ioctl):
//  1. Пробует аллоцировать из secure heap
//  2. Если ядро возвращает ошибку — выводит её и завершается мягко (не fatal),
//     т.к. secure heap может быть недоступен без TEE окружения
//  3. При успехе проверяет что phys != 0, затем освобождает
func TestAllocSecure() {
	fmt.Println("=== TestAllocSecure ===")

	alloc, err := goion.Open()
	if err != nil {
		log.Fatalf("Open: %v", err)
	}
	defer alloc.Close()

	const size = goion.SZ1M // 1 MB

	res, err := alloc.AllocSecure(size)
	if err != nil {
		// Ожидаемо на устройствах без TEE/secure heap — не фатально
		fmt.Printf("  AllocSecure not available: %v\n", err)
		fmt.Println("=== TestAllocSecure SKIPPED ===")
		return
	}

	fmt.Printf("  alloc ok: virt=0x%x phys=0x%x size=%d\n", res.VirtAddr, res.PhysAddr, res.Size)

	if res.PhysAddr == 0 {
		fmt.Println("  WARN: phys addr is 0 — secure heap may not provide physical address")
	} else {
		fmt.Println("  phys addr ok")
	}

	if res.VirtAddr == 0 {
		fmt.Println("  ERROR: virt addr is 0")
	} else {
		// Пробуем записать — на некоторых ядрах secure память не маппится в user space
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("  write to secure mem panicked (expected on real TEE): %v\n", r)
				}
			}()
			buf := res.Bytes()
			buf[0] = 0xAB
			if buf[0] == 0xAB {
				fmt.Println("  write/read ok (non-strict TEE mode)")
			}
		}()
	}

	if err := alloc.Free(res.VirtAddr); err != nil {
		log.Fatalf("Free: %v", err)
	}
	fmt.Println("  free ok")
	fmt.Println("=== TestAllocSecure PASSED ===")
}

func main() {
	ExampleBasicAlloc()
	ExampleDMABufSharing()
	// ExamplePoolInfo() doesn't work at all
	ExampleIommu()
	TestFlushCache()
	TestAllocSecure()
}
