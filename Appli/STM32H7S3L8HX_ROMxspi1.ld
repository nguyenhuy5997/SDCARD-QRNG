/*
******************************************************************************
**
** @file        : LinkerScript.ld
**
** @author      : STM32CubeIDE
**
**  Abstract    : Linker script for STM32H7Sxx Device
**                      128KBytes FLASH
**                      456KBytes RAM
**
**                Set heap size, stack size and stack location according
**                to application requirements.
**
**                Set memory bank area and size if external memory is used
**
**  Target      : STMicroelectronics STM32
**
**  Distribution: The file is distributed as is, without any warranty
**                of any kind.
**
******************************************************************************
** @attention
**
** Copyright (c) 2026 STMicroelectronics.
** All rights reserved.
**
** This software is licensed under terms that can be found in the LICENSE file
** in the root directory of this software component.
** If no LICENSE file comes with this software, it is provided AS-IS.
**
******************************************************************************
*/

/* Entry Point */
ENTRY(Reset_Handler)

/* Highest address of the user mode stack */
_estack = ORIGIN(DTCM) + LENGTH(DTCM); /* end of "DTCM" Ram type memory */

/* EVT2 firmware port (H7S3): main stack in DTCM next to .dtcm_bss (32KB Toeplitz table), so it gets the other
 * ~28KB of DTCM. The deep callers (ML-DSA, and ML-KEM since the port) run on the separate .pqc_sign_stack. Heap is
 * in AXI SRAM (see ._user_heap below) because the vendored FPC5234 SDK mallocs buffers it later hands to UART DMA. */
_Min_Heap_Size = 0x4000;  /* minimum heap guaranteed (16KB); the heap actually extends to the end of RAM */
_Min_Stack_Size = 0x7000; /* 28KB main stack reserved in DTCM */

__FLASH_BEGIN  = 0x90000000;
__FLASH_SIZE   = 0x01000000; /* GD25Q128E: 16 MB (128 Mbit) on the STM32H7S3V8Y6TR board */


__RAM_BEGIN    = 0x24000000;
/* AXI SRAM is 0x24000000-0x24071FFF (456KB). The last 8KB is carved out as the DMA window (.dma_noncache,
 * MPU region 2 in exercise1.ioc / MPU_Config()): an MPU region must be a power-of-2 size aligned to that size, so the
 * window is exactly 8KB at an 8KB boundary (0x24070000) -- the template's 1KB at 0x24071C00 was too small for
 * EVT2's DMA buffers (4KB ADC ring, UART ring, TX bounce buffer, DMA linked-list nodes). */
__RAM_SIZE     = 0x70000;
__RAM_NONCACHEABLEBUFFER_SIZE = 0x2000;

/* Memories definition */
MEMORY
{
  RAM       (xrw) : ORIGIN = __RAM_BEGIN,    LENGTH = __RAM_SIZE
  RAM_NONCACHEABLEBUFFER (xrw) : ORIGIN = __RAM_BEGIN + __RAM_SIZE,  LENGTH = __RAM_NONCACHEABLEBUFFER_SIZE

  ITCM      (xrw) : ORIGIN = 0x00000000,    LENGTH = 0x00010000
  DTCM       (rw) : ORIGIN = 0x20000000,    LENGTH = 0x00010000
  SRAMAHB   (rw)  : ORIGIN = 0x30000000,  LENGTH = 0x00008000
  BKPSRAM   (rw)  : ORIGIN = 0x38800000,  LENGTH = 0x00001000

  FLASH     (xrw) : ORIGIN = __FLASH_BEGIN, LENGTH = __FLASH_SIZE
}

/* Sections */
SECTIONS
{
  /* The startup code into "FLASH" FLASH type memory */
  .isr_vector :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector)) /* Startup code */
    . = ALIGN(4);
  } >FLASH

  /* The program code and other data into "FLASH" FLASH type memory */
  .text :
  {
    . = ALIGN(4);
    *(.text)           /* .text sections (code) */
    *(.text*)          /* .text* sections (code) */
    *(.glue_7)         /* glue arm to thumb code */
    *(.glue_7t)        /* glue thumb to arm code */
    *(.eh_frame)

    KEEP (*(.init))
    KEEP (*(.fini))

    . = ALIGN(4);
    _etext = .;        /* define a global symbols at end of code */
  } >FLASH

  /* Constant data into "FLASH" FLASH type memory */
  .rodata :
  {
    . = ALIGN(4);
    *(.rodata)         /* .rodata sections (constants, strings, etc.) */
    *(.rodata*)        /* .rodata* sections (constants, strings, etc.) */
    . = ALIGN(4);
  } >FLASH

  .ARM.extab (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    . = ALIGN(4);
    *(.ARM.extab* .gnu.linkonce.armextab.*)
    . = ALIGN(4);
  } >FLASH
  .ARM (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    . = ALIGN(4);
    __exidx_start = .;
    *(.ARM.exidx*)
    __exidx_end = .;
    . = ALIGN(4);
  } >FLASH

  .preinit_array (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    . = ALIGN(4);
    PROVIDE_HIDDEN (__preinit_array_start = .);
    KEEP (*(.preinit_array*))
    PROVIDE_HIDDEN (__preinit_array_end = .);
    . = ALIGN(4);
  } >FLASH

  .init_array (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    . = ALIGN(4);
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP (*(SORT(.init_array.*)))
    KEEP (*(.init_array*))
    PROVIDE_HIDDEN (__init_array_end = .);
    . = ALIGN(4);
  } >FLASH

  .fini_array (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    . = ALIGN(4);
    PROVIDE_HIDDEN (__fini_array_start = .);
    KEEP (*(SORT(.fini_array.*)))
    KEEP (*(.fini_array*))
    PROVIDE_HIDDEN (__fini_array_end = .);
    . = ALIGN(4);
  } >FLASH

  /* Used by the startup to initialize data */
  _sidata = LOADADDR(.data);

  /* Initialized data sections into "RAM" Ram type memory */
  .data :
  {
    . = ALIGN(4);
    _sdata = .;        /* create a global symbol at data start */
    *(.data)           /* .data sections */
    *(.data*)          /* .data* sections */
    *(.RamFunc)        /* .RamFunc sections */
    *(.RamFunc*)       /* .RamFunc* sections */

    . = ALIGN(4);
    _edata = .;        /* define a global symbol at data end */

  } >RAM AT> FLASH

  /* EVT2 port: zero-initialised state of the command-protocol adapters (Core_app/App/protocol_adapters: security,
   * CA handshake, media, QRNG -- ~21KB, CPU-only, never a DMA target) lives in the otherwise unused 32KB AHB SRAM
   * (SRAM1+SRAM2 at 0x30000000) instead of AXI SRAM, which is what lets the full feature set (ML-DSA-87 alternate
   * stack, 49152-byte protocol payloads, boot self-tests) fit the H7S3's 448KB of AXI SRAM. Must come BEFORE .bss
   * below (ld assigns an input section to the first matching rule). NOLOAD and outside .bss, so the startup code
   * neither clocks nor zeroes it: bsp_early_init() (Core_app/BSP/bsp_h7s3.c) enables the SRAM1/SRAM2 clocks and
   * clears [__ahb_sram_bss_start__, __ahb_sram_bss_end__) before anything else in main() runs. Default memory map
   * applies (MPU background leaves 0x20000000-0x3FFFFFFF alone), i.e. Normal cacheable, same as AXI SRAM. */
  .ahb_sram_bss (NOLOAD) :
  {
    . = ALIGN(4);
    __ahb_sram_bss_start__ = .;
    *protocol_adapters/*.o(.bss .bss.* COMMON)
    . = ALIGN(4);
    __ahb_sram_bss_end__ = .;
  } >SRAMAHB

  /* Uninitialized data section into "RAM" Ram type memory */
  . = ALIGN(4);
  .bss :
  {
    /* This is used by the startup in order to initialize the .bss section */
    _sbss = .;         /* define a global symbol at bss start */
    __bss_start__ = _sbss;
    *(.bss)
    *(.bss*)
    *(COMMON)

    . = ALIGN(4);
    _ebss = .;         /* define a global symbol at bss end */
    __bss_end__ = _ebss;
  } >RAM

  /* ---- EVT2 custom sections (ported from EVT2's STM32H753ZITX_FLASH.ld, re-placed for the H7S3 memory map) ---- */

  /* DMA buffers the CPU also reads/writes directly (QRNG's raw ADC ring, the FPC5234 UART RX ring, the UART TX
   * bounce buffer) plus the GPDMA linked-list nodes the DMA engine fetches itself. MUST NOT be cacheable while
   * D-Cache is on: MPU_Config() (region 2, exercise1.ioc) maps this whole window (ORIGIN/LENGTH of RAM_NONCACHEABLEBUFFER) as Normal
   * non-cacheable. EVT2 kept this in RAM_D2; the H7S3 has no RAM_D2, so it is the top 8KB of AXI SRAM.
   * ST's "noncacheable_buffer" input section (used by CubeMX-generated code) lands in the same window. NOLOAD:
   * DMA/app fills these at runtime. */
  .dma_noncache (NOLOAD) :
  {
    . = ALIGN(32);
    __NONCACHEABLEBUFFER_BEGIN = .;
    *(.dma_noncache)
    *(.dma_noncache*)
    KEEP(*(noncacheable_buffer))
    . = ALIGN(32);
    __NONCACHEABLEBUFFER_END = .;
  } > RAM_NONCACHEABLEBUFFER
  __dma_noncache_region_start__ = ORIGIN(RAM_NONCACHEABLEBUFFER);
  __dma_noncache_region_end__   = ORIGIN(RAM_NONCACHEABLEBUFFER) + LENGTH(RAM_NONCACHEABLEBUFFER);
  ASSERT(LENGTH(RAM_NONCACHEABLEBUFFER) == 0x2000, "DMA window must be 8KB: MPU region 2 in exercise1.ioc is MPU_REGION_SIZE_8KB at 0x24070000")
  ASSERT((ORIGIN(RAM_NONCACHEABLEBUFFER) % 0x2000) == 0, "DMA window must be 8KB-aligned for its MPU region")

  /* Post-mortem trace (Core_app/App/app_trace.c): FIXED address so it can always be read over SWD, NOLOAD and outside
   * .bss so the startup code never clears it -- it must survive an IWDG/fault reset. Inside the non-cacheable window
   * (MPU region 2), so every write reaches SRAM before a reset. Below 0x24071C00, which Boot's own linker script
   * reserves. */
  .trace_noinit 0x24071800 (NOLOAD) :
  {
    KEEP(*(.trace_noinit))
  } > RAM_NONCACHEABLEBUFFER
  ASSERT(SIZEOF(.trace_noinit) <= 0x400, "trace record must fit 0x24071800-0x24071BFF")

  /* Latency-sensitive tables (Core_app/Drivers/QRNG/toeplitz.c's toeplitz_lookup, 32KB): DTCM = single-cycle,
   * no AXI hop, never cached/evicted. Same intent as EVT2. NOLOAD: callers initialise before first use. Not a DMA
   * target (DMA access to DTCM is not relied on anywhere in this port). */
  .dtcm_bss (NOLOAD) :
  {
    . = ALIGN(4);
    *(.dtcm_bss)
    *(.dtcm_bss*)
    . = ALIGN(4);
  } >DTCM

  /* Main (MSP) stack: the rest of DTCM, top at _estack. Reserved here so the link fails if .dtcm_bss ever grows
   * into the space the stack needs. */
  ._main_stack (NOLOAD) :
  {
    . = ALIGN(8);
    __main_stack_limit__ = .;
    . = . + _Min_Stack_Size;
    . = ALIGN(8);
  } >DTCM
  ASSERT(__main_stack_limit__ + _Min_Stack_Size <= _estack, "main stack reservation does not fit in DTCM")

  /* Dedicated alternate CPU stack for the vendored PQClean calls (ML-DSA keygen/sign/verify, and ML-KEM since the
   * H7S3 port) -- see Core_app/Middleware/PQC/pqc_stack_call.c. EVT2 had it in RAM_D2; here it is plain AXI SRAM.
   * CPU-only (no DMA), so default cacheable attributes are right. NOLOAD: a stack has no preset contents. */
  .pqc_sign_stack (NOLOAD) :
  {
    . = ALIGN(8);
    *(.pqc_sign_stack)
    . = ALIGN(8);
  } >RAM

  /* Heap: from the end of everything else in AXI SRAM up to the end of RAM (Core/Src/sysmem.c bounds _sbrk() by
   * __heap_limit__). The FPC5234 SDK mallocs frames it passes to UART DMA -- keeping the heap in AXI SRAM (not DTCM,
   * as the template did) keeps those reachable by GPDMA. */
  ._user_heap (NOLOAD) :
  {
    . = ALIGN(8);
    PROVIDE ( end = . );
    PROVIDE ( _end = . );
    . = . + _Min_Heap_Size;
    . = ALIGN(8);
  } >RAM
  __heap_limit__ = ORIGIN(RAM) + LENGTH(RAM);

  /* Remove information from the compiler libraries */
  /DISCARD/ :
  {
    libc.a ( * )
    libm.a ( * )
    libgcc.a ( * )
  }

  .ARM.attributes 0 : { *(.ARM.attributes) }
}
