/**
 * @file    bsp_h7s3.c
 * @brief   The parts of the EVT2 bring-up on STM32H7S3 (custom STM32H7S3V8Y6TR board, XIP Appli) that CubeMX does not
 *          generate.
 *
 * Since 2026-09-26 exercise1.ioc describes every peripheral the running code uses (GPIO, ADC2, TIM1, I2C1,
 * CRYP, HASH, RNG, CRC, USB_OTG_HS + CDC, MPU, NVIC, HSE/HSI48 clocks) and CubeMX owns their MX_*_Init() /
 * HAL_*_MspInit() / IRQ handlers (Core/Src/main.c, stm32h7rsxx_hal_msp.c, stm32h7rsxx_it.c). What stays here:
 *
 *   - bsp_early_init(): AHB SRAM clock + zero-fill of .ahb_sram_bss (the startup code only clears .bss) and a D-Cache
 *     clean/invalidate before CubeMX's MPU_Config() changes region attributes (Boot left the caches on).
 *   - The fingerprint sensor (FPC2530) wiring, only with EVT2_ENABLE_BIOMETRIC=1: its pins, EXTI11, USART1 with
 *     GPDMA1 channels 1/2 and their IRQ handlers. That stack is not in the .ioc (see board.h).
 *
 * DMA and cache: ADC2's GPDMA1 channel 0 (circular) is in the .ioc too; CubeMX declares its linked-list node with
 * section "noncacheable_buffer", which the linker script puts in the 8KB .dma_noncache window
 * (RAM_NONCACHEABLEBUFFER) that MPU_Config() maps as region 2 at 0x24070000. The DMA reads nodes and data buffers from
 * RAM, so both must live there; DMA_QListTypeDef queues are CPU-only HAL bookkeeping and stay cacheable.
 */
#include "bsp_hal.h"

#if EVT2_ENABLE_BIOMETRIC /* USART1 + its DMA only exist for the FPC2530 fingerprint sensor */
UART_HandleTypeDef huart1; /* Platform's UART table refers to it weakly: without biometric it does not exist */
static DMA_HandleTypeDef s_dma_usart1_rx;  /* GPDMA1 ch1 */
static DMA_HandleTypeDef s_dma_usart1_tx;  /* GPDMA1 ch2 */
#endif

#if EVT2_ENABLE_BIOMETRIC
/* Linked-list node: read by the DMA engine -> non-cacheable (see file doc comment). */
static DMA_NodeTypeDef s_node_usart1_rx __attribute__((section(".dma_noncache"), aligned(32)));
/* Queue: CPU-only HAL bookkeeping. */
static DMA_QListTypeDef s_list_usart1_rx;
#endif

/* ---- early init: AHB SRAM + cache, before CubeMX's MPU_Config() ------------------------------------------------- */

extern uint8_t __ahb_sram_bss_start__[];
extern uint8_t __ahb_sram_bss_end__[];
extern uint8_t __dma_noncache_region_start__[];

/* MPU region 2 in exercise1.ioc (CubeMX MPU_Config()) is hard-coded to this address and 8KB; the linker script places
 * RAM_NONCACHEABLEBUFFER there. Keep the two in sync -- bsp_early_init() stops if they drift apart. */
#define BSP_DMA_NONCACHE_BASE 0x24070000UL

void bsp_early_init(void)
{
    /* AHB SRAM1/SRAM2 (0x30000000, 2 x 16KB) hold .ahb_sram_bss (see the linker script): clock them, then do the
     * zero-init the startup code only does for .bss. Plain byte loop, not memset(): nothing may touch those statics
     * before this point, and this runs before HAL_Init(). */
    __HAL_RCC_SRAM1_CLK_ENABLE();
    __HAL_RCC_SRAM2_CLK_ENABLE();
    for (volatile uint8_t *p = __ahb_sram_bss_start__; p < __ahb_sram_bss_end__; p++) {
        *p = 0U;
    }

    /* MPU_Config() (generated, runs right after this) changes region attributes while the D-Cache is already on (Boot
     * enabled it before jumping here): write back and drop everything first, so no stale cached line survives for the
     * window about to become non-cacheable. */
    SCB_CleanInvalidateDCache();

    if ((uint32_t)__dma_noncache_region_start__ != BSP_DMA_NONCACHE_BASE) {
        Error_Handler(); /* linker window moved: update MPU region 2 in exercise1.ioc */
    }
}

/* ---- FPC2530 fingerprint sensor (EVT2_ENABLE_BIOMETRIC only; not in the .ioc) --------------------------------- */

#if EVT2_ENABLE_BIOMETRIC


/** Build a one-node circular linked-list DMA channel (peripheral -> memory), ST's own pattern
 *  (UART_ReceptionToIdle_CircularDMA) -- the same code CubeMX generates for ADC1. Buffer address/length are filled
 *  in later by HAL_UART_Receive_DMA(), which patches the head node. */
static void bsp_dma_circular_rx(DMA_HandleTypeDef *h, DMA_Channel_TypeDef *channel, DMA_NodeTypeDef *node,
                                DMA_QListTypeDef *list, uint32_t request, uint32_t src_width, uint32_t dst_width)
{
    DMA_NodeConfTypeDef n = {0};
    n.NodeType = DMA_GPDMA_LINEAR_NODE;
    n.Init.Request = request;
    n.Init.BlkHWRequest = DMA_BREQ_SINGLE_BURST;
    n.Init.Direction = DMA_PERIPH_TO_MEMORY;
    n.Init.SrcInc = DMA_SINC_FIXED;
    n.Init.DestInc = DMA_DINC_INCREMENTED;
    n.Init.SrcDataWidth = src_width;
    n.Init.DestDataWidth = dst_width;
    n.Init.SrcBurstLength = 1;
    n.Init.DestBurstLength = 1;
    n.Init.TransferAllocatedPort = DMA_SRC_ALLOCATED_PORT0 | DMA_DEST_ALLOCATED_PORT0;
    n.Init.TransferEventMode = DMA_TCEM_BLOCK_TRANSFER;
    n.Init.Mode = DMA_NORMAL;
    n.TriggerConfig.TriggerPolarity = DMA_TRIG_POLARITY_MASKED;
    n.DataHandlingConfig.DataExchange = DMA_EXCHANGE_NONE;
    n.DataHandlingConfig.DataAlignment = DMA_DATA_RIGHTALIGN_ZEROPADDED;
    if (HAL_DMAEx_List_BuildNode(&n, node) != HAL_OK ||
        HAL_DMAEx_List_InsertNode(list, NULL, node) != HAL_OK ||
        HAL_DMAEx_List_SetCircularMode(list) != HAL_OK) {
        Error_Handler();
    }

    h->Instance = channel;
    h->InitLinkedList.Priority = DMA_LOW_PRIORITY_HIGH_WEIGHT;
    h->InitLinkedList.LinkStepMode = DMA_LSM_FULL_EXECUTION;
    h->InitLinkedList.LinkAllocatedPort = DMA_LINK_ALLOCATED_PORT0;
    h->InitLinkedList.TransferEventMode = DMA_TCEM_BLOCK_TRANSFER;
    h->InitLinkedList.LinkedListMode = DMA_LINKEDLIST_CIRCULAR;
    if (HAL_DMAEx_List_Init(h) != HAL_OK || HAL_DMAEx_List_LinkQ(h, list) != HAL_OK ||
        HAL_DMA_ConfigChannelAttributes(h, DMA_CHANNEL_NPRIV) != HAL_OK) {
        Error_Handler();
    }
}

static void bsp_fpc_gpio_init(void)
{
    GPIO_InitTypeDef g = {0};
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOC_CLK_ENABLE();
    __HAL_RCC_GPIOF_CLK_ENABLE();

    HAL_GPIO_WritePin(FPC2530_RST_N_GPIO_Port, FPC2530_RST_N_Pin, GPIO_PIN_RESET);
    HAL_GPIO_WritePin(FPC2530_CS_N_GPIO_Port, FPC2530_CS_N_Pin, GPIO_PIN_RESET);
    HAL_GPIO_WritePin(FPC2530_IF_CFG_1_GPIO_Port, FPC2530_IF_CFG_1_Pin, GPIO_PIN_RESET);

    g.Pin = FPC2530_IRQ_Pin;
    g.Mode = GPIO_MODE_IT_RISING;
    g.Pull = GPIO_NOPULL;
    HAL_GPIO_Init(FPC2530_IRQ_GPIO_Port, &g);

    g.Mode = GPIO_MODE_OUTPUT_PP;
    g.Pull = GPIO_NOPULL;
    g.Speed = GPIO_SPEED_FREQ_LOW;
    g.Pin = FPC2530_RST_N_Pin;
    HAL_GPIO_Init(FPC2530_RST_N_GPIO_Port, &g);
    g.Pin = FPC2530_CS_N_Pin;
    HAL_GPIO_Init(FPC2530_CS_N_GPIO_Port, &g);
    g.Pin = FPC2530_IF_CFG_1_Pin;
    HAL_GPIO_Init(FPC2530_IF_CFG_1_GPIO_Port, &g);

    /* H7RS has one EXTI IRQ per line (EVT2/H753 shared EXTI15_10 between the FPC IRQ and the button). */
    HAL_NVIC_SetPriority(FPC2530_IRQ_EXTI_IRQn, 0, 0);
    HAL_NVIC_EnableIRQ(FPC2530_IRQ_EXTI_IRQn);
}

/** USART1 clock, pins and DMA. Done by hand before HAL_UART_Init(): the generated HAL_UART_MspInit() only knows
 *  USART3 (USART1 is not in the .ioc), so its call from HAL_UART_Init() does nothing for USART1. */
static void bsp_usart1_msp_init(UART_HandleTypeDef *huart)
{
    RCC_PeriphCLKInitTypeDef pclk = {0};
    GPIO_InitTypeDef g = {0};

    pclk.PeriphClockSelection = RCC_PERIPHCLK_USART1;
    pclk.Usart1ClockSelection = RCC_USART1CLKSOURCE_PCLK2; /* 144MHz */
    if (HAL_RCCEx_PeriphCLKConfig(&pclk) != HAL_OK) {
        Error_Handler();
    }
    __HAL_RCC_USART1_CLK_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();
    g.Pin = GPIO_PIN_9 | GPIO_PIN_10; /* PA9 TX, PA10 RX */
    g.Mode = GPIO_MODE_AF_PP;
    g.Pull = GPIO_NOPULL;
    g.Speed = GPIO_SPEED_FREQ_LOW;
    g.Alternate = GPIO_AF7_USART1;
    HAL_GPIO_Init(GPIOA, &g);

    __HAL_RCC_GPDMA1_CLK_ENABLE();
    HAL_NVIC_SetPriority(GPDMA1_Channel1_IRQn, 0, 0);
    HAL_NVIC_EnableIRQ(GPDMA1_Channel1_IRQn);
    HAL_NVIC_SetPriority(GPDMA1_Channel2_IRQn, 0, 0);
    HAL_NVIC_EnableIRQ(GPDMA1_Channel2_IRQn);

    /* RX: circular linked-list (EVT2: DMA1 Stream2 circular). */
    bsp_dma_circular_rx(&s_dma_usart1_rx, GPDMA1_Channel1, &s_node_usart1_rx, &s_list_usart1_rx,
                        GPDMA1_REQUEST_USART1_RX, DMA_SRC_DATAWIDTH_BYTE, DMA_DEST_DATAWIDTH_BYTE);
    __HAL_LINKDMA(huart, hdmarx, s_dma_usart1_rx);

    /* TX: plain channel (EVT2: DMA1 Stream1 normal) -- ST's UART_TwoBoards_ComDMA settings. */
    s_dma_usart1_tx.Instance = GPDMA1_Channel2;
    s_dma_usart1_tx.Init.Request = GPDMA1_REQUEST_USART1_TX;
    s_dma_usart1_tx.Init.BlkHWRequest = DMA_BREQ_SINGLE_BURST;
    s_dma_usart1_tx.Init.Direction = DMA_MEMORY_TO_PERIPH;
    s_dma_usart1_tx.Init.SrcInc = DMA_SINC_INCREMENTED;
    s_dma_usart1_tx.Init.DestInc = DMA_DINC_FIXED;
    s_dma_usart1_tx.Init.SrcDataWidth = DMA_SRC_DATAWIDTH_BYTE;
    s_dma_usart1_tx.Init.DestDataWidth = DMA_DEST_DATAWIDTH_BYTE;
    s_dma_usart1_tx.Init.Priority = DMA_LOW_PRIORITY_HIGH_WEIGHT;
    s_dma_usart1_tx.Init.SrcBurstLength = 1;
    s_dma_usart1_tx.Init.DestBurstLength = 1;
    s_dma_usart1_tx.Init.TransferAllocatedPort = DMA_SRC_ALLOCATED_PORT0 | DMA_DEST_ALLOCATED_PORT0;
    s_dma_usart1_tx.Init.TransferEventMode = DMA_TCEM_BLOCK_TRANSFER;
    s_dma_usart1_tx.Init.Mode = DMA_NORMAL;
    if (HAL_DMA_Init(&s_dma_usart1_tx) != HAL_OK ||
        HAL_DMA_ConfigChannelAttributes(&s_dma_usart1_tx, DMA_CHANNEL_NPRIV) != HAL_OK) {
        Error_Handler();
    }
    __HAL_LINKDMA(huart, hdmatx, s_dma_usart1_tx);

    HAL_NVIC_SetPriority(USART1_IRQn, 0, 0);
    HAL_NVIC_EnableIRQ(USART1_IRQn);
}

static void bsp_usart1_init(void)
{
    huart1.Instance = USART1;
    huart1.Init.BaudRate = 921600;
    huart1.Init.WordLength = UART_WORDLENGTH_8B;
    huart1.Init.StopBits = UART_STOPBITS_1;
    huart1.Init.Parity = UART_PARITY_NONE;
    huart1.Init.Mode = UART_MODE_TX_RX;
    huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    huart1.Init.OverSampling = UART_OVERSAMPLING_8; /* EVT2 value */
    huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
    huart1.Init.ClockPrescaler = UART_PRESCALER_DIV1;
    huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
    bsp_usart1_msp_init(&huart1);
    if (HAL_UART_Init(&huart1) != HAL_OK ||
        HAL_UARTEx_SetTxFifoThreshold(&huart1, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK ||
        HAL_UARTEx_SetRxFifoThreshold(&huart1, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK ||
        HAL_UARTEx_DisableFifoMode(&huart1) != HAL_OK) {
        Error_Handler();
    }
}

void GPDMA1_Channel1_IRQHandler(void)
{
    HAL_DMA_IRQHandler(&s_dma_usart1_rx);
}

void GPDMA1_Channel2_IRQHandler(void)
{
    HAL_DMA_IRQHandler(&s_dma_usart1_tx);
}

void USART1_IRQHandler(void)
{
    HAL_UART_IRQHandler(&huart1);
}

void EXTI11_IRQHandler(void)
{
    HAL_GPIO_EXTI_IRQHandler(FPC2530_IRQ_Pin);
}

#endif /* EVT2_ENABLE_BIOMETRIC */

/* ---- public ---------------------------------------------------------------------------------------------------- */

void bsp_init(void)
{
#if EVT2_ENABLE_BIOMETRIC
    bsp_fpc_gpio_init();
    bsp_usart1_init();
#endif
}
