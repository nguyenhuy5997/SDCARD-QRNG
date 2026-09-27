/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : extmem_manager.c
  * @version        : 1.0.0
  * @brief          : This file implements the extmem configuration
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "extmem_manager.h"
#include <string.h>

/* USER CODE BEGIN Includes */
/* A/B test switch (2026-09-27), see MX_EXTMEM_Init_PostTreatment: 1 = GD25 at 25 MHz + half-cycle sampling. */
#define EVT2_XSPI_AB_SLOW 0

/* USER CODE END Includes */

/* USER CODE BEGIN PV */
/* Private variables ---------------------------------------------------------*/

/* USER CODE END PV */

/* USER CODE BEGIN PFP */
/* Private function prototypes -----------------------------------------------*/

/* USER CODE END PFP */

/*
 * -- Insert your variables declaration here --
 */
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/*
 * -- Insert your external function declaration here --
 */
/* USER CODE BEGIN 1 */

/* USER CODE END 1 */

/**
  * Init External memory manager
  * @retval None
  */
void MX_EXTMEM_MANAGER_Init(void)
{

  /* USER CODE BEGIN MX_EXTMEM_Init_PreTreatment */

  /* USER CODE END MX_EXTMEM_Init_PreTreatment */
  HAL_RCCEx_EnableClockProtection(RCC_CLOCKPROTECT_XSPI);

  /* Initialization of the memory parameters */
  memset(extmem_list_config, 0x0, sizeof(extmem_list_config));

  /* EXTMEMORY_1 */
  extmem_list_config[0].MemType = EXTMEM_NOR_SFDP;
  extmem_list_config[0].Handle = (void*)&hxspi1;
  extmem_list_config[0].ConfigType = EXTMEM_LINK_CONFIG_4LINES;

  EXTMEM_Init(EXTMEMORY_1, HAL_RCCEx_GetPeriphCLKFreq(RCC_PERIPHCLK_XSPI1));

  /* USER CODE BEGIN MX_EXTMEM_Init_PostTreatment */
#if EVT2_XSPI_AB_SLOW
  /* A/B TEST (2026-09-27): the board hangs (bus stall, SWD lost, IWDG reset) while the SE050 works hard. Slow the
   * GD25 down from 50 MHz to 25 MHz (PLL2S 200 MHz / 8) and sample half a cycle later (the GD25 needs up to 7 ns from
   * the falling SCLK edge to valid data, tCLQV) -- before BOOT_Application() turns memory-mapped mode on. If the
   * hangs stop, the external flash link is the weak point. */
  MODIFY_REG(hxspi1.Instance->DCR2, XSPI_DCR2_PRESCALER, (7U << XSPI_DCR2_PRESCALER_Pos));
  SET_BIT(hxspi1.Instance->TCR, XSPI_TCR_SSHIFT);
#endif
  /* USER CODE END MX_EXTMEM_Init_PostTreatment */
}
