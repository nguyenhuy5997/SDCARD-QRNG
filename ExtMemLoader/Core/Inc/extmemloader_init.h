/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    extmemloader_init.h
  * @author  MCD Application Team
  * @brief   Header file of Loader_Src.c
  *
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

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef EXTMEMLOADER_INIT_H
#define EXTMEMLOADER_INIT_H

/* Includes ------------------------------------------------------------------*/
#include "stm32h7rsxx_hal.h"

/* Exported types ------------------------------------------------------------*/

/* USER CODE BEGIN ET */

/* USER CODE END ET */

/* Exported constants --------------------------------------------------------*/

/* USER CODE BEGIN EC */

/* USER CODE END EC */

/* Exported macro ------------------------------------------------------------*/

/* USER CODE BEGIN EM */

/* USER CODE END EM */

/* Exported functions prototypes ---------------------------------------------*/

/* USER CODE BEGIN EFP */

/* USER CODE END EFP */

uint32_t extmemloader_Init(void);
void Error_Handler(void);

/* Private defines -----------------------------------------------------------*/

/* USER CODE BEGIN Private defines */

/* USER CODE END Private defines */

#define LED_ENABLE_Pin GPIO_PIN_11
#define LED_ENABLE_GPIO_Port GPIOM
#define SE05x_ENABLE_Pin GPIO_PIN_14
#define SE05x_ENABLE_GPIO_Port GPIOC
#define OSC_ENABLE_Pin GPIO_PIN_15
#define OSC_ENABLE_GPIO_Port GPIOC
#define PS_FIRST_STAGE_ENABLE_Pin GPIO_PIN_8
#define PS_FIRST_STAGE_ENABLE_GPIO_Port GPIOA
#define PS_SECOND_STAGE_ENABLE_Pin GPIO_PIN_14
#define PS_SECOND_STAGE_ENABLE_GPIO_Port GPIOB
#define LED_SINK_Pin GPIO_PIN_2
#define LED_SINK_GPIO_Port GPIOO
#endif /* EXTMEMLOADER_INIT_H */
