/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.h
  * @brief          : Header for main.c file.
  *                   This file contains the common defines of the application.
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
#ifndef __MAIN_H
#define __MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "stm32h7rsxx_hal.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

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
void Error_Handler(void);

/* USER CODE BEGIN EFP */

/* USER CODE END EFP */

/* Private defines -----------------------------------------------------------*/
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

/* USER CODE BEGIN Private defines */

/* USER CODE END Private defines */

#ifdef __cplusplus
}
#endif

#endif /* __MAIN_H */
