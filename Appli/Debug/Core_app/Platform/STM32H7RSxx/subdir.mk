################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (14.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Core_app/Platform/STM32H7RSxx/platform_adc.c \
../Core_app/Platform/STM32H7RSxx/platform_crypto.c \
../Core_app/Platform/STM32H7RSxx/platform_dac.c \
../Core_app/Platform/STM32H7RSxx/platform_gpio.c \
../Core_app/Platform/STM32H7RSxx/platform_hash.c \
../Core_app/Platform/STM32H7RSxx/platform_i2c.c \
../Core_app/Platform/STM32H7RSxx/platform_rng.c \
../Core_app/Platform/STM32H7RSxx/platform_time.c \
../Core_app/Platform/STM32H7RSxx/platform_timer.c \
../Core_app/Platform/STM32H7RSxx/platform_uart.c \
../Core_app/Platform/STM32H7RSxx/platform_usb_stm32lib.c \
../Core_app/Platform/STM32H7RSxx/platform_usb_tinyusb.c 

OBJS += \
./Core_app/Platform/STM32H7RSxx/platform_adc.o \
./Core_app/Platform/STM32H7RSxx/platform_crypto.o \
./Core_app/Platform/STM32H7RSxx/platform_dac.o \
./Core_app/Platform/STM32H7RSxx/platform_gpio.o \
./Core_app/Platform/STM32H7RSxx/platform_hash.o \
./Core_app/Platform/STM32H7RSxx/platform_i2c.o \
./Core_app/Platform/STM32H7RSxx/platform_rng.o \
./Core_app/Platform/STM32H7RSxx/platform_time.o \
./Core_app/Platform/STM32H7RSxx/platform_timer.o \
./Core_app/Platform/STM32H7RSxx/platform_uart.o \
./Core_app/Platform/STM32H7RSxx/platform_usb_stm32lib.o \
./Core_app/Platform/STM32H7RSxx/platform_usb_tinyusb.o 

C_DEPS += \
./Core_app/Platform/STM32H7RSxx/platform_adc.d \
./Core_app/Platform/STM32H7RSxx/platform_crypto.d \
./Core_app/Platform/STM32H7RSxx/platform_dac.d \
./Core_app/Platform/STM32H7RSxx/platform_gpio.d \
./Core_app/Platform/STM32H7RSxx/platform_hash.d \
./Core_app/Platform/STM32H7RSxx/platform_i2c.d \
./Core_app/Platform/STM32H7RSxx/platform_rng.d \
./Core_app/Platform/STM32H7RSxx/platform_time.d \
./Core_app/Platform/STM32H7RSxx/platform_timer.d \
./Core_app/Platform/STM32H7RSxx/platform_uart.d \
./Core_app/Platform/STM32H7RSxx/platform_usb_stm32lib.d \
./Core_app/Platform/STM32H7RSxx/platform_usb_tinyusb.d 


# Each subdirectory must supply rules for building sources it contributes
Core_app/Platform/STM32H7RSxx/%.o Core_app/Platform/STM32H7RSxx/%.su Core_app/Platform/STM32H7RSxx/%.cyclo: ../Core_app/Platform/STM32H7RSxx/%.c Core_app/Platform/STM32H7RSxx/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m7 -std=gnu11 -g3 -DEVT2_DIAGNOSTICS=0 -DEVT2_ENABLE_BIOMETRIC=0 -DUSE_HAL_DRIVER -DSTM32H7S3xx -DT1oI2C -DT1oI2C_UM11225 -DSSS_USE_FTR_FILE -DAX_EMBEDDED=1 -DPLUG_AND_TRUST_STM32 -DPLUG_AND_TRUST_STM32_ENABLE_SCP03 -DHOST_IF_UART -DDEBUG -c -I../Core/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc/Legacy -I../../Drivers/CMSIS/Device/ST/STM32H7RSxx/Include -I../../Drivers/CMSIS/Include -I../Core_app/Platform -I../Core_app/BSP -I../Core_app/App -I../Core_app/Middleware/Security -I../Core_app/Middleware/Biometric -I../Core_app/Middleware/QRNG -I../Core_app/Middleware/CommandProtocol -I../Core_app/Middleware/CA -I../Core_app/Middleware/PQC -I../Core_app/Middleware/PQC/pqclean -I../Core_app/Middleware/PQC/pqclean/ml-kem-768-clean -I../Core_app/Middleware/PQC/pqclean/common -I../Core_app/Drivers/QRNG -I../Core_app/Drivers/AD5398 -I../Core_app/Drivers/FPC5234 -I../Core_app/Drivers/SE05x/middleware/hostlib/inc -I../Core_app/Drivers/SE05x/middleware/hostlib/platform/inc -I../Core_app/Drivers/SE05x/middleware/hostlib/libCommon/infra -I../Core_app/Drivers/SE05x/middleware/hostlib/libCommon/log -I../Core_app/Drivers/SE05x/middleware/hostlib/libCommon/smCom -I../Core_app/Drivers/SE05x/middleware/hostlib/libCommon/smCom/T1oI2C -I../Core_app/Drivers/SE05x/middleware/hostlib/se05x/src -I../Core_app/Drivers/SE05x/middleware/hostlib/se05x_03_xx_xx -I../Core_app/Drivers/SE05x/middleware/sss/inc -I../Core_app/Drivers/SE05x/middleware/sss/port/default -I../Core_app/Drivers/SE05x/middleware/sss/src/user -I../Core_app/Drivers/SE05x/middleware/sss/src/user/crypto -I../Core_app/Drivers/SE05x/config -I../Core_app/Drivers/SE05x/platform/stm32h7rs/inc -I../Core_app/Drivers/SE05x/tests -I../USB_DEVICE/App -I../USB_DEVICE/Target -I../../Middlewares/ST/STM32_USB_Device_Library/Core/Inc -I../../Middlewares/ST/STM32_USB_Device_Library/Class/CDC/Inc -O2 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-Core_app-2f-Platform-2f-STM32H7RSxx

clean-Core_app-2f-Platform-2f-STM32H7RSxx:
	-$(RM) ./Core_app/Platform/STM32H7RSxx/platform_adc.cyclo ./Core_app/Platform/STM32H7RSxx/platform_adc.d ./Core_app/Platform/STM32H7RSxx/platform_adc.o ./Core_app/Platform/STM32H7RSxx/platform_adc.su ./Core_app/Platform/STM32H7RSxx/platform_crypto.cyclo ./Core_app/Platform/STM32H7RSxx/platform_crypto.d ./Core_app/Platform/STM32H7RSxx/platform_crypto.o ./Core_app/Platform/STM32H7RSxx/platform_crypto.su ./Core_app/Platform/STM32H7RSxx/platform_dac.cyclo ./Core_app/Platform/STM32H7RSxx/platform_dac.d ./Core_app/Platform/STM32H7RSxx/platform_dac.o ./Core_app/Platform/STM32H7RSxx/platform_dac.su ./Core_app/Platform/STM32H7RSxx/platform_gpio.cyclo ./Core_app/Platform/STM32H7RSxx/platform_gpio.d ./Core_app/Platform/STM32H7RSxx/platform_gpio.o ./Core_app/Platform/STM32H7RSxx/platform_gpio.su ./Core_app/Platform/STM32H7RSxx/platform_hash.cyclo ./Core_app/Platform/STM32H7RSxx/platform_hash.d ./Core_app/Platform/STM32H7RSxx/platform_hash.o ./Core_app/Platform/STM32H7RSxx/platform_hash.su ./Core_app/Platform/STM32H7RSxx/platform_i2c.cyclo ./Core_app/Platform/STM32H7RSxx/platform_i2c.d ./Core_app/Platform/STM32H7RSxx/platform_i2c.o ./Core_app/Platform/STM32H7RSxx/platform_i2c.su ./Core_app/Platform/STM32H7RSxx/platform_rng.cyclo ./Core_app/Platform/STM32H7RSxx/platform_rng.d ./Core_app/Platform/STM32H7RSxx/platform_rng.o ./Core_app/Platform/STM32H7RSxx/platform_rng.su ./Core_app/Platform/STM32H7RSxx/platform_time.cyclo ./Core_app/Platform/STM32H7RSxx/platform_time.d ./Core_app/Platform/STM32H7RSxx/platform_time.o ./Core_app/Platform/STM32H7RSxx/platform_time.su ./Core_app/Platform/STM32H7RSxx/platform_timer.cyclo ./Core_app/Platform/STM32H7RSxx/platform_timer.d ./Core_app/Platform/STM32H7RSxx/platform_timer.o ./Core_app/Platform/STM32H7RSxx/platform_timer.su ./Core_app/Platform/STM32H7RSxx/platform_uart.cyclo ./Core_app/Platform/STM32H7RSxx/platform_uart.d ./Core_app/Platform/STM32H7RSxx/platform_uart.o ./Core_app/Platform/STM32H7RSxx/platform_uart.su ./Core_app/Platform/STM32H7RSxx/platform_usb_stm32lib.cyclo ./Core_app/Platform/STM32H7RSxx/platform_usb_stm32lib.d ./Core_app/Platform/STM32H7RSxx/platform_usb_stm32lib.o ./Core_app/Platform/STM32H7RSxx/platform_usb_stm32lib.su ./Core_app/Platform/STM32H7RSxx/platform_usb_tinyusb.cyclo ./Core_app/Platform/STM32H7RSxx/platform_usb_tinyusb.d ./Core_app/Platform/STM32H7RSxx/platform_usb_tinyusb.o ./Core_app/Platform/STM32H7RSxx/platform_usb_tinyusb.su

.PHONY: clean-Core_app-2f-Platform-2f-STM32H7RSxx

