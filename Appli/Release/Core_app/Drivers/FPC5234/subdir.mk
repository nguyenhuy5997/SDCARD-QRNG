################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (14.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Core_app/Drivers/FPC5234/fpc_hal.c \
../Core_app/Drivers/FPC5234/fpc_hal_crypto.c \
../Core_app/Drivers/FPC5234/fpc_host_sample.c \
../Core_app/Drivers/FPC5234/hal_common.c \
../Core_app/Drivers/FPC5234/i2c_host.c \
../Core_app/Drivers/FPC5234/spi_host.c \
../Core_app/Drivers/FPC5234/uart_debug.c \
../Core_app/Drivers/FPC5234/uart_host.c 

OBJS += \
./Core_app/Drivers/FPC5234/fpc_hal.o \
./Core_app/Drivers/FPC5234/fpc_hal_crypto.o \
./Core_app/Drivers/FPC5234/fpc_host_sample.o \
./Core_app/Drivers/FPC5234/hal_common.o \
./Core_app/Drivers/FPC5234/i2c_host.o \
./Core_app/Drivers/FPC5234/spi_host.o \
./Core_app/Drivers/FPC5234/uart_debug.o \
./Core_app/Drivers/FPC5234/uart_host.o 

C_DEPS += \
./Core_app/Drivers/FPC5234/fpc_hal.d \
./Core_app/Drivers/FPC5234/fpc_hal_crypto.d \
./Core_app/Drivers/FPC5234/fpc_host_sample.d \
./Core_app/Drivers/FPC5234/hal_common.d \
./Core_app/Drivers/FPC5234/i2c_host.d \
./Core_app/Drivers/FPC5234/spi_host.d \
./Core_app/Drivers/FPC5234/uart_debug.d \
./Core_app/Drivers/FPC5234/uart_host.d 


# Each subdirectory must supply rules for building sources it contributes
Core_app/Drivers/FPC5234/%.o Core_app/Drivers/FPC5234/%.su Core_app/Drivers/FPC5234/%.cyclo: ../Core_app/Drivers/FPC5234/%.c Core_app/Drivers/FPC5234/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m7 -std=gnu11 -DUSE_HAL_DRIVER -DSTM32H7S3xx -DT1oI2C -DT1oI2C_UM11225 -DSSS_USE_FTR_FILE -DAX_EMBEDDED=1 -DPLUG_AND_TRUST_STM32 -DPLUG_AND_TRUST_STM32_ENABLE_SCP03 -DHOST_IF_UART -c -I../Core/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc/Legacy -I../../Drivers/CMSIS/Device/ST/STM32H7RSxx/Include -I../../Drivers/CMSIS/Include -I../Core_app/Platform -I../Core_app/BSP -I../Core_app/App -I../Core_app/Middleware/Security -I../Core_app/Middleware/Biometric -I../Core_app/Middleware/QRNG -I../Core_app/Middleware/CommandProtocol -I../Core_app/Middleware/CA -I../Core_app/Middleware/PQC -I../Core_app/Middleware/PQC/pqclean -I../Core_app/Middleware/PQC/pqclean/ml-kem-768-clean -I../Core_app/Middleware/PQC/pqclean/common -I../Core_app/Drivers/QRNG -I../Core_app/Drivers/AD5398 -I../Core_app/Drivers/FPC5234 -I../Core_app/Drivers/SE05x/middleware/hostlib/inc -I../Core_app/Drivers/SE05x/middleware/hostlib/platform/inc -I../Core_app/Drivers/SE05x/middleware/hostlib/libCommon/infra -I../Core_app/Drivers/SE05x/middleware/hostlib/libCommon/log -I../Core_app/Drivers/SE05x/middleware/hostlib/libCommon/smCom -I../Core_app/Drivers/SE05x/middleware/hostlib/libCommon/smCom/T1oI2C -I../Core_app/Drivers/SE05x/middleware/hostlib/se05x/src -I../Core_app/Drivers/SE05x/middleware/hostlib/se05x_03_xx_xx -I../Core_app/Drivers/SE05x/middleware/sss/inc -I../Core_app/Drivers/SE05x/middleware/sss/port/default -I../Core_app/Drivers/SE05x/middleware/sss/src/user -I../Core_app/Drivers/SE05x/middleware/sss/src/user/crypto -I../Core_app/Drivers/SE05x/config -I../Core_app/Drivers/SE05x/platform/stm32h7rs/inc -I../Core_app/Drivers/SE05x/tests -I../USB_DEVICE/App -I../USB_DEVICE/Target -I../../Middlewares/ST/STM32_USB_Device_Library/Core/Inc -I../../Middlewares/ST/STM32_USB_Device_Library/Class/CDC/Inc -O3 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-Core_app-2f-Drivers-2f-FPC5234

clean-Core_app-2f-Drivers-2f-FPC5234:
	-$(RM) ./Core_app/Drivers/FPC5234/fpc_hal.cyclo ./Core_app/Drivers/FPC5234/fpc_hal.d ./Core_app/Drivers/FPC5234/fpc_hal.o ./Core_app/Drivers/FPC5234/fpc_hal.su ./Core_app/Drivers/FPC5234/fpc_hal_crypto.cyclo ./Core_app/Drivers/FPC5234/fpc_hal_crypto.d ./Core_app/Drivers/FPC5234/fpc_hal_crypto.o ./Core_app/Drivers/FPC5234/fpc_hal_crypto.su ./Core_app/Drivers/FPC5234/fpc_host_sample.cyclo ./Core_app/Drivers/FPC5234/fpc_host_sample.d ./Core_app/Drivers/FPC5234/fpc_host_sample.o ./Core_app/Drivers/FPC5234/fpc_host_sample.su ./Core_app/Drivers/FPC5234/hal_common.cyclo ./Core_app/Drivers/FPC5234/hal_common.d ./Core_app/Drivers/FPC5234/hal_common.o ./Core_app/Drivers/FPC5234/hal_common.su ./Core_app/Drivers/FPC5234/i2c_host.cyclo ./Core_app/Drivers/FPC5234/i2c_host.d ./Core_app/Drivers/FPC5234/i2c_host.o ./Core_app/Drivers/FPC5234/i2c_host.su ./Core_app/Drivers/FPC5234/spi_host.cyclo ./Core_app/Drivers/FPC5234/spi_host.d ./Core_app/Drivers/FPC5234/spi_host.o ./Core_app/Drivers/FPC5234/spi_host.su ./Core_app/Drivers/FPC5234/uart_debug.cyclo ./Core_app/Drivers/FPC5234/uart_debug.d ./Core_app/Drivers/FPC5234/uart_debug.o ./Core_app/Drivers/FPC5234/uart_debug.su ./Core_app/Drivers/FPC5234/uart_host.cyclo ./Core_app/Drivers/FPC5234/uart_host.d ./Core_app/Drivers/FPC5234/uart_host.o ./Core_app/Drivers/FPC5234/uart_host.su

.PHONY: clean-Core_app-2f-Drivers-2f-FPC5234

