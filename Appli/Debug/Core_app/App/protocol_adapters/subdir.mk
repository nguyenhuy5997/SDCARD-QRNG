################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (14.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Core_app/App/protocol_adapters/biometric_protocol.c \
../Core_app/App/protocol_adapters/ca_protocol.c \
../Core_app/App/protocol_adapters/media_protocol.c \
../Core_app/App/protocol_adapters/qrng_protocol.c \
../Core_app/App/protocol_adapters/security_protocol.c 

OBJS += \
./Core_app/App/protocol_adapters/biometric_protocol.o \
./Core_app/App/protocol_adapters/ca_protocol.o \
./Core_app/App/protocol_adapters/media_protocol.o \
./Core_app/App/protocol_adapters/qrng_protocol.o \
./Core_app/App/protocol_adapters/security_protocol.o 

C_DEPS += \
./Core_app/App/protocol_adapters/biometric_protocol.d \
./Core_app/App/protocol_adapters/ca_protocol.d \
./Core_app/App/protocol_adapters/media_protocol.d \
./Core_app/App/protocol_adapters/qrng_protocol.d \
./Core_app/App/protocol_adapters/security_protocol.d 


# Each subdirectory must supply rules for building sources it contributes
Core_app/App/protocol_adapters/%.o Core_app/App/protocol_adapters/%.su Core_app/App/protocol_adapters/%.cyclo: ../Core_app/App/protocol_adapters/%.c Core_app/App/protocol_adapters/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m7 -std=gnu11 -g3 -DEVT2_DIAGNOSTICS=0 -DEVT2_ENABLE_BIOMETRIC=0 -DUSE_HAL_DRIVER -DSTM32H7S3xx -DT1oI2C -DT1oI2C_UM11225 -DSSS_USE_FTR_FILE -DAX_EMBEDDED=1 -DPLUG_AND_TRUST_STM32 -DPLUG_AND_TRUST_STM32_ENABLE_SCP03 -DHOST_IF_UART -DDEBUG -c -I../Core/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc/Legacy -I../../Drivers/CMSIS/Device/ST/STM32H7RSxx/Include -I../../Drivers/CMSIS/Include -I../Core_app/Platform -I../Core_app/BSP -I../Core_app/App -I../Core_app/Middleware/Security -I../Core_app/Middleware/Biometric -I../Core_app/Middleware/QRNG -I../Core_app/Middleware/CommandProtocol -I../Core_app/Middleware/CA -I../Core_app/Middleware/PQC -I../Core_app/Middleware/PQC/pqclean -I../Core_app/Middleware/PQC/pqclean/ml-kem-768-clean -I../Core_app/Middleware/PQC/pqclean/common -I../Core_app/Drivers/QRNG -I../Core_app/Drivers/AD5398 -I../Core_app/Drivers/FPC5234 -I../Core_app/Drivers/SE05x/middleware/hostlib/inc -I../Core_app/Drivers/SE05x/middleware/hostlib/platform/inc -I../Core_app/Drivers/SE05x/middleware/hostlib/libCommon/infra -I../Core_app/Drivers/SE05x/middleware/hostlib/libCommon/log -I../Core_app/Drivers/SE05x/middleware/hostlib/libCommon/smCom -I../Core_app/Drivers/SE05x/middleware/hostlib/libCommon/smCom/T1oI2C -I../Core_app/Drivers/SE05x/middleware/hostlib/se05x/src -I../Core_app/Drivers/SE05x/middleware/hostlib/se05x_03_xx_xx -I../Core_app/Drivers/SE05x/middleware/sss/inc -I../Core_app/Drivers/SE05x/middleware/sss/port/default -I../Core_app/Drivers/SE05x/middleware/sss/src/user -I../Core_app/Drivers/SE05x/middleware/sss/src/user/crypto -I../Core_app/Drivers/SE05x/config -I../Core_app/Drivers/SE05x/platform/stm32h7rs/inc -I../Core_app/Drivers/SE05x/tests -I../USB_DEVICE/App -I../USB_DEVICE/Target -I../../Middlewares/ST/STM32_USB_Device_Library/Core/Inc -I../../Middlewares/ST/STM32_USB_Device_Library/Class/CDC/Inc -O2 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-Core_app-2f-App-2f-protocol_adapters

clean-Core_app-2f-App-2f-protocol_adapters:
	-$(RM) ./Core_app/App/protocol_adapters/biometric_protocol.cyclo ./Core_app/App/protocol_adapters/biometric_protocol.d ./Core_app/App/protocol_adapters/biometric_protocol.o ./Core_app/App/protocol_adapters/biometric_protocol.su ./Core_app/App/protocol_adapters/ca_protocol.cyclo ./Core_app/App/protocol_adapters/ca_protocol.d ./Core_app/App/protocol_adapters/ca_protocol.o ./Core_app/App/protocol_adapters/ca_protocol.su ./Core_app/App/protocol_adapters/media_protocol.cyclo ./Core_app/App/protocol_adapters/media_protocol.d ./Core_app/App/protocol_adapters/media_protocol.o ./Core_app/App/protocol_adapters/media_protocol.su ./Core_app/App/protocol_adapters/qrng_protocol.cyclo ./Core_app/App/protocol_adapters/qrng_protocol.d ./Core_app/App/protocol_adapters/qrng_protocol.o ./Core_app/App/protocol_adapters/qrng_protocol.su ./Core_app/App/protocol_adapters/security_protocol.cyclo ./Core_app/App/protocol_adapters/security_protocol.d ./Core_app/App/protocol_adapters/security_protocol.o ./Core_app/App/protocol_adapters/security_protocol.su

.PHONY: clean-Core_app-2f-App-2f-protocol_adapters

