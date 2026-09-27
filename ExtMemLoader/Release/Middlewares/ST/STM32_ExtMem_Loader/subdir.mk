################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (14.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
D:/Workspace/SDQRNG_V8Y/Middlewares/ST/STM32_ExtMem_Loader/MDK-ARM/FlashDev.c \
D:/Workspace/SDQRNG_V8Y/Middlewares/ST/STM32_ExtMem_Loader/MDK-ARM/FlashPrg.c \
D:/Workspace/SDQRNG_V8Y/Middlewares/ST/STM32_ExtMem_Loader/core/memory_wrapper.c \
D:/Workspace/SDQRNG_V8Y/Middlewares/ST/STM32_ExtMem_Loader/STM32Cube/stm32_device_info.c \
D:/Workspace/SDQRNG_V8Y/Middlewares/ST/STM32_ExtMem_Loader/STM32Cube/stm32_loader_api.c \
D:/Workspace/SDQRNG_V8Y/Middlewares/ST/STM32_ExtMem_Loader/core/systick_management.c 

OBJS += \
./Middlewares/ST/STM32_ExtMem_Loader/FlashDev.o \
./Middlewares/ST/STM32_ExtMem_Loader/FlashPrg.o \
./Middlewares/ST/STM32_ExtMem_Loader/memory_wrapper.o \
./Middlewares/ST/STM32_ExtMem_Loader/stm32_device_info.o \
./Middlewares/ST/STM32_ExtMem_Loader/stm32_loader_api.o \
./Middlewares/ST/STM32_ExtMem_Loader/systick_management.o 

C_DEPS += \
./Middlewares/ST/STM32_ExtMem_Loader/FlashDev.d \
./Middlewares/ST/STM32_ExtMem_Loader/FlashPrg.d \
./Middlewares/ST/STM32_ExtMem_Loader/memory_wrapper.d \
./Middlewares/ST/STM32_ExtMem_Loader/stm32_device_info.d \
./Middlewares/ST/STM32_ExtMem_Loader/stm32_loader_api.d \
./Middlewares/ST/STM32_ExtMem_Loader/systick_management.d 


# Each subdirectory must supply rules for building sources it contributes
Middlewares/ST/STM32_ExtMem_Loader/FlashDev.o: D:/Workspace/SDQRNG_V8Y/Middlewares/ST/STM32_ExtMem_Loader/MDK-ARM/FlashDev.c Middlewares/ST/STM32_ExtMem_Loader/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m7 -std=gnu11 -DUSE_HAL_DRIVER -DSTM32H7S3xx -DSTM32_EXTMEMLOADER_STM32CUBETARGET -c -I../Core/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc/Legacy -I../../Middlewares/ST/STM32_ExtMem_Loader/core -I../../Middlewares/ST/STM32_ExtMem_Loader/MDK-ARM -I../../Middlewares/ST/STM32_ExtMem_Loader/STM32Cube -I../../Middlewares/ST/STM32_ExtMem_Manager -I../../Middlewares/ST/STM32_ExtMem_Manager/sal -I../../Middlewares/ST/STM32_ExtMem_Manager/nor_sfdp -I../../Middlewares/ST/STM32_ExtMem_Manager/psram -I../../Middlewares/ST/STM32_ExtMem_Manager/sdcard -I../../Middlewares/ST/STM32_ExtMem_Manager/user -I../../Drivers/CMSIS/Device/ST/STM32H7RSxx/Include -I../../Drivers/CMSIS/Include -Os -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb -o "$@"
Middlewares/ST/STM32_ExtMem_Loader/FlashPrg.o: D:/Workspace/SDQRNG_V8Y/Middlewares/ST/STM32_ExtMem_Loader/MDK-ARM/FlashPrg.c Middlewares/ST/STM32_ExtMem_Loader/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m7 -std=gnu11 -DUSE_HAL_DRIVER -DSTM32H7S3xx -DSTM32_EXTMEMLOADER_STM32CUBETARGET -c -I../Core/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc/Legacy -I../../Middlewares/ST/STM32_ExtMem_Loader/core -I../../Middlewares/ST/STM32_ExtMem_Loader/MDK-ARM -I../../Middlewares/ST/STM32_ExtMem_Loader/STM32Cube -I../../Middlewares/ST/STM32_ExtMem_Manager -I../../Middlewares/ST/STM32_ExtMem_Manager/sal -I../../Middlewares/ST/STM32_ExtMem_Manager/nor_sfdp -I../../Middlewares/ST/STM32_ExtMem_Manager/psram -I../../Middlewares/ST/STM32_ExtMem_Manager/sdcard -I../../Middlewares/ST/STM32_ExtMem_Manager/user -I../../Drivers/CMSIS/Device/ST/STM32H7RSxx/Include -I../../Drivers/CMSIS/Include -Os -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb -o "$@"
Middlewares/ST/STM32_ExtMem_Loader/memory_wrapper.o: D:/Workspace/SDQRNG_V8Y/Middlewares/ST/STM32_ExtMem_Loader/core/memory_wrapper.c Middlewares/ST/STM32_ExtMem_Loader/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m7 -std=gnu11 -DUSE_HAL_DRIVER -DSTM32H7S3xx -DSTM32_EXTMEMLOADER_STM32CUBETARGET -c -I../Core/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc/Legacy -I../../Middlewares/ST/STM32_ExtMem_Loader/core -I../../Middlewares/ST/STM32_ExtMem_Loader/MDK-ARM -I../../Middlewares/ST/STM32_ExtMem_Loader/STM32Cube -I../../Middlewares/ST/STM32_ExtMem_Manager -I../../Middlewares/ST/STM32_ExtMem_Manager/sal -I../../Middlewares/ST/STM32_ExtMem_Manager/nor_sfdp -I../../Middlewares/ST/STM32_ExtMem_Manager/psram -I../../Middlewares/ST/STM32_ExtMem_Manager/sdcard -I../../Middlewares/ST/STM32_ExtMem_Manager/user -I../../Drivers/CMSIS/Device/ST/STM32H7RSxx/Include -I../../Drivers/CMSIS/Include -Os -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb -o "$@"
Middlewares/ST/STM32_ExtMem_Loader/stm32_device_info.o: D:/Workspace/SDQRNG_V8Y/Middlewares/ST/STM32_ExtMem_Loader/STM32Cube/stm32_device_info.c Middlewares/ST/STM32_ExtMem_Loader/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m7 -std=gnu11 -DUSE_HAL_DRIVER -DSTM32H7S3xx -DSTM32_EXTMEMLOADER_STM32CUBETARGET -c -I../Core/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc/Legacy -I../../Middlewares/ST/STM32_ExtMem_Loader/core -I../../Middlewares/ST/STM32_ExtMem_Loader/MDK-ARM -I../../Middlewares/ST/STM32_ExtMem_Loader/STM32Cube -I../../Middlewares/ST/STM32_ExtMem_Manager -I../../Middlewares/ST/STM32_ExtMem_Manager/sal -I../../Middlewares/ST/STM32_ExtMem_Manager/nor_sfdp -I../../Middlewares/ST/STM32_ExtMem_Manager/psram -I../../Middlewares/ST/STM32_ExtMem_Manager/sdcard -I../../Middlewares/ST/STM32_ExtMem_Manager/user -I../../Drivers/CMSIS/Device/ST/STM32H7RSxx/Include -I../../Drivers/CMSIS/Include -Os -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb -o "$@"
Middlewares/ST/STM32_ExtMem_Loader/stm32_loader_api.o: D:/Workspace/SDQRNG_V8Y/Middlewares/ST/STM32_ExtMem_Loader/STM32Cube/stm32_loader_api.c Middlewares/ST/STM32_ExtMem_Loader/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m7 -std=gnu11 -DUSE_HAL_DRIVER -DSTM32H7S3xx -DSTM32_EXTMEMLOADER_STM32CUBETARGET -c -I../Core/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc/Legacy -I../../Middlewares/ST/STM32_ExtMem_Loader/core -I../../Middlewares/ST/STM32_ExtMem_Loader/MDK-ARM -I../../Middlewares/ST/STM32_ExtMem_Loader/STM32Cube -I../../Middlewares/ST/STM32_ExtMem_Manager -I../../Middlewares/ST/STM32_ExtMem_Manager/sal -I../../Middlewares/ST/STM32_ExtMem_Manager/nor_sfdp -I../../Middlewares/ST/STM32_ExtMem_Manager/psram -I../../Middlewares/ST/STM32_ExtMem_Manager/sdcard -I../../Middlewares/ST/STM32_ExtMem_Manager/user -I../../Drivers/CMSIS/Device/ST/STM32H7RSxx/Include -I../../Drivers/CMSIS/Include -Os -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb -o "$@"
Middlewares/ST/STM32_ExtMem_Loader/systick_management.o: D:/Workspace/SDQRNG_V8Y/Middlewares/ST/STM32_ExtMem_Loader/core/systick_management.c Middlewares/ST/STM32_ExtMem_Loader/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m7 -std=gnu11 -DUSE_HAL_DRIVER -DSTM32H7S3xx -DSTM32_EXTMEMLOADER_STM32CUBETARGET -c -I../Core/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc -I../../Drivers/STM32H7RSxx_HAL_Driver/Inc/Legacy -I../../Middlewares/ST/STM32_ExtMem_Loader/core -I../../Middlewares/ST/STM32_ExtMem_Loader/MDK-ARM -I../../Middlewares/ST/STM32_ExtMem_Loader/STM32Cube -I../../Middlewares/ST/STM32_ExtMem_Manager -I../../Middlewares/ST/STM32_ExtMem_Manager/sal -I../../Middlewares/ST/STM32_ExtMem_Manager/nor_sfdp -I../../Middlewares/ST/STM32_ExtMem_Manager/psram -I../../Middlewares/ST/STM32_ExtMem_Manager/sdcard -I../../Middlewares/ST/STM32_ExtMem_Manager/user -I../../Drivers/CMSIS/Device/ST/STM32H7RSxx/Include -I../../Drivers/CMSIS/Include -Os -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-Middlewares-2f-ST-2f-STM32_ExtMem_Loader

clean-Middlewares-2f-ST-2f-STM32_ExtMem_Loader:
	-$(RM) ./Middlewares/ST/STM32_ExtMem_Loader/FlashDev.cyclo ./Middlewares/ST/STM32_ExtMem_Loader/FlashDev.d ./Middlewares/ST/STM32_ExtMem_Loader/FlashDev.o ./Middlewares/ST/STM32_ExtMem_Loader/FlashDev.su ./Middlewares/ST/STM32_ExtMem_Loader/FlashPrg.cyclo ./Middlewares/ST/STM32_ExtMem_Loader/FlashPrg.d ./Middlewares/ST/STM32_ExtMem_Loader/FlashPrg.o ./Middlewares/ST/STM32_ExtMem_Loader/FlashPrg.su ./Middlewares/ST/STM32_ExtMem_Loader/memory_wrapper.cyclo ./Middlewares/ST/STM32_ExtMem_Loader/memory_wrapper.d ./Middlewares/ST/STM32_ExtMem_Loader/memory_wrapper.o ./Middlewares/ST/STM32_ExtMem_Loader/memory_wrapper.su ./Middlewares/ST/STM32_ExtMem_Loader/stm32_device_info.cyclo ./Middlewares/ST/STM32_ExtMem_Loader/stm32_device_info.d ./Middlewares/ST/STM32_ExtMem_Loader/stm32_device_info.o ./Middlewares/ST/STM32_ExtMem_Loader/stm32_device_info.su ./Middlewares/ST/STM32_ExtMem_Loader/stm32_loader_api.cyclo ./Middlewares/ST/STM32_ExtMem_Loader/stm32_loader_api.d ./Middlewares/ST/STM32_ExtMem_Loader/stm32_loader_api.o ./Middlewares/ST/STM32_ExtMem_Loader/stm32_loader_api.su ./Middlewares/ST/STM32_ExtMem_Loader/systick_management.cyclo ./Middlewares/ST/STM32_ExtMem_Loader/systick_management.d ./Middlewares/ST/STM32_ExtMem_Loader/systick_management.o ./Middlewares/ST/STM32_ExtMem_Loader/systick_management.su

.PHONY: clean-Middlewares-2f-ST-2f-STM32_ExtMem_Loader

