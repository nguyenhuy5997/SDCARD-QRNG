################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (14.3.rel1)
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include USB_DEVICE/Target/subdir.mk
-include USB_DEVICE/App/subdir.mk
-include Middlewares/ST/STM32_USB_Device_Library/subdir.mk
-include Drivers/STM32H7RSxx_HAL_Driver/subdir.mk
-include Core_app/Platform/STM32H7RSxx/subdir.mk
-include Core_app/Middleware/Security/p256-m/subdir.mk
-include Core_app/Middleware/Security/SE052F/subdir.mk
-include Core_app/Middleware/QRNG/ADC_Noise/subdir.mk
-include Core_app/Middleware/PQC/pqclean/ml-kem-768-clean/subdir.mk
-include Core_app/Middleware/PQC/pqclean/ml-dsa-87-clean/subdir.mk
-include Core_app/Middleware/PQC/pqclean/ml-dsa-65-clean/subdir.mk
-include Core_app/Middleware/PQC/pqclean/ml-dsa-44-clean/subdir.mk
-include Core_app/Middleware/PQC/pqclean/common/subdir.mk
-include Core_app/Middleware/PQC/subdir.mk
-include Core_app/Middleware/CommandProtocol/subdir.mk
-include Core_app/Middleware/CA/subdir.mk
-include Core_app/Middleware/Biometric/FPC5234/subdir.mk
-include Core_app/Drivers/SE05x/tests/subdir.mk
-include Core_app/Drivers/SE05x/platform/stm32h7rs/src/subdir.mk
-include Core_app/Drivers/SE05x/middleware/sss/src/user/crypto/subdir.mk
-include Core_app/Drivers/SE05x/middleware/sss/src/user/subdir.mk
-include Core_app/Drivers/SE05x/middleware/sss/src/se05x/subdir.mk
-include Core_app/Drivers/SE05x/middleware/hostlib/se05x_03_xx_xx/subdir.mk
-include Core_app/Drivers/SE05x/middleware/hostlib/se05x/src/subdir.mk
-include Core_app/Drivers/SE05x/middleware/hostlib/libCommon/smCom/T1oI2C/subdir.mk
-include Core_app/Drivers/SE05x/middleware/hostlib/libCommon/smCom/subdir.mk
-include Core_app/Drivers/SE05x/middleware/hostlib/libCommon/nxScp/subdir.mk
-include Core_app/Drivers/SE05x/middleware/hostlib/libCommon/log/subdir.mk
-include Core_app/Drivers/SE05x/middleware/hostlib/libCommon/infra/subdir.mk
-include Core_app/Drivers/QRNG/subdir.mk
-include Core_app/Drivers/FPC5234/tests/subdir.mk
-include Core_app/Drivers/FPC5234/subdir.mk
-include Core_app/Drivers/AD5398/subdir.mk
-include Core_app/BSP/subdir.mk
-include Core_app/App/protocol_adapters/subdir.mk
-include Core_app/App/subdir.mk
-include Core/Startup/subdir.mk
-include Core/Src/subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(S_DEPS)),)
-include $(S_DEPS)
endif
ifneq ($(strip $(S_UPPER_DEPS)),)
-include $(S_UPPER_DEPS)
endif
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

OPTIONAL_TOOL_DEPS := \
$(wildcard ../makefile.defs) \
$(wildcard ../makefile.init) \
$(wildcard ../makefile.targets) \


BUILD_ARTIFACT_NAME := exercise1_Appli
BUILD_ARTIFACT_EXTENSION := elf
BUILD_ARTIFACT_PREFIX :=
BUILD_ARTIFACT := $(BUILD_ARTIFACT_PREFIX)$(BUILD_ARTIFACT_NAME)$(if $(BUILD_ARTIFACT_EXTENSION),.$(BUILD_ARTIFACT_EXTENSION),)

# Add inputs and outputs from these tool invocations to the build variables 
EXECUTABLES += \
exercise1_Appli.elf \

MAP_FILES += \
exercise1_Appli.map \

SIZE_OUTPUT += \
default.size.stdout \

OBJDUMP_LIST += \
exercise1_Appli.list \


# All Target
all: main-build

# Main-build Target
main-build: exercise1_Appli.elf secondary-outputs

# Tool invocations
exercise1_Appli.elf exercise1_Appli.map: $(OBJS) $(USER_OBJS) D:\Workspace\SDQRNG_V8Y\Appli\STM32H7S3L8HX_ROMxspi1.ld makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-gcc -o "exercise1_Appli.elf" @"objects.list" $(USER_OBJS) $(LIBS) -mcpu=cortex-m7 -T"D:\Workspace\SDQRNG_V8Y\Appli\STM32H7S3L8HX_ROMxspi1.ld" --specs=nosys.specs -Wl,-Map="exercise1_Appli.map" -Wl,--gc-sections -static --specs=nano.specs -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb -Wl,--start-group -lc -lm -Wl,--end-group
	@echo 'Finished building target: $@'
	@echo ' '

default.size.stdout: $(EXECUTABLES) makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-size  $(EXECUTABLES)
	@echo 'Finished building: $@'
	@echo ' '

exercise1_Appli.list: $(EXECUTABLES) makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-objdump -h -S $(EXECUTABLES) > "exercise1_Appli.list"
	@echo 'Finished building: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) default.size.stdout exercise1_Appli.elf exercise1_Appli.list exercise1_Appli.map
	-@echo ' '

secondary-outputs: $(SIZE_OUTPUT) $(OBJDUMP_LIST)

fail-specified-linker-script-missing:
	@echo 'Error: Cannot find the specified linker script. Check the linker settings in the build configuration.'
	@exit 2

warn-no-linker-script-specified:
	@echo 'Warning: No linker script specified. Check the linker settings in the build configuration.'

.PHONY: all clean dependents main-build fail-specified-linker-script-missing warn-no-linker-script-specified

-include ../makefile.targets
