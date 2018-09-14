from binaryninja_cortex.platforms import MCU

class Chip(MCU):
    NAME="STM32F4"
    ROM_OFF=0x08000000 
    RAM_OFF=0x20000000
    IRQ=MCU.IRQ+ [
        "NVIC_WWDG_IRQ",
        "NVIC_PVD_IRQ",
        "NVIC_TAMP_STAMP_IRQ",
        "NVIC_RTC_WKUP_IRQ",
        "NVIC_FLASH_IRQ",
        "NVIC_RCC_IRQ",
        "NVIC_EXTI0_IRQ",
        "NVIC_EXTI1_IRQ",
        "NVIC_EXTI2_IRQ",
        "NVIC_EXTI3_IRQ",
        "NVIC_EXTI4_IRQ",
        "NVIC_DMA1_STREAM0_IRQ",
        "NVIC_DMA1_STREAM1_IRQ",
        "NVIC_DMA1_STREAM2_IRQ",
        "NVIC_DMA1_STREAM3_IRQ",
        "NVIC_DMA1_STREAM4_IRQ",
        "NVIC_DMA1_STREAM5_IRQ",
        "NVIC_DMA1_STREAM6_IRQ",
        "NVIC_ADC_IRQ",
        "NVIC_CAN1_TX_IRQ",
        "NVIC_CAN1_RX0_IRQ",
        "NVIC_CAN1_RX1_IRQ",
        "NVIC_CAN1_SCE_IRQ",
        "NVIC_EXTI9_5_IRQ",
        "NVIC_TIM1_BRK_TIM9_IRQ",
        "NVIC_TIM1_UP_TIM10_IRQ",
        "NVIC_TIM1_TRG_COM_TIM11_IRQ",
        "NVIC_TIM1_CC_IRQ",
        "NVIC_TIM2_IRQ",
        "NVIC_TIM3_IRQ",
        "NVIC_TIM4_IRQ",
        "NVIC_I2C1_EV_IRQ",
        "NVIC_I2C1_ER_IRQ",
        "NVIC_I2C2_EV_IRQ",
        "NVIC_I2C2_ER_IRQ",
        "NVIC_SPI1_IRQ",
        "NVIC_SPI2_IRQ",
        "NVIC_USART1_IRQ",
        "NVIC_USART2_IRQ",
        "NVIC_USART3_IRQ",
        "NVIC_EXTI15_10_IRQ",
        "NVIC_RTC_ALARM_IRQ",
        "NVIC_USB_FS_WKUP_IRQ",
        "NVIC_TIM8_BRK_TIM12_IRQ",
        "NVIC_TIM8_UP_TIM13_IRQ",
        "NVIC_TIM8_TRG_COM_TIM14_IRQ",
        "NVIC_TIM8_CC_IRQ",
        "NVIC_DMA1_STREAM7_IRQ",
        "NVIC_FSMC_IRQ",
        "NVIC_SDIO_IRQ",
        "NVIC_TIM5_IRQ",
        "NVIC_SPI3_IRQ",
        "NVIC_UART4_IRQ",
        "NVIC_UART5_IRQ",
        "NVIC_TIM6_DAC_IRQ",
        "NVIC_TIM7_IRQ",
        "NVIC_DMA2_STREAM0_IRQ",
        "NVIC_DMA2_STREAM1_IRQ",
        "NVIC_DMA2_STREAM2_IRQ",
        "NVIC_DMA2_STREAM3_IRQ",
        "NVIC_DMA2_STREAM4_IRQ",
        "NVIC_ETH_IRQ",
        "NVIC_ETH_WKUP_IRQ",
        "NVIC_CAN2_TX_IRQ",
        "NVIC_CAN2_RX0_IRQ",
        "NVIC_CAN2_RX1_IRQ",
        "NVIC_CAN2_SCE_IRQ",
        "NVIC_OTG_FS_IRQ",
        "NVIC_DMA2_STREAM5_IRQ",
        "NVIC_DMA2_STREAM6_IRQ",
        "NVIC_DMA2_STREAM7_IRQ",
        "NVIC_USART6_IRQ",
        "NVIC_I2C3_EV_IRQ",
        "NVIC_I2C3_ER_IRQ",
        "NVIC_OTG_HS_EP1_OUT_IRQ",
        "NVIC_OTG_HS_EP1_IN_IRQ",
        "NVIC_OTG_HS_WKUP_IRQ",
        "NVIC_OTG_HS_IRQ",
        "NVIC_DCMI_IRQ",
        "NVIC_CRYP_IRQ",
        "NVIC_HASH_RNG_IRQ",
        "NVIC_FPU_IRQ",
        "NVIC_UART7_IRQ",
        "NVIC_UART8_IRQ",
        "NVIC_SPI4_IRQ",
        "NVIC_SPI5_IRQ",
        "NVIC_SPI6_IRQ",
        "NVIC_SAI1_IRQ",
        "NVIC_LCD_TFT_IRQ",
        "NVIC_LCD_TFT_ERR_IRQ",
        "NVIC_DMA2D_IRQ",
        ]
