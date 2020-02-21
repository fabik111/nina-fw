/*
  This file is part of the Arduino NINA firmware.
  Copyright (c) 2018 Arduino SA. All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "arduino_secrets.h"
#include <rom/uart.h>

extern "C" {
  #include <driver/periph_ctrl.h>
  #include <driver/uart.h>
  #include <esp_bt.h>
}

#include <Arduino.h>

#include <SPIS.h>
#include <WiFi.h>

#include "thingProperties.h"

#define SPI_BUFFER_LEN SPI_MAX_DMA_LEN

int debug = 0;
char CUSTOMCIAO[5];

unsigned long tf = 0;

void setupWiFi();
void setupBluetooth();

void setup() {
 Serial.begin(115200);

 initProperties();
  // Connect to Arduino IoT Cloud
  
  

 //setupWiFi();
  
  delay(1000);

  ArduinoCloud.begin(ArduinoIoTPreferredConnection);
    setDebugMessageLevel(2);
  ArduinoCloud.printDebugInfo();
  #ifdef ARDUINO_NINA_ESP32
    memcpy(CUSTOMCIAO,"INIT" ,sizeof("INIT"));
  #endif
  temperature=22.0;
}



// #define UNO_WIFI_REV2

void setupBluetooth() {
  periph_module_enable(PERIPH_UART1_MODULE);
  periph_module_enable(PERIPH_UHCI0_MODULE);

#ifdef UNO_WIFI_REV2
  uart_set_pin(UART_NUM_1, 1, 3, 33, 0); // TX, RX, RTS, CTS
#else
  uart_set_pin(UART_NUM_1, 23, 12, 18, 5);
#endif
  uart_set_hw_flow_ctrl(UART_NUM_1, UART_HW_FLOWCTRL_CTS_RTS, 5);

  esp_bt_controller_config_t btControllerConfig = BT_CONTROLLER_INIT_CONFIG_DEFAULT();

  btControllerConfig.hci_uart_no = UART_NUM_1;
#ifdef UNO_WIFI_REV2
  btControllerConfig.hci_uart_baudrate = 115200;
#else
  btControllerConfig.hci_uart_baudrate = 912600;
#endif

  esp_bt_controller_init(&btControllerConfig);
  while (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_IDLE);
  esp_bt_controller_enable(ESP_BT_MODE_BLE);
  esp_bt_sleep_enable();

  vTaskSuspend(NULL);

  while (1) {
    vTaskDelay(portMAX_DELAY);
  }
}

void setupWiFi() {
  esp_bt_controller_mem_release(ESP_BT_MODE_BTDM);
  //SPIS.begin();

  if (WiFi.status() == WL_NO_SHIELD) {
    Serial.println("noWIFI");
    while (1); // no shield
  }
}

void loop() {

  ArduinoCloud.update();
  unsigned long current = millis();
  if((current-tf)> 10000){

  temperature += 0.5;
  #ifdef ARDUINO_NINA_ESP32
    String s = String(temperature);
    //memcpy(CUSTOMCIAO,s.c_str() ,s.length());
  #endif
    if(temperature > 30){
      temperature = 22.0;
    }
    tf = current;
  }

}
void onColoredLightChange() {
  ColoredLight colorlight = coloredLight.getValue();

  float h = colorlight.hue/360;
  float s = colorlight.sat/100;
  float b = colorlight.bri/200;

  /*
  if(colorlight.swi) {
    leds.setColorHSL(0,h,s,b);
  }else{
    leds.setColorHSL(0,h,s,0.0);
  }
  */

  Serial.print("Colored Light Status: ");
  Serial.println(colorlight.swi);
  Serial.print("Colored Light Color Hue: ");
  Serial.print(colorlight.hue);
  Serial.print(" Sat: ");
  Serial.print(colorlight.sat);
  Serial.print(" Bri: ");
  Serial.print(colorlight.bri);
  Serial.println();
}


void onDimmedLightChange() {
  DimmedLight dimlight = dimmedLight.getValue();

  /*
  float b = dimlight.bri/200;
  if(dimlight.swi){
    leds.setColorHSL(1,0.1,0.0,b);
  }else{
    leds.setColorHSL(1,0.1,0.0,0.0);
  }
  */

  Serial.print("Dimmed Light Status: ");
  Serial.println(dimlight.swi);
  Serial.print("Dimmed Light : ");
  Serial.print(" Bri: ");
  Serial.print(dimlight.bri);
  Serial.println();
}


void onLightChange() {
  /*
  if(light){
    leds.setColorHSL(2,0.1,0.0,1.0);
  }else{
    leds.setColorHSL(2,0.1,0.0,0.0);
  }
  */

  Serial.print("Light Status: ");
  Serial.println(light);
}

void handleButton() {
  light = !light;
  /*
  if(light){
    leds.setColorHSL(2,0.1,0.0,1.0);
  }else{
    leds.setColorHSL(2,0.1,0.0,0.0);
  }
  */

  Serial.print("Light: ");
  Serial.println(light);
  delayMicroseconds(50000);

}


