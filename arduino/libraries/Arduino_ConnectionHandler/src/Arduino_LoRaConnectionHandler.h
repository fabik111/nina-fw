/*
   This file is part of ArduinoIoTCloud.

   Copyright 2019 ARDUINO SA (http://www.arduino.cc/)

   This software is released under the GNU General Public License version 3,
   which covers the main part of arduino-cli.
   The terms of this license can be found at:
   https://www.gnu.org/licenses/gpl-3.0.en.html

   You can be released from the requirements of the above licenses by purchasing
   a commercial license. Buying such a license is mandatory if you want to modify or
   otherwise use the software for commercial activities involving the Arduino
   software without disclosing the source code of your own applications. To purchase
   a commercial license, send an email to license@arduino.cc.
*/

#ifndef ARDUINO_LORA_CONNECTION_HANDLER_H_
#define ARDUINO_LORA_CONNECTION_HANDLER_H_

/******************************************************************************
   INCLUDE
 ******************************************************************************/

#include "Arduino_LPWANConnectionHandler.h"

typedef enum {
  LORA_ERROR_ACK_NOT_RECEIVED = -1,
  LORA_ERROR_GENERIC = -2,
  LORA_ERROR_WRONG_PARAM = -3,
  LORA_ERROR_COMMUNICATION_BUSY = -4,
  LORA_ERROR_MESSAGE_OVERFLOW = -5,
  LORA_ERROR_NO_NETWORK_AVAILABLE = -6,
  LORA_ERROR_RX_PACKET = -7,
  LORA_ERROR_REASON_UNKNOWN = -8,
  LORA_ERROR_MAX_PACKET_SIZE = -20
} LoRaCommunicationError;

/******************************************************************************
   CLASS DECLARATION
 ******************************************************************************/

class LoRaConnectionHandler : public LPWANConnectionHandler {
  public:
    LoRaConnectionHandler(const char *_appeui, const char *_appkey, _lora_band = _lora_band::EU868, _lora_class = _lora_class::CLASS_A);

    void init();
    unsigned long getTime();
    void check() {
      update();
    }
    void update();

    int write(const uint8_t *buf, size_t size);
    int read();
    bool available();

    void disconnect();
    void connect();

  private:

    const int CHECK_INTERVAL_IDLE = 100;
    const int CHECK_INTERVAL_INIT = 100;
    const int CHECK_INTERVAL_CONNECTING = 500;
    const int CHECK_INTERVAL_CONNECTED = 10000;
    const int CHECK_INTERVAL_RETRYING = 30000;
    const int CHECK_INTERVAL_DISCONNECTING = 500;
    const int CHECK_INTERVAL_DISCONNECTED = 1000;
    const int CHECK_INTERVAL_ERROR = 500;

    LoRaModem modem;
    const char *appeui, *appkey;
    _lora_band band;
    _lora_class deviceClass;
    unsigned long lastConnectionTickTime;

    int connectionTickTimeInterval;

    bool keepAlive;

    NetworkConnectionState update_handleInit();
    NetworkConnectionState update_handleConnecting();
    NetworkConnectionState update_handleConnected();

    NetworkConnectionState update_handleDisconnecting();
    NetworkConnectionState update_handleDisconnected();


};

#endif /* ARDUINO_LORA_CONNECTION_HANDLER_H_ */
