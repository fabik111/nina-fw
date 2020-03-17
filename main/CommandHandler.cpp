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

#include <lwip/sockets.h>

#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiServer.h>
#include <WiFiSSLClient.h>
#include <WiFiUdp.h>

#include "arduino_secrets.h"
#include <ArduinoIoTCloud.h>
#include <Arduino_ConnectionHandler.h>

#include "CommandHandler.h"

const char FIRMWARE_VERSION[6] = "1.3.0";
#ifdef ARDUINO_NINA_ESP32
extern char CUSTOMCIAO[5];
#endif
/*IPAddress*/uint32_t resolvedHostname;

LinkedList<ArduinoCloudProperty *> _global_property_list;
WiFiConnectionHandler *ArduinoIoTPreferredConnection;
char ssid[32 + 1];
char pass[64 + 1];
char mqtt[64 + 1];
char thingId[36];


#define MAX_SOCKETS CONFIG_LWIP_MAX_SOCKETS
uint8_t socketTypes[MAX_SOCKETS];
WiFiClient tcpClients[MAX_SOCKETS];
WiFiUDP udps[MAX_SOCKETS];
WiFiSSLClient tlsClients[MAX_SOCKETS];
WiFiServer tcpServers[MAX_SOCKETS];


int setNet(const uint8_t command[], uint8_t response[])
{
  char ssid[32 + 1];

  memset(ssid, 0x00, sizeof(ssid));
  memcpy(ssid, &command[4], command[3]);

  WiFi.begin(ssid);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

int setPassPhrase(const uint8_t command[], uint8_t response[])
{
  char ssid[32 + 1];
  char pass[64 + 1];

  memset(ssid, 0x00, sizeof(ssid));
  memset(pass, 0x00, sizeof(pass));

  memcpy(ssid, &command[4], command[3]);
  memcpy(pass, &command[5 + command[3]], command[4 + command[3]]);

  WiFi.begin(ssid, pass);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

int setKey(const uint8_t command[], uint8_t response[])
{
  char ssid[32 + 1];
  char key[26 + 1];

  memset(ssid, 0x00, sizeof(ssid));
  memset(key, 0x00, sizeof(key));

  memcpy(ssid, &command[4], command[3]);
  memcpy(key, &command[7 + command[3]], command[6 + command[3]]);

  WiFi.begin(ssid, key);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

int setIPconfig(const uint8_t command[], uint8_t response[])
{
  uint32_t ip;
  uint32_t gwip;
  uint32_t mask;

  memcpy(&ip, &command[6], sizeof(ip));
  memcpy(&gwip, &command[11], sizeof(gwip));
  memcpy(&mask, &command[16], sizeof(mask));

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length

  WiFi.config(ip, gwip, mask);

  return 6;
}

int setDNSconfig(const uint8_t command[], uint8_t response[])
{
  uint32_t dns1;
  uint32_t dns2;

  memcpy(&dns1, &command[6], sizeof(dns1));
  memcpy(&dns2, &command[11], sizeof(dns2));

  WiFi.setDNS(dns1, dns2);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

int setHostname(const uint8_t command[], uint8_t response[])
{
  char hostname[255 + 1];

  memset(hostname, 0x00, sizeof(hostname));
  memcpy(hostname, &command[4], command[3]);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  WiFi.hostname(hostname);

  return 6;
}

int setPowerMode(const uint8_t command[], uint8_t response[])
{
  if (command[4]) {
    // low power
    WiFi.lowPowerMode();
  } else {
    // no low power
    WiFi.noLowPowerMode();
  }

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

int setApNet(const uint8_t command[], uint8_t response[])
{
  char ssid[32 + 1];
  uint8_t channel;

  memset(ssid, 0x00, sizeof(ssid));
  memcpy(ssid, &command[4], command[3]);

  channel = command[5 + command[3]];

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length

  if (WiFi.beginAP(ssid, channel) != WL_AP_FAILED) {
    response[4] = 1;
  } else {
    response[4] = 0;
  }

  return 6;
}

int setApPassPhrase(const uint8_t command[], uint8_t response[])
{
  char ssid[32 + 1];
  char pass[64 + 1];
  uint8_t channel;

  memset(ssid, 0x00, sizeof(ssid));
  memset(pass, 0x00, sizeof(pass));

  memcpy(ssid, &command[4], command[3]);
  memcpy(pass, &command[5 + command[3]], command[4 + command[3]]);
  channel = command[6 + command[3] + command[4 + command[3]]];

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length

  if (WiFi.beginAP(ssid, pass, channel) != WL_AP_FAILED) {
    response[4] = 1;
  } else {
    response[4] = 0;
  }

  return 6;
}

extern void setDebug(int debug);

int setDebug(const uint8_t command[], uint8_t response[])
{
  setDebug(command[4]);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

extern "C" {
  uint8_t temprature_sens_read();
}

int getTemperature(const uint8_t command[], uint8_t response[])
{
  float temperature = (temprature_sens_read() - 32) / 1.8;

  response[2] = 1; // number of parameters
  response[3] = sizeof(temperature); // parameter 1 length

  memcpy(&response[4], &temperature, sizeof(temperature));

  return 9;
}

int getReasonCode(const uint8_t command[], uint8_t response[])
{
  uint8_t reasonCode = WiFi.reasonCode();

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = reasonCode;

  return 6;
}

int getConnStatus(const uint8_t command[], uint8_t response[])
{
  uint8_t status = WiFi.status();

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = status;

  return 6;
}

int getIPaddr(const uint8_t command[], uint8_t response[])
{
  /*IPAddress*/uint32_t ip = WiFi.localIP();
  /*IPAddress*/uint32_t mask = WiFi.subnetMask();
  /*IPAddress*/uint32_t gwip = WiFi.gatewayIP();

  response[2] = 3; // number of parameters

  response[3] = 4; // parameter 1 length
  memcpy(&response[4], &ip, sizeof(ip));

  response[8] = 4; // parameter 2 length
  memcpy(&response[9], &mask, sizeof(mask));

  response[13] = 4; // parameter 3 length
  memcpy(&response[14], &gwip, sizeof(gwip));

  return 19;
}

int getMACaddr(const uint8_t command[], uint8_t response[])
{
  uint8_t mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  WiFi.macAddress(mac);

  response[2] = 1; // number of parameters
  response[3] = sizeof(mac); // parameter 1 length

  memcpy(&response[4], mac, sizeof(mac));

  return 11;
}

int getCurrSSID(const uint8_t command[], uint8_t response[])
{
  // ssid
  const char* ssid = WiFi.SSID();
  uint8_t ssidLen = strlen(ssid);

  response[2] = 1; // number of parameters
  response[3] = ssidLen; // parameter 1 length

  memcpy(&response[4], ssid, ssidLen);

  return (5 + ssidLen);
}

int getCurrBSSID(const uint8_t command[], uint8_t response[])
{
  uint8_t bssid[6];

  WiFi.BSSID(bssid);

  response[2] = 1; // number of parameters
  response[3] = 6; // parameter 1 length

  memcpy(&response[4], bssid, sizeof(bssid));

  return 11;
}

int getCurrRSSI(const uint8_t command[], uint8_t response[])
{
  int32_t rssi = WiFi.RSSI();

  response[2] = 1; // number of parameters
  response[3] = sizeof(rssi); // parameter 1 length

  memcpy(&response[4], &rssi, sizeof(rssi));

  return 9;
}

int getCurrEnct(const uint8_t command[], uint8_t response[])
{
  uint8_t encryptionType = WiFi.encryptionType();

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = encryptionType;

  return 6;
}

int scanNetworks(const uint8_t command[], uint8_t response[])
{
  int num = WiFi.scanNetworks();
  int responseLength = 3;

  response[2] = num;

  for (int i = 0; i < num; i++) {
    const char* ssid = WiFi.SSID(i);
    int ssidLen = strlen(ssid);

    response[responseLength++] = ssidLen;

    memcpy(&response[responseLength], ssid, ssidLen);
    responseLength += ssidLen;
  }

  return (responseLength + 1);
}

int startServerTcp(const uint8_t command[], uint8_t response[])
{
  uint32_t ip = 0;
  uint16_t port;
  uint8_t socket;
  uint8_t type;

  if (command[2] == 3) {
    memcpy(&port, &command[4], sizeof(port));
    port = ntohs(port);
    socket = command[7];
    type = command[9];
  } else {
    memcpy(&ip, &command[4], sizeof(ip));
    memcpy(&port, &command[9], sizeof(port));
    port = ntohs(port);
    socket = command[12];
    type = command[14];
  }

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length

  if (type == 0x00) {
    tcpServers[socket] = WiFiServer(port);

    tcpServers[socket].begin();

    socketTypes[socket] = 0x00;
    response[4] = 1;
  } else if (type == 0x01 && udps[socket].begin(port)) {
    socketTypes[socket] = 0x01;
    response[4] = 1;
  } else if (type == 0x03 && udps[socket].beginMulticast(ip, port)) {
    socketTypes[socket] = 0x01;
    response[4] = 1;
  } else {
    response[4] = 0;
  }

  return 6;
}

int getStateTcp(const uint8_t command[], uint8_t response[])
{
  uint8_t socket = command[4];

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length

  if (tcpServers[socket]) {
    response[4] = 1;
  } else {
    response[4] = 0;
  }

  return 6;
}

int dataSentTcp(const uint8_t command[], uint8_t response[])
{
  // -> no op as write does the work

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

int availDataTcp(const uint8_t command[], uint8_t response[])
{
  uint8_t socket = command[4];
  uint16_t available = 0;

  if (socketTypes[socket] == 0x00) {
    if (tcpServers[socket]) {
      WiFiClient client = tcpServers[socket].available();

      available = 255;

      if (client) {
        // try to find existing socket slot
        for (int i = 0; i < MAX_SOCKETS; i++) {
          if (i == socket) {
            continue; // skip this slot
          }

          if (socketTypes[i] == 0x00 && tcpClients[i] == client) {
            available = i;
            break;
          }
        }

        if (available == 255) {
          // book keep new slot

          for (int i = 0; i < MAX_SOCKETS; i++) {
            if (i == socket) {
              continue; // skip this slot
            }

            if (socketTypes[i] == 255) {
              socketTypes[i] = 0x00;
              tcpClients[i] = client;

              available = i;
              break;
            }
          }
        }
      }
    } else {
      available = tcpClients[socket].available();
    }
  } else if (socketTypes[socket] == 0x01) {
    available = udps[socket].available();

    if (available <= 0) {
      available = udps[socket].parsePacket();
    }
  } else if (socketTypes[socket] == 0x02) {
    available = tlsClients[socket].available();
  }

  response[2] = 1; // number of parameters
  response[3] = sizeof(available); // parameter 1 length

  memcpy(&response[4], &available, sizeof(available));

  return 7;
}

int getDataTcp(const uint8_t command[], uint8_t response[])
{
  uint8_t socket = command[4];
  uint8_t peek = command[6];

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length

  if (socketTypes[socket] == 0x00) {
    if (peek) {
      response[4] = tcpClients[socket].peek();
    } else {
      response[4] = tcpClients[socket].read();
    }
  } else if (socketTypes[socket] == 0x01) {
    if (peek) {
      response[4] = udps[socket].peek();
    } else {
      response[4] = udps[socket].read();
    }
  } else if (socketTypes[socket] == 0x02) {
    if (peek) {
      response[4] = tlsClients[socket].peek();
    } else {
      response[4] = tlsClients[socket].read();
    }
  }

  return 6;
}

int startClientTcp(const uint8_t command[], uint8_t response[])
{
  char host[255 + 1];
  uint32_t ip;
  uint16_t port;
  uint8_t socket;
  uint8_t type;

  memset(host, 0x00, sizeof(host));

  if (command[2] == 4) {
    memcpy(&ip, &command[4], sizeof(ip));
    memcpy(&port, &command[9], sizeof(port));
    port = ntohs(port);
    socket = command[12];
    type = command[14];
  } else {
    memcpy(host, &command[4], command[3]);
    memcpy(&ip, &command[5 + command[3]], sizeof(ip));
    memcpy(&port, &command[10 + command[3]], sizeof(port));
    port = ntohs(port);
    socket = command[13 + command[3]];
    type = command[15 + command[3]];
  }

  if (type == 0x00) {
    int result;

    if (host[0] != '\0') {
      result = tcpClients[socket].connect(host, port);
    } else {
      result = tcpClients[socket].connect(ip, port);
    }

    if (result) {
      socketTypes[socket] = 0x00;

      response[2] = 1; // number of parameters
      response[3] = 1; // parameter 1 length
      response[4] = 1;

      return 6;
    } else {
      response[2] = 0; // number of parameters

      return 4;
    }
  } else if (type == 0x01) {
    int result;

    if (host[0] != '\0') {
      result = udps[socket].beginPacket(host, port);
    } else {
      result = udps[socket].beginPacket(ip, port);
    }

    if (result) {
      socketTypes[socket] = 0x01;

      response[2] = 1; // number of parameters
      response[3] = 1; // parameter 1 length
      response[4] = 1;

      return 6;
    } else {
      response[2] = 0; // number of parameters

      return 4;
    }
  } else if (type == 0x02) {
    int result;

    if (host[0] != '\0') {
      result = tlsClients[socket].connect(host, port);
    } else {
      result = tlsClients[socket].connect(ip, port);
    }

    if (result) {
      socketTypes[socket] = 0x02;

      response[2] = 1; // number of parameters
      response[3] = 1; // parameter 1 length
      response[4] = 1;

      return 6;
    } else {
      response[2] = 0; // number of parameters

      return 4;
    }
  } else {
    response[2] = 0; // number of parameters

    return 4;
  }
}

int stopClientTcp(const uint8_t command[], uint8_t response[])
{
  uint8_t socket = command[4];

  if (socketTypes[socket] == 0x00) {
    tcpClients[socket].stop();

    socketTypes[socket] = 255;
  } else if (socketTypes[socket] == 0x01) {
    udps[socket].stop();

    socketTypes[socket] = 255;
  } else if (socketTypes[socket] == 0x02) {
    tlsClients[socket].stop();

    socketTypes[socket] = 255;
  }

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

int getClientStateTcp(const uint8_t command[], uint8_t response[])
{
  uint8_t socket = command[4];

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length

  if ((socketTypes[socket] == 0x00) && tcpClients[socket].connected()) {
    response[4] = 4;
  } else if ((socketTypes[socket] == 0x02) && tlsClients[socket].connected()) {
    response[4] = 4;
  } else {
    socketTypes[socket] = 255;
    response[4] = 0;
  }

  return 6;
}

int disconnect(const uint8_t command[], uint8_t response[])
{
  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  WiFi.disconnect();

  return 6;
}

int getIdxRSSI(const uint8_t command[], uint8_t response[])
{
  // RSSI
  int32_t rssi = WiFi.RSSI(command[4]);

  response[2] = 1; // number of parameters
  response[3] = sizeof(rssi); // parameter 1 length

  memcpy(&response[4], &rssi, sizeof(rssi));

  return 9;
}

int getIdxEnct(const uint8_t command[], uint8_t response[])
{
  uint8_t encryptionType = WiFi.encryptionType(command[4]);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = encryptionType;

  return 6;
}

int reqHostByName(const uint8_t command[], uint8_t response[])
{
  char host[255 + 1];

  memset(host, 0x00, sizeof(host));
  memcpy(host, &command[4], command[3]);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length

  resolvedHostname = /*IPAddress(255, 255, 255, 255)*/0xffffffff;
  if (WiFi.hostByName(host, resolvedHostname)) {
    response[4] = 1;
  } else {
    response[4] = 0;
  }

  return 6;
}

int getHostByName(const uint8_t command[], uint8_t response[])
{
  response[2] = 1; // number of parameters
  response[3] = 4; // parameter 1 length
  memcpy(&response[4], &resolvedHostname, sizeof(resolvedHostname));

  return 9;
}

int startScanNetworks(const uint8_t command[], uint8_t response[])
{
  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

int getFwVersion(const uint8_t command[], uint8_t response[])
{
  response[2] = 1; // number of parameters
  response[3] = sizeof(FIRMWARE_VERSION); // parameter 1 length

  memcpy(&response[4], FIRMWARE_VERSION, sizeof(FIRMWARE_VERSION));

  return 11;
}
int customCommand(const uint8_t command[], uint8_t response[])
{
  response[2] = 1; // number of parameters
  response[3] = sizeof(CUSTOMCIAO); // parameter 1 length

  memcpy(&response[4], CUSTOMCIAO, sizeof(CUSTOMCIAO));

  return 10;
}

int sendUDPdata(const uint8_t command[], uint8_t response[])
{
  uint8_t socket = command[4];

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length

  if (udps[socket].endPacket()) {
    response[4] = 1;
  } else {
    response[4] = 0;
  }

  return 6;
}

int getRemoteData(const uint8_t command[], uint8_t response[])
{
  uint8_t socket = command[4];

  /*IPAddress*/uint32_t ip = /*IPAddress(0, 0, 0, 0)*/0;
  uint16_t port = 0;

  if (socketTypes[socket] == 0x00) {
    ip = tcpClients[socket].remoteIP();
    port = tcpClients[socket].remotePort();
  } else if (socketTypes[socket] == 0x01) {
    ip = udps[socket].remoteIP();
    port = udps[socket].remotePort();
  } else if (socketTypes[socket] == 0x02) {
    ip = tlsClients[socket].remoteIP();
    port = tlsClients[socket].remotePort();
  }

  response[2] = 2; // number of parameters

  response[3] = 4; // parameter 1 length
  memcpy(&response[4], &ip, sizeof(ip));

  response[8] = 2; // parameter 2 length
  response[9] = (port >> 8) & 0xff;
  response[10] = (port >> 0) & 0xff;

  return 12;
}

int getTime(const uint8_t command[], uint8_t response[])
{
  unsigned long now = WiFi.getTime();

  response[2] = 1; // number of parameters
  response[3] = sizeof(now); // parameter 1 length

  memcpy(&response[4], &now, sizeof(now));

  return 5 + sizeof(now);
}

int getIdxBSSID(const uint8_t command[], uint8_t response[])
{
  uint8_t bssid[6];

  WiFi.BSSID(command[4], bssid);

  response[2] = 1; // number of parameters
  response[3] = 6; // parameter 1 length
  memcpy(&response[4], bssid, sizeof(bssid));

  return 11;
}

int getIdxChannel(const uint8_t command[], uint8_t response[])
{
  uint8_t channel = WiFi.channel(command[4]);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = channel;

  return 6;
}

int setEnt(const uint8_t command[], uint8_t response[])
{
  const uint8_t* commandPtr = &command[3];
  uint8_t eapType;
  char ssid[32 + 1];

  memset(ssid, 0x00, sizeof(ssid));

  // EAP Type - length
  uint16_t eapTypeLen = (commandPtr[0] << 8) | commandPtr[1];
  commandPtr += sizeof(eapTypeLen);

  // EAP Type - data
  memcpy(&eapType, commandPtr, sizeof(eapType));
  commandPtr += sizeof(eapType);

  // SSID - length
  uint16_t ssidLen = (commandPtr[0] << 8) | commandPtr[1];
  commandPtr += sizeof(ssidLen);

  // SSID - data
  memcpy(ssid, commandPtr, ssidLen);
  commandPtr += ssidLen;

  if (eapType == 0) {
    // PEAP/MSCHAPv2
    char username[128 + 1];
    char password[128 + 1];
    char identity[128 + 1];
    const char* rootCA;

    memset(username, 0x00, sizeof(username));
    memset(password, 0x00, sizeof(password));
    memset(identity, 0x00, sizeof(identity));

    // username - length
    uint16_t usernameLen = (commandPtr[0] << 8) | commandPtr[1];
    commandPtr += sizeof(usernameLen);

    // username - data
    memcpy(username, commandPtr, usernameLen);
    commandPtr += usernameLen;

    // password - length
    uint16_t passwordLen = (commandPtr[0] << 8) | commandPtr[1];
    commandPtr += sizeof(passwordLen);

    // password - data
    memcpy(password, commandPtr, passwordLen);
    commandPtr += passwordLen;

    // identity - length
    uint16_t identityLen = (commandPtr[0] << 8) | commandPtr[1];
    commandPtr += sizeof(identityLen);

    // identity - data
    memcpy(identity, commandPtr, identityLen);
    commandPtr += identityLen;

    // rootCA - length
    uint16_t rootCALen = (commandPtr[0] << 8) | commandPtr[1];
    memcpy(&rootCALen, commandPtr, sizeof(rootCALen));
    commandPtr += sizeof(rootCALen);

    // rootCA - data
    rootCA = (const char*)commandPtr;
    commandPtr += rootCALen;

    WiFi.beginEnterprise(ssid, username, password, identity, rootCA);
  } else {
    // EAP-TLS
    const char* cert;
    const char* key;
    char identity[128 + 1];
    const char* rootCA;

    memset(identity, 0x00, sizeof(identity));

    // cert - length
    uint16_t certLen = (commandPtr[0] << 8) | commandPtr[1];
    commandPtr += sizeof(certLen);

    // cert - data
    cert = (const char*)commandPtr;
    commandPtr += certLen;

    // key - length
    uint16_t keyLen = (commandPtr[0] << 8) | commandPtr[1];
    commandPtr += sizeof(keyLen);

    // key - data
    key = (const char*)commandPtr;
    commandPtr += keyLen;

    // identity - length
    uint16_t identityLen = (commandPtr[0] << 8) | commandPtr[1];
    commandPtr += sizeof(identityLen);

    // identity - data
    memcpy(identity, commandPtr, identityLen);
    commandPtr += identityLen;

    // rootCA - length
    uint16_t rootCALen = (commandPtr[0] << 8) | commandPtr[1];
    commandPtr += sizeof(rootCALen);

    // rootCA - data
    rootCA = (const char*)commandPtr;
    commandPtr += rootCALen;

    WiFi.beginEnterpriseTLS(ssid, cert, key, identity, rootCA);
  }

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

int sendDataTcp(const uint8_t command[], uint8_t response[])
{
  uint8_t socket;
  uint16_t length;
  uint16_t written = 0;

  socket = command[5];
  memcpy(&length, &command[6], sizeof(length));
  length = ntohs(length);

  if ((socketTypes[socket] == 0x00) && tcpServers[socket]) {
    written = tcpServers[socket].write(&command[8], length);
  } else if (socketTypes[socket] == 0x00) {
    written = tcpClients[socket].write(&command[8], length);
  } else if (socketTypes[socket] == 0x02) {
    written = tlsClients[socket].write(&command[8], length);
  }

  response[2] = 1; // number of parameters
  response[3] = sizeof(written); // parameter 1 length
  memcpy(&response[4], &written, sizeof(written));

  return 7;
}

int getDataBufTcp(const uint8_t command[], uint8_t response[])
{
  uint8_t socket;
  uint16_t length;
  int read = 0;

  socket = command[5];
  memcpy(&length, &command[8], sizeof(length));

  if (socketTypes[socket] == 0x00) {
    read = tcpClients[socket].read(&response[5], length);
  } else if (socketTypes[socket] == 0x01) {
    read = udps[socket].read(&response[5], length);
  } else if (socketTypes[socket] == 0x02) {
    read = tlsClients[socket].read(&response[5], length);
  }

  if (read < 0) {
    read = 0;
  }

  response[2] = 1; // number of parameters
  response[3] = (read >> 8) & 0xff; // parameter 1 length
  response[4] = (read >> 0) & 0xff;

  return (6 + read);
}

int insertDataBuf(const uint8_t command[], uint8_t response[])
{
  uint8_t socket;
  uint16_t length;

  socket = command[5];
  memcpy(&length, &command[6], sizeof(length));
  length = ntohs(length);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length

  if (udps[socket].write(&command[8], length) != 0) {
    response[4] = 1;
  } else {
    response[4] = 0;
  }

  return 6;
}

int ping(const uint8_t command[], uint8_t response[])
{
  uint32_t ip;
  uint8_t ttl;
  int16_t result;

  memcpy(&ip, &command[4], sizeof(ip));
  ttl = command[9];

  result = WiFi.ping(ip, ttl);

  response[2] = 1; // number of parameters
  response[3] = sizeof(result); // parameter 1 length
  memcpy(&response[4], &result, sizeof(result));

  return 7;
}

int getSocket(const uint8_t command[], uint8_t response[])
{
  uint8_t result = 255;

  for (int i = 0; i < MAX_SOCKETS; i++) {
    if (socketTypes[i] == 255) {
      result = i;
      break;
    }
  }

  response[2] = 1; // number of parameters
  response[3] = sizeof(result); // parameter 1 length
  response[4] = result;

  return 6;
}

int setPinMode(const uint8_t command[], uint8_t response[])
{
  uint8_t pin = command[4];
  uint8_t mode = command[6];

  pinMode(pin, mode);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

int setDigitalWrite(const uint8_t command[], uint8_t response[])
{
  uint8_t pin = command[4];
  uint8_t value = command[6];

  digitalWrite(pin, value);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

int setAnalogWrite(const uint8_t command[], uint8_t response[])
{
  uint8_t pin = command[4];
  uint8_t value = command[6];

  ledcWrite(pin, value);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}
/*
  Arduino IoT Cloud methods:
    IOT_BEGIN		= 0x60,
    IOT_UPDATE	= 0x61,
    IOT_ADD_PROPERTY	= 0x62,
    IOT_UPDATE_BOOL = 0x63,
    IOT_UPDATE_INT = 0x64,
    IOT_UPDATE_FLOAT = 0x65,
    IOT_UPDATE_STRING = 0x66,
    IOT_READ_BOOL = 0x67,
    IOT_READ_INT = 0x68,
    IOT_READ_FLOAT = 0x69,
    IOT_READ_STRING = 0x6A,
    IOT_SET_THING_ID = 0x6B,
    IOT_SET_BOARD_ID = 0x6C,
    IOT_SET_SECRET_KEY = 0x6D,

*/
int iotBegin(const uint8_t command[], uint8_t response[])
{


  memset(ssid, 0x00, sizeof(ssid));
  memset(pass, 0x00, sizeof(pass));
  memset(mqtt, 0x00, sizeof(mqtt));

  memcpy(ssid, &command[4], command[3]);
  memcpy(pass, &command[5 + command[3]], command[4 + command[3]]);
  uint8_t dim_first_param = command[3];
  uint8_t dim_second_param = command[4 + command[3]];
  memcpy(mqtt, &command[6 + dim_first_param + dim_second_param], command[5 + dim_first_param + dim_second_param]);
  /*Serial.print("ssid arrived: ");
  Serial.println(ssid);
  Serial.print("pass arrived: ");
  Serial.println(pass);
  Serial.print("mqtt arrived: ");
  Serial.println(mqtt);*/
  ArduinoIoTPreferredConnection = new WiFiConnectionHandler(ssid, pass);
  ArduinoCloud.begin(*ArduinoIoTPreferredConnection , mqtt);
    setDebugMessageLevel(2);
  ArduinoCloud.printDebugInfo();
  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

int iotUpdate(const uint8_t command[], uint8_t response[])
{
  ArduinoCloud.update();
  uint8_t iotStatus = (uint8_t)ArduinoCloud.getIoTStatus();
  uint8_t syncStatus = (uint8_t)ArduinoCloud.getIoTSyncStatus();
  uint8_t connStatus = (uint8_t)ArduinoIoTPreferredConnection->getStatus();

  response[2] = 3; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = iotStatus;
  response[5] = 1;
  response[6] = syncStatus;
  response[7] = 1;
  response[8] = connStatus;
  return 10;
}

int iotAddProperty(const uint8_t command[], uint8_t response[])
{
  uint8_t property_type;

  char name[32 + 1];

  uint8_t permission;
  long seconds;

  property_type = command[4];

  memset(name, 0x00, sizeof(name));
  memcpy(name, &command[6], command[5]);

  int start_pos = 6 + command[5];
  permission = command[start_pos + 1];
  memcpy(&seconds, &command[start_pos + 3], command[start_pos + 2]);
  //seconds = command[start_pos + 2];
  /*  Serial.print("property update name: ");
  Serial.println(name);
  Serial.print("property update permission: ");
  Serial.println(permission);
  Serial.println(command[start_pos]);
  Serial.print("property update seconds: ");
  Serial.println(seconds);*/

  switch (property_type) {
    case 1: {
      CloudBool *property_bool = new CloudBool();
      property_bool->init(String(name), (Permission)permission, NULL);
      _global_property_list.add(property_bool);
      ArduinoCloud.addPropertyReal(*property_bool, String(name), (permissionType)permission, seconds);
      }
      break;
    case 2: {
      CloudInt *property_int = new CloudInt();
      property_int->init(String(name), (Permission)permission, NULL);
      _global_property_list.add(property_int);
      ArduinoCloud.addPropertyReal(*property_int, String(name), (permissionType)permission, seconds);
      }
      break;
    case 3: {
      CloudFloat  * property_float = new CloudFloat();
      property_float->init(String(name), (Permission)permission, NULL);
      _global_property_list.add(property_float);
      ArduinoCloud.addPropertyReal(*property_float, String(name), (permissionType)permission, seconds);
      }
      break;
    case 4: {
      CloudString * property_string = new CloudString();
      property_string->init(String(name), (Permission)permission, NULL);
      _global_property_list.add(property_string);
      ArduinoCloud.addPropertyReal(*property_string, String(name), (permissionType)permission, seconds);
      }
      break;
  }

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}

ArduinoCloudProperty * getPropertyObj(String name){
  for(int i=0; i<_global_property_list.size(); i++){
    ArduinoCloudProperty *prop = _global_property_list.get(i);
    if(prop->name() == name){
      return prop;
    }
  }
  return NULL;
}

//0x63
int iotUpdateBool(const uint8_t command[], uint8_t response[])
{
  char propertyName[command[3]];

  memset(propertyName, 0x00, sizeof(propertyName));
  memcpy(propertyName, &command[4], command[3]);

  bool propertyValue;
  memcpy(&propertyValue, &command[5 + command[3]], command[4 + command[3]] );

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  CloudBool *prop = (CloudBool *)getPropertyObj(String(propertyName));

  if(prop){
    bool tmp = (bool) (*prop);
    if(tmp != propertyValue){
      /*Serial.print("bool diverso ho: ");
      Serial.print(tmp);
      Serial.print(" mi è arrivato: ");
      Serial.println(propertyValue);*/
      *prop = propertyValue;
    }
    response[4] = 1;
  }
  else{
    response[4] = 0;
  }

  return 6;
}
//0x64
int iotUpdateInt(const uint8_t command[], uint8_t response[])
{
  char propertyName[command[3]];

  memset(propertyName, 0x00, sizeof(propertyName));
  memcpy(propertyName, &command[4], command[3]);

  int propertyValue;
  memcpy(&propertyValue, &command[5 + command[3]], command[4 + command[3]] );

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  CloudInt *prop =  (CloudInt *)getPropertyObj(String(propertyName));

  if(prop){
    int tmp = (int) (*prop);
    if(tmp != propertyValue)
      *prop = propertyValue;
    response[4] = 1;
  }
  else{
    response[4] = 0;
  }

  return 6;
}



//0x65
int iotUpdateFloat(const uint8_t command[], uint8_t response[])
{
  char propertyName[command[3]];

  memset(propertyName, 0x00, sizeof(propertyName));
  memcpy(propertyName, &command[4], command[3]);

  float propertyValue;
  memcpy(&propertyValue, &command[5 + command[3]], command[4 + command[3]] );

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length

  CloudFloat *prop = (CloudFloat *)getPropertyObj(String(propertyName));

  if(prop){
    float tmp = (float)(*prop);
    if(tmp != propertyValue){
       /*Serial.print("float diverso ho: ");
      Serial.print(tmp);
      Serial.print(" mi è arrivato: ");
      Serial.println(propertyValue);*/
      *prop = propertyValue;
    }
    response[4] = 1;
  }
  else{
	//Serial.println("oggetto non trovato");
    response[4] = 0;
  }

  return 6;
}

//0x66
int iotUpdateString(const uint8_t command[], uint8_t response[])
{
  char propertyName[command[3]];

  memset(propertyName, 0x00, sizeof(propertyName));
  memcpy(propertyName, &command[4], command[3]);

  String propertyValue;
  char value[command[4 + command[3]]];
  memset(value,0x00,command[4 + command[3]]);
  memcpy(value, &command[5 + command[3]], command[4 + command[3]] );

  propertyValue = value;

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  CloudString *prop =  (CloudString *)getPropertyObj(String(propertyName));

  if(prop){
    String tmp = (String) *prop;
    if(tmp != propertyValue){
	  /*Serial.print("string diverso ho: ");
      Serial.print(tmp);
      Serial.print(" mi è arrivato: ");
      Serial.println(value);*/
      *prop = propertyValue;
    }
    response[4] = 1;
  }
  else{
    response[4] = 0;
  }

  return 6;
}

//0x67
int iotReadBool(const uint8_t command[], uint8_t response[])
{
  char propertyName[command[3]];

  memset(propertyName, 0x00, sizeof(propertyName));
  memcpy(propertyName, &command[4], command[3]);

  CloudBool *prop =  (CloudBool *)getPropertyObj(String(propertyName));
  //response[2] = 1; // number of parameters
  response[2] = 2;
  if(prop){
    bool val = (bool) (*prop);
    response[3] = sizeof(val); // parameter 1 length
    response[4] = val;
    unsigned long lastChangeTimestamp = prop->getLastCloudChangeTimestamp();
    response[5] = sizeof(lastChangeTimestamp);
    memcpy(&response[6], &lastChangeTimestamp, sizeof(lastChangeTimestamp));
    return 5 + sizeof(val) + 1 + sizeof(lastChangeTimestamp);
  }

  response[3] = 1;
  response[4] = 0;
  return 6;
}

//0x68
int iotReadInt(const uint8_t command[], uint8_t response[])
{
  char propertyName[command[3]];

  memset(propertyName, 0x00, sizeof(propertyName));
  memcpy(propertyName, &command[4], command[3]);

  CloudInt *prop =  (CloudInt *)getPropertyObj(String(propertyName));
  //response[2] = 1; // number of parameters
  response[2] = 2;
  if(prop){
    int val = (int) (*prop);
    response[3] = sizeof(val); // parameter 1 length
    memcpy(&response[4], &val, sizeof(val));
    unsigned long lastChangeTimestamp = prop->getLastCloudChangeTimestamp();
    response[5 + sizeof(val)] = sizeof(lastChangeTimestamp);
    memcpy(&response[6 + sizeof(val)], &lastChangeTimestamp, sizeof(lastChangeTimestamp));
    return 5 + sizeof(val) + 1 + sizeof(lastChangeTimestamp);
    //return 5 + sizeof(val);
  }

  response[3] = 1;
  response[4] = 0;
  return 6;
}

//0x69
int iotReadFloat(const uint8_t command[], uint8_t response[])
{
  char propertyName[command[3]];

  memset(propertyName, 0x00, sizeof(propertyName));
  memcpy(propertyName, &command[4], command[3]);

  CloudFloat *prop =  (CloudFloat *)getPropertyObj(String(propertyName));
  //response[2] = 1; // number of parameters
  response[2] = 2;
  if(prop){
    float val = (float) (*prop);
    response[3] = sizeof(val); // parameter 1 length
    memcpy(&response[4], &val, sizeof(val));
    unsigned long lastChangeTimestamp = prop->getLastCloudChangeTimestamp();
    response[5 + sizeof(val)] = sizeof(lastChangeTimestamp);
    memcpy(&response[6 + sizeof(val)], &lastChangeTimestamp, sizeof(lastChangeTimestamp));
    return 5 + sizeof(val) + 1 + sizeof(lastChangeTimestamp);
    //return 5 + sizeof(val);
  }

  response[3] = 1;
  response[4] = 0;
  return 6;
}

//0x6A
int iotReadString(const uint8_t command[], uint8_t response[])
{
  char propertyName[command[3]];

  memset(propertyName, 0x00, sizeof(propertyName));
  memcpy(propertyName, &command[4], command[3]);

  CloudString *prop =  (CloudString *)getPropertyObj(String(propertyName));
  //response[2] = 1; // number of parameters
  response[2] = 2;
  if(prop){

    String val = (String) (*prop);
    response[3] = (val.length() + 1); // parameter 1 length
    memcpy(&response[4], val.c_str(), (val.length() + 1));
    unsigned long lastChangeTimestamp = prop->getLastCloudChangeTimestamp();
    response[5 + val.length() + 1] = sizeof(lastChangeTimestamp);
    memcpy(&response[6 + val.length() + 1], &lastChangeTimestamp, sizeof(lastChangeTimestamp));
    return 5 + val.length() + 1 + 1 + sizeof(lastChangeTimestamp);
    //return 5 + (val.length() + 1);


  }else{
    //Serial.println("errore oggetto non trovato");
  }

  response[3] = 1;
  response[4] = 0;
  return 6;
}

//0x6B
int iotSetThingID(const uint8_t command[], uint8_t response[])
{

  memset(thingId, 0x00, sizeof(thingId));
  memcpy(thingId, &command[4], command[3]);
  /*Serial.print("thing id: ");
  Serial.println(thingId);*/
  ArduinoCloud.setThingId(thingId);

  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}
//0x6C
int iotSetBoardId(const uint8_t command[], uint8_t response[])
{
  char boardId[command[3]];

  memset(boardId, 0x00, sizeof(boardId));
  memcpy(boardId, &command[4], command[3]);
  /*Serial.print("board id: ");
  Serial.println(boardId);*/
  #ifdef BOARD_ESP
  ArduinoCloud.setBoardId(boardId);
  #endif
  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}
//0x6D
int iotSetSecretDeviceKey(const uint8_t command[], uint8_t response[])
{
  char boardSecret[command[3]];

  memset(boardSecret, 0x00, sizeof(boardSecret));
  memcpy(boardSecret, &command[4], command[3]);
  /*Serial.print("secret id: ");
  Serial.println(boardSecret);*/
  #ifdef BOARD_ESP
  ArduinoCloud.setSecretDeviceKey(boardSecret);
  #endif
  response[2] = 1; // number of parameters
  response[3] = 1; // parameter 1 length
  response[4] = 1;

  return 6;
}



typedef int (*CommandHandlerType)(const uint8_t command[], uint8_t response[]);

const CommandHandlerType commandHandlers[] = {
  // 0x00 -> 0x0f
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

  // 0x10 -> 0x1f
  setNet, setPassPhrase, setKey, NULL, setIPconfig, setDNSconfig, setHostname, setPowerMode, setApNet, setApPassPhrase, setDebug, getTemperature, NULL, NULL, NULL, getReasonCode,

  // 0x20 -> 0x2f
  getConnStatus, getIPaddr, getMACaddr, getCurrSSID, getCurrBSSID, getCurrRSSI, getCurrEnct, scanNetworks, startServerTcp, getStateTcp, dataSentTcp, availDataTcp, getDataTcp, startClientTcp, stopClientTcp, getClientStateTcp,

  // 0x30 -> 0x3f
  disconnect, NULL, getIdxRSSI, getIdxEnct, reqHostByName, getHostByName, startScanNetworks, getFwVersion, customCommand, sendUDPdata, getRemoteData, getTime, getIdxBSSID, getIdxChannel, ping, getSocket,

  // 0x40 -> 0x4f
  setEnt, NULL, NULL, NULL, sendDataTcp, getDataBufTcp, insertDataBuf, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

  // 0x50 -> 0x5f
  setPinMode, setDigitalWrite, setAnalogWrite, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

  // 0x60 -> 0x6f
  iotBegin, iotUpdate, iotAddProperty, iotUpdateBool, iotUpdateInt, iotUpdateFloat, iotUpdateString, iotReadBool, iotReadInt, iotReadFloat, iotReadString, iotSetThingID, iotSetBoardId, iotSetSecretDeviceKey, NULL, NULL,
};

#define NUM_COMMAND_HANDLERS (sizeof(commandHandlers) / sizeof(commandHandlers[0]))

CommandHandlerClass::CommandHandlerClass()
{
}

void CommandHandlerClass::begin()
{
  pinMode(0, OUTPUT);

  for (int i = 0; i < MAX_SOCKETS; i++) {
    socketTypes[i] = 255;
  }

  _updateGpio0PinSemaphore = xSemaphoreCreateCounting(2, 0);

  WiFi.onReceive(CommandHandlerClass::onWiFiReceive);
  WiFi.onDisconnect(CommandHandlerClass::onWiFiDisconnect);

  xTaskCreatePinnedToCore(CommandHandlerClass::gpio0Updater, "gpio0Updater", 8192, NULL, 1, NULL, 1);
}

int CommandHandlerClass::handle(const uint8_t command[], uint8_t response[])
{
  int responseLength = 0;

  if (command[0] == 0xe0 && command[1] < NUM_COMMAND_HANDLERS) {
    CommandHandlerType commandHandlerType = commandHandlers[command[1]];

    if (commandHandlerType) {
      responseLength = commandHandlerType(command, response);
    }
  }

  if (responseLength == 0) {
    response[0] = 0xef;
    response[1] = 0x00;
    response[2] = 0xee;

    responseLength = 3;
  } else {
    response[0] = 0xe0;
    response[1] = (0x80 | command[1]);
    response[responseLength - 1] = 0xee;
  }

  xSemaphoreGive(_updateGpio0PinSemaphore);

  return responseLength;
}

void CommandHandlerClass::gpio0Updater(void*)
{
  while (1) {
    CommandHandler.updateGpio0Pin();
  }
}

void CommandHandlerClass::updateGpio0Pin()
{
  xSemaphoreTake(_updateGpio0PinSemaphore, portMAX_DELAY);

  int available = 0;

  for (int i = 0; i < MAX_SOCKETS; i++) {
    if (socketTypes[i] == 0x00) {
      if (tcpServers[i] && tcpServers[i].available()) {
        available = 1;
        break;
      } else if (tcpClients[i] && tcpClients[i].connected() && tcpClients[i].available()) {
        available = 1;
        break;
      }
    }

    if (socketTypes[i] == 0x01 && udps[i] && (udps[i].available() || udps[i].parsePacket())) {
      available = 1;
      break;
    }

    if (socketTypes[i] == 0x02 && tlsClients[i] && tlsClients[i].connected() && tlsClients[i].available()) {
      available = 1;
      break;
    }
  }

  if (available) {
    digitalWrite(0, HIGH);
  } else {
    digitalWrite(0, LOW);
  }

  vTaskDelay(1);
}

void CommandHandlerClass::onWiFiReceive()
{
  CommandHandler.handleWiFiReceive();
}

void CommandHandlerClass::handleWiFiReceive()
{
  xSemaphoreGiveFromISR(_updateGpio0PinSemaphore, NULL);
}

void CommandHandlerClass::onWiFiDisconnect()
{
  CommandHandler.handleWiFiDisconnect();
}

void CommandHandlerClass::handleWiFiDisconnect()
{
  // workaround to stop lwip_connect hanging
  // close all non-listening sockets

  for (int i = 0; i < CONFIG_LWIP_MAX_SOCKETS; i++) {
    struct sockaddr_in addr;
    size_t addrLen = sizeof(addr);
    int socket = LWIP_SOCKET_OFFSET + i;

    if (lwip_getsockname(socket, (sockaddr*)&addr, &addrLen) < 0) {
      continue;
    }

    if (addr.sin_addr.s_addr != 0) {
      // non-listening socket, close
      close(socket);
    }
  }
}

CommandHandlerClass CommandHandler;
