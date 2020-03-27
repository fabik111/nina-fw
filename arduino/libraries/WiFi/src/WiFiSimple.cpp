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

#include <errno.h>
#include <string.h>

#include <lwip/sockets.h>

#include "WiFi.h"

#include "WiFiSimple.h"


WiFiSimple::WiFiSimple() :
  WiFiSimple(-1)
{
}

WiFiSimple::WiFiSimple(int socket) :
  _socket(socket)
{
}

int WiFiSimple::connect(const char* host, uint16_t port)
{
  uint32_t address;

  if (!WiFi.hostByName(host, address)) {
    return 0;
  }

  return connect(address, port);
}

int WiFiSimple::connect(/*IPAddress*/uint32_t ip, uint16_t port)
{
  _socket = lwip_socket(AF_INET, SOCK_STREAM, 0);

  if (_socket < 0) {
    _socket = -1;
    return 0;
  }

  struct sockaddr_in addr;
  memset(&addr, 0x00, sizeof(addr));

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = (uint32_t)ip;
  addr.sin_port = htons(port);

  if (lwip_connect_r(_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    lwip_close_r(_socket);
    _socket = -1;
    return 0;
  }

  int nonBlocking = 1;
  lwip_ioctl_r(_socket, FIONBIO, &nonBlocking);
  //Serial.println("connection succed");
  return 1;
}

size_t WiFiSimple::write(uint8_t b)
{
  return write(&b, 1);
}

size_t WiFiSimple::write(const uint8_t *buf, size_t size)
{
  if (_socket == -1) {
    return 0;
  }
  /*Serial.print("message write: ");
  for(int i=0; i<size; i++){
    Serial.print(buf[i], HEX);
    Serial.print(" ");
  }
  Serial.println("");*/
  int result = lwip_send_r(_socket, (void*)buf, size, MSG_DONTWAIT);

  if (result < 0) {
    lwip_close_r(_socket);
    _socket = -1;
    Serial.println("after write close");
    return 0;
  }

  return result;
}

int WiFiSimple::available()
{
  if (_socket == -1) {
    Serial.println("_socket -1");
    return 0;
  }

  int result = 0;

  if (lwip_ioctl_r(_socket, FIONREAD, &result) < 0) {
    lwip_close_r(_socket);
    _socket = -1;
    Serial.println("lwip_ioctl_r si spacca");
    return 0;
  }

  return result;
}

int WiFiSimple::read()
{
  uint8_t b;

  if (read(&b, sizeof(b)) == -1) {
    return -1;
  }

  return b;
}

int WiFiSimple::read(uint8_t* buf, size_t size)
{
  if (!available()) {
    //Serial.println("not available");
    return -1;
  }

  int result = lwip_recv_r(_socket, buf, size, MSG_DONTWAIT);

  /*Serial.print("size richiesta: ");
  Serial.println(size);
  Serial.print("result ricevuta: ");
  Serial.println(result);
  Serial.print("read succed: ");
  for(int i=0; i<size; i++){
  Serial.print(buf[i], HEX);
  Serial.print(" ");
  }
  Serial.println();*/

  if (result <= 0 && errno != EWOULDBLOCK) {
    lwip_close_r(_socket);
    _socket = -1;
    Serial.println("result<0 and EWOULDBLOCK");
    return 0;
  }

  if (result == 0) {
    Serial.println("result zero");
    result = -1;
  }

  return result;
}

int WiFiSimple::peek()
{
  uint8_t b;
  Serial.println("peek called");
  if (recv(_socket, &b, sizeof(b), MSG_PEEK | MSG_DONTWAIT) <= 0) {
    if (errno != EWOULDBLOCK) {
      lwip_close_r(_socket);
      _socket = -1;
    }

    return -1;
  }

  return b;
}

void WiFiSimple::flush()
{
}

void WiFiSimple::stop()
{
  if (_socket != -1) {
    lwip_close_r(_socket);
    _socket = -1;
  }
}

uint8_t WiFiSimple::connected()
{
  if (_socket != -1) {
    // use peek to update socket state
    peek();
  }

  return (_socket != -1);
}

WiFiSimple::operator bool()
{
  return (_socket != -1);
}

bool WiFiSimple::operator==(const WiFiSimple &other) const
{
  return (_socket == other._socket);
}

/*IPAddress*/uint32_t WiFiSimple::remoteIP()
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof(addr);

  getpeername(_socket, (struct sockaddr*)&addr, &len);

  return ((struct sockaddr_in *)&addr)->sin_addr.s_addr;
}

uint16_t WiFiSimple::remotePort()
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof(addr);

  getpeername(_socket, (struct sockaddr*)&addr, &len);

  return ntohs(((struct sockaddr_in *)&addr)->sin_port);
}