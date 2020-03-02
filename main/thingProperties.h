#include <ArduinoIoTCloud.h>
#include <Arduino_ConnectionHandler.h>


const char THING_ID[] = "a8cc2b5a-cdb3-434f-815b-9a89c510c1c4";
#define BOARD_ID "7c482e92-2bb7-48a5-a7c6-fa2de1f477ba"

const char SSID[]     = SECRET_SSID;    // Network SSID (name)
const char PASS[]     = SECRET_PASS;    // Network password (use for WPA, or use as key for WEP)

void onLightChange();
void onColoredLightChange();
void onDimmedLightChange();

CloudLight light;
CloudColoredLight coloredLight;
CloudDimmedLight dimmedLight;
CloudTemperature temperature;

void initProperties(){

  ArduinoCloud.setThingId(THING_ID);
  ArduinoCloud.setBoardId(BOARD_ID);
  ArduinoCloud.setSecretDeviceKey(SECRET_DEVICE_KEY);
  //ArduinoCloud.addProperty(light, READWRITE, ON_CHANGE, onLightChange);
  //ArduinoCloud.addProperty(coloredLight, READWRITE, ON_CHANGE, onColoredLightChange);
  //ArduinoCloud.addProperty(dimmedLight, READWRITE, ON_CHANGE, onDimmedLightChange);
  ArduinoCloud.addProperty(temperature, READ, ON_CHANGE, NULL);

}

WiFiConnectionHandler ArduinoIoTPreferredConnection(SSID, PASS);
