#include <ArduinoIoTCloud.h>
#include <Arduino_ConnectionHandler.h>


const char THING_ID[] = "83a62d76-5338-4731-8b47-ac7180201a8a";

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
  //ArduinoCloud.addProperty(light, READWRITE, ON_CHANGE, onLightChange);
  //ArduinoCloud.addProperty(coloredLight, READWRITE, ON_CHANGE, onColoredLightChange);
  //ArduinoCloud.addProperty(dimmedLight, READWRITE, ON_CHANGE, onDimmedLightChange);
  ArduinoCloud.addProperty(temperature, READ, ON_CHANGE, NULL);

}

WiFiConnectionHandler ArduinoIoTPreferredConnection(SSID, PASS);
