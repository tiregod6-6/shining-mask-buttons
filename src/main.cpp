// ESP32-S3 -> 2x Shining Mask (full mask + glasses) over BLE, driven by 5 buttons.
//
// Protocol (from github.com/GoneUp/mask-go and github.com/shawnrancatore/shining-mask):
//   service      0000fff0-0000-1000-8000-00805f9b34fb
//   command char d44bc439-abfd-45a2-b575-925416129600  (write)
//   every command = 16 bytes: [len][ASCII cmd][args...] zero-padded, AES-128-ECB encrypted
//   e.g. 05 'I''M''A''G' nn   -> show built-in image nn
//        05 'A''N''I''M' nn   -> play built-in animation nn
//        06 'L''I''G''H''T' nn -> brightness
//        06 'P''L''A''Y' 01 nn -> play DIY slot nn (uploaded with the phone app)
//
// Library: NimBLE-Arduino 2.x (h2zero). AES comes from mbedtls, built into the ESP32 core.

#include <Arduino.h>
#include <NimBLEDevice.h>
#include "mbedtls/aes.h"

// ---------------------------------------------------------------- config ----

// Each device is picked by the start of its advertised name, e.g. "MASK-1A2B3C"
// and "GLASS-961DFF". Other gadgets nearby (e.g. barcode readers) reuse the
// generic fff0 service, so the name is the only reliable filter. Every other
// nearby device is printed once at scan time.
static const char* NAME_PREFIX[2] = {
  "MASK",    // [0] full mask
  "GLASS",   // [1] glasses
};

// Optional: pin a device by address instead (overrides the name match), useful
// if you own two of the same kind. The serial log prints each device's address.
static const char* MASK_ADDR[2] = {
  "",   // [0] full mask,   e.g. "aa:bb:cc:dd:ee:ff"
  "",   // [1] glasses
};

// Safe GPIOs on ESP32-S3 (avoid 0/3/45/46 strapping, 19/20 USB, 26-37 flash/PSRAM).
// Wire each button between the pin and GND (internal pull-up is used).
static const uint8_t BUTTON_PINS[5] = {4, 5, 6, 7, 15};

enum CmdType : uint8_t { IMAGE, ANIMATION, DIY, BRIGHTNESS };
struct Action { CmdType type; uint8_t value; };

// What each button does on each device. The glasses have a smaller screen, so their
// built-in image/animation numbers don't match the mask's. Adjust per device.
static const Action ACTIONS[2][5] = {
  // full mask
  { {ANIMATION, 1}, {ANIMATION, 2}, {ANIMATION, 3}, {IMAGE, 1}, {DIY, 1} },
  // glasses
  { {ANIMATION, 1}, {ANIMATION, 2}, {ANIMATION, 3}, {IMAGE, 1}, {DIY, 1} },
};

// ------------------------------------------------------------- protocol ----

static const NimBLEUUID SERVICE_UUID("0000fff0-0000-1000-8000-00805f9b34fb");
static const NimBLEUUID CMD_UUID("d44bc439-abfd-45a2-b575-925416129600");
static const uint8_t AES_KEY[16] = {0x32, 0x67, 0x2f, 0x79, 0x74, 0xad, 0x43, 0x45,
                                    0x1d, 0x9c, 0x6c, 0x89, 0x4a, 0x0e, 0x87, 0x64};

static mbedtls_aes_context aes;

// Connection state. Written from NimBLE callbacks (host task) and from loop().
enum MaskState : uint8_t { IDLE, CONNECTING, DISCOVER, READY };

struct Mask {
  const char* label;
  NimBLEAddress addr;
  std::string name;  // advertised name, for the log
  volatile bool known;
  volatile MaskState state;
  NimBLEClient* client;
  NimBLERemoteCharacteristic* cmd;
  uint32_t nextAttempt;
  bool dumped;  // GATT table already printed
  Mask(const char* l)
      : label(l), known(false), state(IDLE), client(nullptr), cmd(nullptr), nextAttempt(0), dumped(false) {}
  bool connected() { return state == READY && client->isConnected() && cmd; }
};
static Mask masks[2] = {Mask("mask"), Mask("glasses")};

static bool sendRaw(Mask& m, const char* name, const uint8_t* args, uint8_t argLen) {
  if (!m.connected()) return false;
  uint8_t plain[16] = {0}, enc[16];
  uint8_t nameLen = strlen(name);
  plain[0] = nameLen + argLen;  // length byte = command name + args
  memcpy(plain + 1, name, nameLen);
  memcpy(plain + 1 + nameLen, args, argLen);
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plain, enc);
  bool noRsp = m.cmd->canWriteNoResponse();
  return m.cmd->writeValue(enc, sizeof(enc), !noRsp);
}

static bool runAction(Mask& m, const Action& a) {
  switch (a.type) {
    case IMAGE:      return sendRaw(m, "IMAG", &a.value, 1);
    case ANIMATION:  return sendRaw(m, "ANIM", &a.value, 1);
    case BRIGHTNESS: return sendRaw(m, "LIGHT", &a.value, 1);
    case DIY: { uint8_t args[2] = {1, a.value}; return sendRaw(m, "PLAY", args, 2); }
  }
  return false;
}

// ------------------------------------------------------------ BLE setup ----
//
// Nothing here blocks for long, so buttons stay responsive while a mask is
// switched off: scanning runs in the background, connects are async, and only
// the short GATT discovery right after connecting runs inside loop().

static const uint32_t RETRY_MS = 3000;

static Mask* maskFor(NimBLEClient* c) {
  for (auto& m : masks)
    if (m.client == c) return &m;
  return nullptr;
}

class ClientCallbacks : public NimBLEClientCallbacks {
  void onConnect(NimBLEClient* c) override {
    if (Mask* m = maskFor(c)) m->state = DISCOVER;
  }
  void onConnectFail(NimBLEClient* c, int reason) override {
    if (Mask* m = maskFor(c)) {
      Serial.printf("[%s] connect failed (reason %d)\n", m->label, reason);
      m->state = IDLE;
    }
  }
  void onDisconnect(NimBLEClient* c, int reason) override {
    if (Mask* m = maskFor(c)) {
      Serial.printf("[%s] disconnected (reason %d)\n", m->label, reason);
      m->state = IDLE;
    }
  }
} clientCallbacks;

// Print each nearby non-matching device once (named or not), with the service
// UUIDs and manufacturer data it advertises, so unknown devices can be identified.
// Hold the device close to the ESP32: anything weaker than LOG_MIN_RSSI is skipped.
static const int LOG_MIN_RSSI = -70;

static void logOther(const NimBLEAdvertisedDevice* d) {
  if (d->getRSSI() < LOG_MIN_RSSI) return;
  static std::vector<NimBLEAddress> seen;
  for (auto& a : seen)
    if (a == d->getAddress()) return;
  if (seen.size() >= 64) seen.clear();
  seen.push_back(d->getAddress());

  Serial.printf("  other \"%s\" %s rssi %d", d->getName().c_str(), d->getAddress().toString().c_str(),
                d->getRSSI());
  for (int i = 0; i < d->getServiceUUIDCount(); i++)
    Serial.printf(" svc %s", d->getServiceUUID(i).toString().c_str());
  if (d->haveManufacturerData()) {
    Serial.print(" mfr");
    for (uint8_t b : d->getManufacturerData()) Serial.printf(" %02x", b);
  }
  Serial.println();
}

class ScanCallbacks : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* d) override {
    std::string name = d->getName();
    const NimBLEAddress& a = d->getAddress();
    for (int k = 0; k < 2; k++) {
      bool match = MASK_ADDR[k][0] ? strcasecmp(a.toString().c_str(), MASK_ADDR[k]) == 0
                                   : name.rfind(NAME_PREFIX[k], 0) == 0;
      if (!match) continue;
      if (masks[k].known) return;  // already have one
      masks[k].addr = a; masks[k].name = name; masks[k].known = true;
      Serial.printf("  found \"%s\" %s rssi %d -> %s\n", name.c_str(), a.toString().c_str(), d->getRSSI(),
                    masks[k].label);
      return;
    }
    logOther(d);
  }
} scanCallbacks;

// Print every service/characteristic the device exposes. Used to work out the
// protocol of devices that don't match the Shining Mask layout.
static void dumpGatt(Mask& m) {
  Serial.printf("[%s] GATT table of \"%s\" %s:\n", m.label, m.name.c_str(), m.addr.toString().c_str());
  for (NimBLERemoteService* svc : m.client->getServices(true)) {
    Serial.printf("  service %s\n", svc->getUUID().toString().c_str());
    for (NimBLERemoteCharacteristic* c : svc->getCharacteristics(true)) {
      Serial.printf("    char %s %s%s%s%s%s\n", c->getUUID().toString().c_str(),
                    c->canRead() ? " read" : "", c->canWrite() ? " write" : "",
                    c->canWriteNoResponse() ? " write-no-rsp" : "", c->canNotify() ? " notify" : "",
                    c->canIndicate() ? " indicate" : "");
    }
  }
}

static void finishConnect(Mask& m) {
  NimBLERemoteService* svc = m.client->getService(SERVICE_UUID);
  m.cmd = svc ? svc->getCharacteristic(CMD_UUID) : nullptr;

  if (!m.cmd) {
    Serial.printf("[%s] \"%s\" has no Shining Mask command characteristic\n", m.label, m.name.c_str());
    if (!m.dumped) { dumpGatt(m); m.dumped = true; }
    m.client->disconnect();
    m.state = IDLE;
    m.nextAttempt = millis() + 30000;  // don't hammer a device we can't drive
    return;
  }
  m.state = READY;
  Serial.printf("[%s] connected \"%s\" %s\n", m.label, m.name.c_str(), m.addr.toString().c_str());
}

static void serviceBle() {
  bool connecting = false, allKnown = true;
  for (auto& m : masks) {
    if (m.state == DISCOVER) finishConnect(m);
    if (m.state == CONNECTING) connecting = true;
    if (!m.known) allKnown = false;
  }

  // The controller handles one pending connection at a time.
  if (!connecting) {
    for (auto& m : masks) {
      if (!m.known || m.state != IDLE || (int32_t)(millis() - m.nextAttempt) < 0) continue;
      m.nextAttempt = millis() + RETRY_MS;
      m.cmd = nullptr;
      m.state = CONNECTING;
      if (!m.client->connect(m.addr, true, true)) m.state = IDLE;  // async
      return;
    }
  }

  // Connecting stops the scan, so restart it whenever we still need addresses.
  NimBLEScan* scan = NimBLEDevice::getScan();
  if (!allKnown && !connecting && !scan->isScanning()) {
    Serial.println("Scanning...");
    scan->start(5000, false, true);
  }
}

// --------------------------------------------------------------- buttons ----

static bool lastState[5];
static uint32_t lastChange[5];

static void handleButtons() {
  for (int b = 0; b < 5; b++) {
    bool pressed = digitalRead(BUTTON_PINS[b]) == LOW;
    if (pressed != lastState[b] && millis() - lastChange[b] > 40) {
      lastState[b] = pressed;
      lastChange[b] = millis();
      if (!pressed) continue;
      for (int k = 0; k < 2; k++) {
        bool ok = runAction(masks[k], ACTIONS[k][b]);
        Serial.printf("button %d -> %s: %s\n", b + 1, masks[k].label, ok ? "ok" : "not connected");
      }
    }
  }
}

// ------------------------------------------------------------ main loop ----

void setup() {
  Serial.begin(115200);
  for (int b = 0; b < 5; b++) pinMode(BUTTON_PINS[b], INPUT_PULLUP);

  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, AES_KEY, 128);

  NimBLEDevice::init("mask-remote");
  NimBLEDevice::setPower(9);  // dBm, max range

  NimBLEScan* scan = NimBLEDevice::getScan();
  scan->setScanCallbacks(&scanCallbacks, false);
  scan->setActiveScan(true);  // the "MASK-xxxx" name is in the scan response

  for (auto& m : masks) {
    m.client = NimBLEDevice::createClient();
    m.client->setClientCallbacks(&clientCallbacks, false);
    m.client->setConnectTimeout(4000);
  }
}

void loop() {
  handleButtons();
  serviceBle();
  delay(5);
}
