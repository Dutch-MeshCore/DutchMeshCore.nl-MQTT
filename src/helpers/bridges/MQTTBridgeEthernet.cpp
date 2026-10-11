#if defined(WITH_MQTT_BRIDGE) && defined(ETHERNET_ENABLED)

#include "MQTTBridge.h"
#include "../MQTTMessageBuilder.h"
#include "../TxtDataHelpers.h"
#include "../net/BearTLSClient.h"
#include "../net/WSClient.h"

#include <Arduino.h>
#include <SPI.h>
#include <RAK13800_W5100S.h>
#include <PubSubClient.h>
#include <NTPClient.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>

// ---------------------------------------------------------------------------
// Hardware configuration (defaults: RAK13800 in the WisBlock IO slot of a RAK4631,
// same wiring as Meshtastic's rak4631_eth_gw). Override via build_flags.
// ---------------------------------------------------------------------------
#ifndef ETH_PIN_CS
#define ETH_PIN_CS 26        // WB_SPI_CS
#endif
#ifndef ETH_PIN_RESET
#define ETH_PIN_RESET 21     // WB_IO3
#endif
#ifndef ETH_PIN_POWER
#define ETH_PIN_POWER 34     // WB_IO2 (3V3_S rail enable)
#endif
#ifndef ETH_PIN_SCK
#define ETH_PIN_SCK 3        // WB_SPI_CLK
#endif
#ifndef ETH_PIN_MISO
#define ETH_PIN_MISO 29      // WB_SPI_MISO
#endif
#ifndef ETH_PIN_MOSI
#define ETH_PIN_MOSI 30      // WB_SPI_MOSI
#endif
#ifndef ETH_DHCP_TIMEOUT_MS
#define ETH_DHCP_TIMEOUT_MS 10000
#endif
#ifndef MQTT_ETH_MAX_ACTIVE_SLOTS
#define MQTT_ETH_MAX_ACTIVE_SLOTS 2   // W5100S has 4 sockets; each TLS slot needs ~19 KB RAM
#endif
#ifndef MQTT_ETH_BUFFER_SIZE
#define MQTT_ETH_BUFFER_SIZE 2304     // CONNECT with JWT, or PUBLISH with 2 KB JSON payload
#endif
#ifndef MQTT_TASK_STACK_WORDS
#define MQTT_TASK_STACK_WORDS 3072    // 12 KB: BearSSL handshake + Ed25519 JWT signing
#endif

#ifdef NRF52_PLATFORM
// The global SPI (SPIM3) is re-pinned to the LoRa radio; Ethernet gets its own SPIM2.
static SPIClass s_eth_spi(NRF_SPIM2, ETH_PIN_MISO, ETH_PIN_SCK, ETH_PIN_MOSI);
#else
static SPIClass& s_eth_spi = SPI;
#endif

// ---------------------------------------------------------------------------
// Shared state (written by the MQTT task, read by CLI/UI/AlertReporter)
// ---------------------------------------------------------------------------
enum NetState : uint8_t { NET_OFF, NET_STARTING, NET_UP, NET_NO_HW, NET_NO_LINK, NET_DHCP_FAILED };
enum NetReason : uint8_t { NET_REASON_NONE = 0, NET_REASON_NO_HW = 1, NET_REASON_NO_LINK = 2, NET_REASON_DHCP = 3 };

static MQTTBridge* s_instance = nullptr;
static volatile uint8_t s_net_state = NET_OFF;
static volatile uint8_t s_net_reason = NET_REASON_NONE;
static volatile unsigned long s_link_up_at = 0;     // millis() when IP acquired, 0 while down
static volatile unsigned long s_link_down_at = 0;   // millis() of last loss/failure
static uint8_t s_ip[4] = { 0, 0, 0, 0 };
static uint8_t s_mac[6];

static BearTrustAnchors s_anchors;

static EthernetUDP s_ntp_udp;
static NTPClient s_ntp_client(s_ntp_udp, "pool.ntp.org", 0, 60000);

// ---------------------------------------------------------------------------
// Wall clock: epoch base captured from NTP (or the RTC at boot), advanced by millis().
// Avoids touching an I2C RTC from the MQTT task.
// ---------------------------------------------------------------------------
static volatile uint32_t s_epoch_base = 0;
static volatile unsigned long s_epoch_millis = 0;
static const uint32_t MIN_VALID_EPOCH = 1735689600UL;  // 2025-01-01

static uint32_t netNow() {
  if (s_epoch_base == 0) return 0;
  return s_epoch_base + (uint32_t)((millis() - s_epoch_millis) / 1000UL);
}

static void setEpoch(uint32_t epoch) {
  s_epoch_millis = millis();
  s_epoch_base = epoch;
}

#ifdef NRF52_PLATFORM
// newlib's time() ends up here; MQTTMessageBuilder and JWTHelper use time(nullptr).
extern "C" int _gettimeofday(struct timeval* tv, void* tz) {
  (void)tz;
  if (tv) {
    tv->tv_sec = netNow();
    tv->tv_usec = 0;
  }
  return 0;
}
#endif

// ---------------------------------------------------------------------------
// Transport stack
// ---------------------------------------------------------------------------

// PubSubClient busy-waits on available(). The nRF52 FreeRTOS port has time slicing
// disabled, so yield whenever no data is ready to keep the mesh loop task running.
class YieldingClient : public Client {
public:
  void setInner(Client* inner) { _inner = inner; }
  int connect(IPAddress ip, uint16_t port) override { return _inner ? _inner->connect(ip, port) : 0; }
  int connect(const char* host, uint16_t port) override { return _inner ? _inner->connect(host, port) : 0; }
  size_t write(uint8_t b) override { return _inner ? _inner->write(b) : 0; }
  size_t write(const uint8_t* buf, size_t size) override { return _inner ? _inner->write(buf, size) : 0; }
  int available() override {
    int n = _inner ? _inner->available() : 0;
    if (n <= 0) yield();
    return n;
  }
  int read() override { return _inner ? _inner->read() : -1; }
  int read(uint8_t* buf, size_t size) override { return _inner ? _inner->read(buf, size) : -1; }
  int peek() override { return _inner ? _inner->peek() : -1; }
  void flush() override { if (_inner) _inner->flush(); }
  void stop() override { if (_inner) _inner->stop(); }
  uint8_t connected() override { return _inner ? _inner->connected() : 0; }
  operator bool() override { return connected(); }

private:
  Client* _inner = nullptr;
};

struct MQTTSlotTransport {
  EthernetClient tcp;
  BearTLSClient tls;
  WSClient ws;
  YieldingClient top;
  PubSubClient mqtt;

  MQTTSlotTransport() : tls(tcp) {}
};

// ---------------------------------------------------------------------------
// Static helpers / CLI accessors
// ---------------------------------------------------------------------------

static void applyEffectiveOrigin(const NodePrefs* prefs, char* dest, size_t dest_size) {
  if (!prefs || !dest || dest_size == 0) return;
  if (prefs->mqtt_origin[0] == '\0') {
    strncpy(dest, prefs->node_name, dest_size - 1);
  } else {
    strncpy(dest, prefs->mqtt_origin, dest_size - 1);
  }
  dest[dest_size - 1] = '\0';
  StrHelper::stripSurroundingQuotes(dest, dest_size);
}

void MQTTBridge::getEffectiveMqttOrigin(const NodePrefs* prefs, char* buf, size_t buf_size) {
  if (!buf || buf_size == 0) return;
  if (!prefs) {
    buf[0] = '\0';
    return;
  }
  applyEffectiveOrigin(prefs, buf, buf_size);
}

void MQTTBridge::refreshOriginFromPrefs() {
  applyEffectiveOrigin(_prefs, _origin, sizeof(_origin));
}

bool MQTTBridge::isConfigValid(const NodePrefs* prefs) {
  if (!prefs) return false;
  for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
    const char* preset_name = prefs->mqtt_slot_preset[i];
    if (preset_name[0] == '\0' || strcmp(preset_name, MQTT_PRESET_NONE) == 0) continue;
    if (strcmp(preset_name, MQTT_PRESET_CUSTOM) == 0) {
      if (prefs->mqtt_slot_host[i][0] != '\0' && prefs->mqtt_slot_port[i] != 0) return true;
    } else if (findMQTTPreset(preset_name) != nullptr) {
      return true;
    }
  }
  return false;
}

unsigned long MQTTBridge::getWifiConnectedAtMillis() { return s_link_up_at; }
uint8_t MQTTBridge::getLastWifiDisconnectReason() { return s_net_reason; }
unsigned long MQTTBridge::getLastWifiDisconnectTime() { return s_link_down_at; }

const char* MQTTBridge::wifiReasonStr(uint8_t reason) {
  switch (reason) {
    case NET_REASON_NO_HW:   return "no Ethernet module";
    case NET_REASON_NO_LINK: return "cable unplugged";
    case NET_REASON_DHCP:    return "DHCP failed";
    default:                 return nullptr;
  }
}

const char* MQTTBridge::tlsErrorStr(int32_t err) {
  return BearTLSClient::errorStr((int)err);
}

void MQTTBridge::getLocalIP(uint8_t ip[4]) {
  if (s_net_state == NET_UP) {
    memcpy(ip, s_ip, 4);
  } else {
    memset(ip, 0, 4);
  }
}

static void formatUptime(char* buf, size_t size, unsigned long ms) {
  unsigned long s = ms / 1000;
  unsigned long d = s / 86400, h = (s % 86400) / 3600, m = (s % 3600) / 60;
  if (d > 0) snprintf(buf, size, "%lud %luh %lum", d, h, m);
  else if (h > 0) snprintf(buf, size, "%luh %lum", h, m);
  else snprintf(buf, size, "%lum %lus", m, s % 60);
}

void MQTTBridge::formatNetStatusReply(char* buf, size_t bufsize) {
  if (!buf || bufsize == 0) return;
  switch (s_net_state) {
    case NET_UP: {
      char up[24];
      formatUptime(up, sizeof(up), millis() - s_link_up_at);
      snprintf(buf, bufsize, "> ethernet up, IP: %u.%u.%u.%u, MAC: %02X:%02X:%02X:%02X:%02X:%02X, uptime: %s",
               s_ip[0], s_ip[1], s_ip[2], s_ip[3],
               s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5], up);
      break;
    }
    case NET_STARTING:
      snprintf(buf, bufsize, "> ethernet starting (DHCP)");
      break;
    case NET_OFF:
      snprintf(buf, bufsize, "> ethernet off (bridge not running)");
      break;
    default: {
      const char* why = wifiReasonStr(s_net_reason);
      snprintf(buf, bufsize, "> ethernet down: %s", why ? why : "unknown");
      break;
    }
  }
}

void MQTTBridge::formatMqttStatusReply(char* buf, size_t bufsize, const NodePrefs* prefs) {
  if (buf == nullptr || bufsize == 0) return;
  const char* msgs = (prefs->mqtt_status_enabled) ? "on" : "off";
  if (s_instance == nullptr || !s_instance->_initialized) {
    snprintf(buf, bufsize, "> msgs: %s (bridge not running)", msgs);
    return;
  }
  MQTTBridge* b = s_instance;

  int pos = snprintf(buf, bufsize, "> msgs: %s", msgs);
  if (s_net_state != NET_UP) {
    pos += snprintf(buf + pos, bufsize - pos, ", eth: down");
  }
  for (int i = 0; i < RUNTIME_MQTT_SLOTS && pos < (int)bufsize - 1; i++) {
    const MQTTSlot& slot = b->_slots[i];
    const char* name = slot.preset ? slot.preset->name : "custom";
    const char* state;
    if (!slot.enabled && slot.preset) {
      state = "inactive";
    } else if (!slot.enabled) {
      continue;
    } else if (!b->isSlotReady(i)) {
      state = "wait";
    } else if (slot.connected) {
      state = "ok";
    } else if (slot.circuit_breaker_tripped) {
      state = "fail";
    } else {
      state = "disc";
    }
    pos += snprintf(buf + pos, bufsize - pos, ", %d: %s (%s)", i + 1, name, state);
  }
  snprintf(buf + pos, bufsize - pos, ", q:%d", b->_queue_count);
}

void MQTTBridge::formatSlotDiagReply(char* buf, size_t bufsize, int slot_index) {
  if (!buf || bufsize == 0) return;
  if (!s_instance || !s_instance->_initialized) {
    snprintf(buf, bufsize, "> mqtt%d: bridge not running", slot_index + 1);
    return;
  }
  if (slot_index < 0 || slot_index >= RUNTIME_MQTT_SLOTS) {
    snprintf(buf, bufsize, "> invalid slot");
    return;
  }
  const MQTTSlot& slot = s_instance->_slots[slot_index];
  if (!slot.enabled && !slot.preset && slot.host[0] == '\0') {
    snprintf(buf, bufsize, "> mqtt%d: not configured", slot_index + 1);
    return;
  }
  const char* state = !slot.enabled ? "inactive"
                    : slot.connected ? "ok"
                    : slot.circuit_breaker_tripped ? "fail" : "disc";
  int pos = snprintf(buf, bufsize, "> mqtt%d: %s", slot_index + 1, state);
  if (slot.disconnect_count > 0) {
    pos += snprintf(buf + pos, bufsize - pos, ", dc:%lu", (unsigned long)slot.disconnect_count);
  }
  if (slot.last_error_time == 0) {
    snprintf(buf + pos, bufsize - pos, slot.connected ? ", no errors" : ", no error info");
    return;
  }
  if (slot.last_tls_err != 0) {
    const char* desc = BearTLSClient::errorStr(slot.last_tls_err);
    if (desc) pos += snprintf(buf + pos, bufsize - pos, ", tls: %s", desc);
    else pos += snprintf(buf + pos, bufsize - pos, ", tls:%d", slot.last_tls_err);
  }
  if (slot.last_http_status != 0 && slot.last_http_status != 101) {
    pos += snprintf(buf + pos, bufsize - pos, ", ws http:%d", slot.last_http_status);
  }
  if (slot.last_mqtt_state != 0) {
    pos += snprintf(buf + pos, bufsize - pos, ", mqtt:%d", slot.last_mqtt_state);
  }
  unsigned long ago = (millis() - slot.last_error_time) / 1000;
  if (ago < 60) snprintf(buf + pos, bufsize - pos, ", %lus ago", ago);
  else if (ago < 3600) snprintf(buf + pos, bufsize - pos, ", %lum ago", ago / 60);
  else snprintf(buf + pos, bufsize - pos, ", %luh ago", ago / 3600);
}

unsigned long MQTTBridge::getSlotCurrentOutageStartMs(int slot_index) const {
  if (slot_index < 0 || slot_index >= RUNTIME_MQTT_SLOTS) return 0;
  return _slots[slot_index].current_outage_started_ms;
}

bool MQTTBridge::isSlotEnabledAndAttempted(int slot_index) const {
  if (slot_index < 0 || slot_index >= RUNTIME_MQTT_SLOTS) return false;
  return _slots[slot_index].enabled && _slots[slot_index].initial_connect_done;
}

const char* MQTTBridge::getSlotPresetName(int slot_index) const {
  if (slot_index < 0 || slot_index >= RUNTIME_MQTT_SLOTS) return "?";
  const MQTTSlot& s = _slots[slot_index];
  if (s.preset && s.preset->name) return s.preset->name;
  if (!s.enabled) return MQTT_PRESET_NONE;
  return MQTT_PRESET_CUSTOM;
}

// ---------------------------------------------------------------------------
// Construction / lifecycle
// ---------------------------------------------------------------------------

MQTTBridge::MQTTBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc, mesh::LocalIdentity *identity)
    : BridgeBase(prefs, mgr, rtc),
      _status_enabled(true), _packets_enabled(true), _raw_enabled(false),
      _last_status_publish(0), _last_status_retry(0), _status_interval(300000),
      _packet_queue(nullptr), _task_handle(nullptr), _reload_pending(false), _paused(false), _queue_count(0),
      _queue_disconnected_since(0),
      _staged_raw_len(0), _staged_snr(0), _staged_rssi(0), _staged_raw_valid(false),
      _ntp_synced(false), _last_ntp_sync(0), _last_ntp_attempt(0), _pending_rtc_epoch(0),
      _slots_setup_done(false), _max_active_slots(MQTT_ETH_MAX_ACTIVE_SLOTS),
      _timezone_utc(TimeChangeRule{"UTC", Last, Sun, Mar, 0, 0}, TimeChangeRule{"UTC", Last, Sun, Mar, 0, 0}),
      _identity(identity), _last_slot_connect_ms(0), _last_no_broker_log(0), _last_config_warning(0),
      _dispatcher(nullptr), _radio(nullptr), _board(nullptr), _ms(nullptr) {
  strcpy(_origin, "MeshCore-Repeater");
  strcpy(_iata, "XXX");
  strcpy(_device_id, "DEVICE_ID_PLACEHOLDER");
  strcpy(_firmware_version, "unknown");
  strcpy(_board_model, "unknown");
  strcpy(_build_date, "unknown");
  _jwt_username[0] = '\0';
  for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
    memset(&_slots[i], 0, sizeof(MQTTSlot));
    _slots[i].port = 1883;
    _slot_reconfigure_pending[i] = false;
  }
}

void MQTTBridge::loadSlotsFromPrefs() {
  for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
    MQTTSlot& slot = _slots[i];
    slot.enabled = false;
    slot.preset = nullptr;
    const char* preset_name = _prefs->mqtt_slot_preset[i];
    if (preset_name[0] == '\0' || strcmp(preset_name, MQTT_PRESET_NONE) == 0) continue;

    if (strcmp(preset_name, MQTT_PRESET_CUSTOM) == 0) {
      StrHelper::strncpy(slot.host, _prefs->mqtt_slot_host[i], sizeof(slot.host));
      if (slot.host[0] == '\0') {
        MQTT_DEBUG_PRINTLN("MQTT%d: custom preset has no server configured, disabling", i + 1);
        continue;
      }
      slot.port = _prefs->mqtt_slot_port[i];
      StrHelper::strncpy(slot.username, _prefs->mqtt_slot_username[i], sizeof(slot.username));
      StrHelper::strncpy(slot.password, _prefs->mqtt_slot_password[i], sizeof(slot.password));
      StrHelper::strncpy(slot.audience, _prefs->mqtt_slot_audience[i], sizeof(slot.audience));
      slot.enabled = true;
    } else {
      const MQTTPresetDef* preset = findMQTTPreset(preset_name);
      if (!preset) {
        MQTT_DEBUG_PRINTLN("MQTT%d: unknown preset '%s', disabling", i + 1, preset_name);
        continue;
      }
      slot.preset = preset;
      slot.enabled = true;
      if (mqttPresetNeedsSlotCredentials(preset)) {
        StrHelper::strncpy(slot.username, _prefs->mqtt_slot_username[i], sizeof(slot.username));
        StrHelper::strncpy(slot.password, _prefs->mqtt_slot_password[i], sizeof(slot.password));
      }
    }
  }
}

void MQTTBridge::begin() {
  if (_initialized) return;
  MQTT_DEBUG_PRINTLN("Initializing Ethernet MQTT bridge...");

  refreshOriginFromPrefs();
  StrHelper::strncpy(_iata, _prefs->mqtt_iata, sizeof(_iata));
  StrHelper::stripSurroundingQuotes(_iata, sizeof(_iata));
  for (int i = 0; _iata[i]; i++) _iata[i] = toupper(_iata[i]);

  _status_enabled = _prefs->mqtt_status_enabled;
  _packets_enabled = _prefs->mqtt_packets_enabled;
  _raw_enabled = _prefs->mqtt_raw_enabled;
  if (_prefs->mqtt_status_interval >= 1000 && _prefs->mqtt_status_interval <= 3600000) {
    _status_interval = _prefs->mqtt_status_interval;
  } else {
    _prefs->mqtt_status_interval = 300000;
    _status_interval = 300000;
  }

  // Seed the wall clock from the RTC (read here, on the mesh task) until NTP syncs.
  if (s_epoch_base == 0 && _rtc) {
    uint32_t rtc_now = _rtc->getCurrentTime();
    if (rtc_now >= MIN_VALID_EPOCH) setEpoch(rtc_now);
  }

  if (_identity && _jwt_username[0] == '\0') {
    char public_key_hex[65];
    mesh::Utils::toHex(public_key_hex, _identity->pub_key, PUB_KEY_SIZE);
    snprintf(_jwt_username, sizeof(_jwt_username), "v1_%s", public_key_hex);
  }

  if (_task_handle != nullptr) {
    // Restart (e.g. after a CLI setting change): the running task owns the slots and
    // the W5100S, so it reloads the configuration itself.
    _reload_pending = true;
    _initialized = true;
    s_instance = this;
    MQTT_DEBUG_PRINTLN("Ethernet MQTT bridge restarted");
    return;
  }

  loadSlotsFromPrefs();

  _packet_queue = xQueueCreate(MAX_QUEUE_SIZE, sizeof(QueuedPacket));
  if (!_packet_queue) {
    MQTT_DEBUG_PRINTLN("Failed to create packet queue");
    return;
  }

  for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
    if (!_slots[i].net) {
      _slots[i].net = new MQTTSlotTransport();
      _slots[i].net->mqtt.setBufferSize(MQTT_ETH_BUFFER_SIZE);
    }
  }

  _slots_setup_done = false;
  _initialized = true;
  s_instance = this;

  TaskHandle_t handle = nullptr;
  if (xTaskCreate(taskEntry, "mqtt_eth", MQTT_TASK_STACK_WORDS, this, TASK_PRIO_LOW, &handle) != pdPASS) {
    MQTT_DEBUG_PRINTLN("Failed to create MQTT task");
    _initialized = false;
    s_instance = nullptr;
    vQueueDelete((QueueHandle_t)_packet_queue);
    _packet_queue = nullptr;
    return;
  }
  _task_handle = handle;
  MQTT_DEBUG_PRINTLN("Ethernet MQTT bridge started");
}

void MQTTBridge::end() {
  if (!_initialized) return;
  // Non-blocking: the task notices, closes its MQTT sessions and idles. The task is
  // never deleted, since it may be in the middle of a W5100S/SPI transaction.
  _initialized = false;
  MQTT_DEBUG_PRINTLN("Ethernet MQTT bridge stopping");
}

void MQTTBridge::loop() {
  // Runs on the mesh loop task: the only place where the (possibly I2C) RTC is written.
  uint32_t epoch = _pending_rtc_epoch;
  if (epoch != 0 && _rtc) {
    _pending_rtc_epoch = 0;
    _rtc->setCurrentTime(netNow());
  }
}

// ---------------------------------------------------------------------------
// MQTT task
// ---------------------------------------------------------------------------

void MQTTBridge::taskEntry(void* param) {
  static_cast<MQTTBridge*>(param)->taskLoop();
}

void MQTTBridge::taskLoop() {
  ethernetInit();

  // Trust anchors: every distinct CA used by the built-in presets (also used for custom TLS slots).
  if (s_anchors.count() == 0) {
    for (int i = 0; i < MQTT_PRESET_COUNT; i++) {
      if (MQTT_PRESETS[i].ca_cert && !s_anchors.addPEM(MQTT_PRESETS[i].ca_cert)) {
        MQTT_DEBUG_PRINTLN("Failed to load CA for preset %s", MQTT_PRESETS[i].name);
      }
    }
    MQTT_DEBUG_PRINTLN("Loaded %u trust anchors", (unsigned)s_anchors.count());
  }

  while (true) {
    unsigned long now = millis();
    ethernetMaintain(now);

    if (_reload_pending) {
      _reload_pending = false;
      for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
        teardownSlot(i);
        _slot_reconfigure_pending[i] = false;
      }
      loadSlotsFromPrefs();
      _slots_setup_done = false;
      _last_status_publish = 0;
      _paused = false;
    }

    if (!_initialized) {
      if (!_paused) {
        for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) teardownSlot(i);
        xQueueReset((QueueHandle_t)_packet_queue);
        _queue_count = 0;
        _paused = true;
      }
      vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }

    if (isNetworkUp()) {
      bool want_ntp = !_ntp_synced ? (_last_ntp_attempt == 0 || now - _last_ntp_attempt >= 30000UL)
                                   : (now - _last_ntp_sync >= 3600000UL);
      if (want_ntp) syncTimeWithNTP();

      for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
        if (_slot_reconfigure_pending[i]) {
          _slot_reconfigure_pending[i] = false;
          applySlotPreset(i, _prefs->mqtt_slot_preset[i]);
        }
      }

      // Slot activation waits for a valid clock (JWT iat/exp and certificate validity).
      if (!_slots_setup_done && netNow() >= MIN_VALID_EPOCH) {
        _slots_setup_done = true;
        int active = 0;
        for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
          if (!_slots[i].enabled) continue;
          if (active >= _max_active_slots) {
            MQTT_DEBUG_PRINTLN("MQTT%d skipped: max active slots (%d) reached", i + 1, _max_active_slots);
            _slots[i].enabled = false;
            continue;
          }
          active++;
        }
      }

      if (_slots_setup_done) maintainSlots(now);
    }

    processPacketQueue();

    if (_status_enabled && anySlotConnected()) {
      bool due;
      if (_last_status_retry != 0) {
        due = (now - _last_status_retry) >= STATUS_RETRY_INTERVAL;
      } else {
        due = (_last_status_publish == 0) || (now - _last_status_publish) >= _status_interval;
      }
      if (due) {
        _last_status_retry = now;
        if (publishStatus()) {
          _last_status_publish = now;
          _last_status_retry = 0;
        }
      }
    } else {
      _last_status_retry = 0;
    }

    checkConfigurationMismatch();
    vTaskDelay(pdMS_TO_TICKS(_queue_count > 0 ? 5 : 20));
  }
}

// ---------------------------------------------------------------------------
// Ethernet (W5100S)
// ---------------------------------------------------------------------------

void MQTTBridge::ethernetInit() {
  s_net_state = NET_STARTING;

  // Same bring-up sequence as the RAK13800 examples / Meshtastic rak4631_eth_gw.
  pinMode(ETH_PIN_POWER, OUTPUT);
  digitalWrite(ETH_PIN_POWER, HIGH);
  delay(100);
  pinMode(ETH_PIN_RESET, OUTPUT);
  digitalWrite(ETH_PIN_RESET, LOW);
  delay(100);
  digitalWrite(ETH_PIN_RESET, HIGH);
  delay(100);

  s_eth_spi.begin();
  Ethernet.init(s_eth_spi, ETH_PIN_CS);

#ifdef NRF52_PLATFORM
  // Stable, locally administered unicast MAC derived from the chip's device address.
  const uint8_t* src = (const uint8_t*)NRF_FICR->DEVICEADDR;
  s_mac[0] = (uint8_t)((src[5] | 0xC2) & 0xFE);
  s_mac[1] = src[4];
  s_mac[2] = src[3];
  s_mac[3] = src[2];
  s_mac[4] = src[1];
  s_mac[5] = src[0];
#else
  const uint8_t def_mac[6] = { 0xC2, 0x4D, 0x43, 0x00, 0x00, 0x01 };
  memcpy(s_mac, def_mac, 6);
#endif
}

bool MQTTBridge::ethernetBegin() {
  s_net_state = NET_STARTING;
  MQTT_DEBUG_PRINTLN("Ethernet: starting DHCP...");
  if (Ethernet.begin(s_mac, ETH_DHCP_TIMEOUT_MS, 4000) == 0) {
    if (Ethernet.hardwareStatus() == EthernetNoHardware) {
      s_net_state = NET_NO_HW;
      s_net_reason = NET_REASON_NO_HW;
      MQTT_DEBUG_PRINTLN("Ethernet: W5100S not found (check RAK13800 / IO slot)");
    } else if (Ethernet.linkStatus() == LinkOFF) {
      s_net_state = NET_NO_LINK;
      s_net_reason = NET_REASON_NO_LINK;
      MQTT_DEBUG_PRINTLN("Ethernet: cable not connected");
    } else {
      s_net_state = NET_DHCP_FAILED;
      s_net_reason = NET_REASON_DHCP;
      MQTT_DEBUG_PRINTLN("Ethernet: DHCP failed");
    }
    s_link_up_at = 0;
    if (s_link_down_at == 0) s_link_down_at = millis();
    return false;
  }

  IPAddress ip = Ethernet.localIP();
  for (int i = 0; i < 4; i++) s_ip[i] = ip[i];
  s_net_reason = NET_REASON_NONE;
  s_link_up_at = millis();
  if (s_link_up_at == 0) s_link_up_at = 1;
  s_net_state = NET_UP;
  MQTT_DEBUG_PRINTLN("Ethernet up: IP %u.%u.%u.%u", s_ip[0], s_ip[1], s_ip[2], s_ip[3]);

  // Network (re)gained: let disconnected slots retry right away.
  for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
    _slots[i].last_reconnect_attempt = 0;
    _slots[i].reconnect_backoff = 0;
  }
  return true;
}

void MQTTBridge::ethernetMaintain(unsigned long now) {
  static unsigned long next_attempt = 0;
  static unsigned long last_link_check = 0;

  if (s_net_state != NET_UP) {
    if ((long)(now - next_attempt) < 0) return;
    if (s_net_state == NET_NO_LINK && Ethernet.linkStatus() != LinkON) {
      next_attempt = now + 2000;  // wait for the cable instead of running a doomed DHCP cycle
      return;
    }
    if (!ethernetBegin()) {
      next_attempt = millis() + (s_net_state == NET_NO_HW ? 60000UL : 10000UL);
    }
    return;
  }

  if (now - last_link_check < 2000) return;
  last_link_check = now;

  if (Ethernet.linkStatus() == LinkOFF) {
    MQTT_DEBUG_PRINTLN("Ethernet: link lost");
    s_net_state = NET_NO_LINK;
    s_net_reason = NET_REASON_NO_LINK;
    s_link_up_at = 0;
    s_link_down_at = now;
    for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
      if (_slots[i].connected) disconnectSlot(i, true);
    }
    next_attempt = now + 3000;
    return;
  }

  Ethernet.maintain();  // DHCP lease renewal
  IPAddress ip = Ethernet.localIP();
  if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) {
    MQTT_DEBUG_PRINTLN("Ethernet: DHCP lease lost");
    s_net_state = NET_DHCP_FAILED;
    s_net_reason = NET_REASON_DHCP;
    s_link_up_at = 0;
    s_link_down_at = now;
    for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
      if (_slots[i].connected) disconnectSlot(i, true);
    }
    next_attempt = now;
    return;
  }
  for (int i = 0; i < 4; i++) s_ip[i] = ip[i];
}

bool MQTTBridge::isNetworkUp() const {
  return s_net_state == NET_UP;
}

// ---------------------------------------------------------------------------
// NTP
// ---------------------------------------------------------------------------

void MQTTBridge::syncTimeWithNTP() {
  _last_ntp_attempt = millis();
  MQTT_DEBUG_PRINTLN("Syncing time with NTP...");

  bool ok = false;
  unsigned long epoch = 0;
  s_ntp_client.begin();
  for (int attempt = 0; attempt < 3 && !ok; attempt++) {
    if (attempt > 0) delay(1000);
    if (s_ntp_client.forceUpdate()) {
      epoch = s_ntp_client.getEpochTime();
      ok = epoch >= MIN_VALID_EPOCH;
    }
  }
  s_ntp_client.end();

  if (!ok) {
    MQTT_DEBUG_PRINTLN("NTP sync failed");
    return;
  }
  setEpoch(epoch);
  _ntp_synced = true;
  _last_ntp_sync = millis();
  _pending_rtc_epoch = epoch;  // RTC itself is updated from the mesh task (see loop())
  MQTT_DEBUG_PRINTLN("Time synced: %lu", epoch);
}

// ---------------------------------------------------------------------------
// Slot management
// ---------------------------------------------------------------------------

bool MQTTBridge::slotUsesJwt(int index) const {
  const MQTTSlot& slot = _slots[index];
  return (slot.preset && slot.preset->auth_type == MQTT_AUTH_JWT) ||
         (!slot.preset && slot.audience[0] != '\0');
}

bool MQTTBridge::resolveEndpoint(int index) {
  MQTTSlot& slot = _slots[index];
  char url[160];

  if (slot.preset) {
    StrHelper::strncpy(url, slot.preset->server_url, sizeof(url));
  } else if (strstr(slot.host, "://") != nullptr) {
    StrHelper::strncpy(url, slot.host, sizeof(url));
  } else {
    // Bare host: infer protocol from the port, like the ESP32 bridge.
    const char* proto = (slot.port == 8883) ? "mqtts" : (slot.port == 443) ? "wss" : "mqtt";
    snprintf(url, sizeof(url), "%s://%s:%u", proto, slot.host, (unsigned)slot.port);
  }

  const char* p = url;
  if (strncmp(p, "mqtts://", 8) == 0) { slot.scheme = SCHEME_MQTTS; p += 8; }
  else if (strncmp(p, "mqtt://", 7) == 0) { slot.scheme = SCHEME_MQTT; p += 7; }
  else if (strncmp(p, "wss://", 6) == 0) { slot.scheme = SCHEME_WSS; p += 6; }
  else if (strncmp(p, "ws://", 5) == 0) { slot.scheme = SCHEME_WS; p += 5; }
  else return false;

  const char* path = strchr(p, '/');
  const char* host_end = path ? path : p + strlen(p);
  const char* colon = (const char*)memchr(p, ':', host_end - p);
  const char* name_end = colon ? colon : host_end;
  size_t host_len = name_end - p;
  if (host_len == 0 || host_len >= sizeof(slot.ep_host)) return false;
  memcpy(slot.ep_host, p, host_len);
  slot.ep_host[host_len] = '\0';

  if (colon) {
    slot.ep_port = (uint16_t)atoi(colon + 1);
  } else if (!slot.preset && slot.port != 0) {
    slot.ep_port = slot.port;
  } else {
    static const uint16_t DEFAULT_PORTS[] = { 1883, 8883, 80, 443 };
    slot.ep_port = DEFAULT_PORTS[slot.scheme];
  }
  if (slot.ep_port == 0) return false;

  StrHelper::strncpy(slot.ep_path, path ? path : "/", sizeof(slot.ep_path));
  return true;
}

bool MQTTBridge::createSlotAuthToken(int index) {
  MQTTSlot& slot = _slots[index];
  if (!_identity) return false;

  const char* audience = nullptr;
  unsigned long base_lifetime = 86400;
  if (slot.preset && slot.preset->auth_type == MQTT_AUTH_JWT) {
    audience = slot.preset->jwt_audience;
    if (slot.preset->token_lifetime > 0) base_lifetime = slot.preset->token_lifetime;
  } else if (slot.audience[0] != '\0') {
    audience = slot.audience;
  }
  if (!audience || audience[0] == '\0') return false;

  const char* owner_key = nullptr;
  char owner_key_upper[65];
  if (_prefs->mqtt_owner_public_key[0] != '\0') {
    StrHelper::strncpy(owner_key_upper, _prefs->mqtt_owner_public_key, sizeof(owner_key_upper));
    for (int i = 0; owner_key_upper[i]; i++) owner_key_upper[i] = toupper(owner_key_upper[i]);
    owner_key = owner_key_upper;
  }
  char client_version[64];
  getClientVersion(client_version, sizeof(client_version));
  const char* email = (_prefs->mqtt_email[0] != '\0') ? _prefs->mqtt_email : nullptr;

  uint32_t now = netNow();
  if (now < MIN_VALID_EPOCH) return false;
  unsigned long stagger = index * min((unsigned long)300, base_lifetime / 20);
  unsigned long expires_in = base_lifetime - stagger;

  if (JWTHelper::createAuthToken(*_identity, audience, now, expires_in,
                                 slot.auth_token, AUTH_TOKEN_SIZE, owner_key, client_version, email)) {
    slot.token_expires_at = now + expires_in;
    return true;
  }
  slot.token_expires_at = 0;
  return false;
}

bool MQTTBridge::connectSlot(int index) {
  MQTTSlot& slot = _slots[index];
  MQTTSlotTransport* n = slot.net;
  if (!n) return false;

  slot.last_tls_err = 0;
  slot.last_http_status = 0;
  slot.last_mqtt_state = 0;

  if (!resolveEndpoint(index)) {
    MQTT_DEBUG_PRINTLN("MQTT%d: invalid broker URL", index + 1);
    slot.last_error_time = millis();
    slot.last_mqtt_state = MQTT_CONNECT_FAILED;
    return false;
  }

  bool use_tls = (slot.scheme == SCHEME_MQTTS || slot.scheme == SCHEME_WSS);
  bool use_ws = (slot.scheme == SCHEME_WS || slot.scheme == SCHEME_WSS);

  n->tcp.setConnectionTimeout(10000);
  Client* base = &n->tcp;
  if (use_tls) {
    n->tls.setTrustAnchors(&s_anchors);
    n->tls.setUnixTime(netNow());
    base = &n->tls;
  }
  Client* top = base;
  if (use_ws) {
    n->ws.setTransport(base);
    n->ws.setPath(slot.ep_path);
    top = &n->ws;
  }
  n->top.setInner(top);

  PubSubClient& m = n->mqtt;
  m.setClient(n->top);
  m.setServer(slot.ep_host, slot.ep_port);
  m.setKeepAlive((slot.preset && slot.preset->keepalive > 0) ? slot.preset->keepalive : 60);
  m.setSocketTimeout(15);

  const char* user = nullptr;
  const char* pass = nullptr;
  if (slotUsesJwt(index)) {
    if (!createSlotAuthToken(index)) {
      MQTT_DEBUG_PRINTLN("MQTT%d: JWT creation failed", index + 1);
      slot.last_error_time = millis();
      return false;
    }
    user = _jwt_username;
    pass = slot.auth_token;
  } else if (slot.preset && slot.preset->auth_type == MQTT_AUTH_USERPASS) {
    if (slot.preset->userpass_username && slot.preset->userpass_password) {
      user = slot.preset->userpass_username;
      pass = slot.preset->userpass_password;
    } else if (slot.username[0] != '\0') {
      user = slot.username;
      pass = slot.password;
    }
  } else if (!slot.preset && slot.username[0] != '\0') {
    user = slot.username;
    pass = slot.password;
  }

  char client_id[40];
  snprintf(client_id, sizeof(client_id), "meshcore_%.16s_%d", _device_id, index + 1);

  MQTT_DEBUG_PRINTLN("MQTT%d connecting to %s://%s:%u%s", index + 1,
                     slot.scheme == SCHEME_MQTT ? "mqtt" : slot.scheme == SCHEME_MQTTS ? "mqtts"
                     : slot.scheme == SCHEME_WS ? "ws" : "wss",
                     slot.ep_host, (unsigned)slot.ep_port, use_ws ? slot.ep_path : "");

  bool ok = m.connect(client_id, user, pass);
  if (!ok) {
    slot.last_mqtt_state = m.state();
    if (use_tls) slot.last_tls_err = n->tls.lastError();
    if (use_ws) slot.last_http_status = n->ws.lastHttpStatus();
    slot.last_error_time = millis();
    n->top.stop();
    MQTT_DEBUG_PRINTLN("MQTT%d connect failed: mqtt=%d tls=%d http=%d", index + 1,
                       slot.last_mqtt_state, slot.last_tls_err, slot.last_http_status);
    return false;
  }
  MQTT_DEBUG_PRINTLN("MQTT%d connected", index + 1);
  return true;
}

void MQTTBridge::disconnectSlot(int index, bool count_as_disconnect) {
  MQTTSlot& slot = _slots[index];
  if (slot.net) {
    if (slot.net->mqtt.connected()) slot.net->mqtt.disconnect();
    slot.net->top.stop();
  }
  if (slot.connected && count_as_disconnect) {
    unsigned long now = millis();
    slot.disconnect_count++;
    if (slot.first_disconnect_time == 0) slot.first_disconnect_time = now;
    if (slot.current_outage_started_ms == 0) slot.current_outage_started_ms = now;
  }
  slot.connected = false;
}

void MQTTBridge::teardownSlot(int index) {
  disconnectSlot(index, false);
  MQTTSlot& slot = _slots[index];
  slot.auth_token[0] = '\0';
  slot.token_expires_at = 0;
  slot.initial_connect_done = false;
  slot.reconnect_backoff = 0;
  slot.max_backoff_failures = 0;
  slot.circuit_breaker_tripped = false;
  slot.last_reconnect_attempt = 0;
  slot.current_outage_started_ms = 0;
}

void MQTTBridge::maintainSlots(unsigned long now) {
  static const unsigned long SLOT_BACKOFF_MS[] = { 10000, 30000, 60000, 120000, 300000 };
  static const uint8_t MAX_FAILURES_AT_MAX_BACKOFF = 3;
  static const unsigned long CIRCUIT_BREAKER_PROBE_MS = 1800000UL;
  static const unsigned long CONNECT_GUARD_MS = 5000UL;  // one handshake at a time

  for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
    MQTTSlot& slot = _slots[i];
    if (!slot.enabled || !slot.net) continue;

    if (slot.connected) {
      if (!slot.net->mqtt.loop()) {
        slot.last_mqtt_state = slot.net->mqtt.state();
        slot.last_error_time = now;
        MQTT_DEBUG_PRINTLN("MQTT%d connection lost (state %d)", i + 1, slot.last_mqtt_state);
        disconnectSlot(i, true);
        slot.last_reconnect_attempt = now;
      } else if (slotUsesJwt(i) && slot.token_expires_at != 0 && netNow() + 60 >= slot.token_expires_at) {
        // Reconnect with a fresh token shortly before the current one expires.
        MQTT_DEBUG_PRINTLN("MQTT%d token expiring, reconnecting", i + 1);
        disconnectSlot(i, false);
        slot.last_reconnect_attempt = 0;
        slot.reconnect_backoff = 0;
      }
      continue;
    }

    if (!isSlotReady(i)) continue;
    if (_last_slot_connect_ms != 0 && now - _last_slot_connect_ms < CONNECT_GUARD_MS) continue;

    if (slot.initial_connect_done && slot.last_reconnect_attempt != 0) {
      unsigned long elapsed = now - slot.last_reconnect_attempt;
      if (slot.circuit_breaker_tripped) {
        if (elapsed < CIRCUIT_BREAKER_PROBE_MS) continue;
      } else {
        unsigned int idx = slot.reconnect_backoff < 5 ? slot.reconnect_backoff : 4;
        if (elapsed < SLOT_BACKOFF_MS[idx] + i * 3000UL) continue;
      }
    }

    slot.initial_connect_done = true;
    slot.last_reconnect_attempt = now;
    _last_slot_connect_ms = now;

    if (connectSlot(i)) {
      slot.connected = true;
      slot.reconnect_backoff = 0;
      slot.max_backoff_failures = 0;
      slot.circuit_breaker_tripped = false;
      slot.last_error_time = 0;
      slot.current_outage_started_ms = 0;
      publishStatusToSlot(i);
    } else {
      if (slot.current_outage_started_ms == 0) slot.current_outage_started_ms = millis();
      if (slot.reconnect_backoff < 5) {
        slot.reconnect_backoff++;
      } else if (!slot.circuit_breaker_tripped && ++slot.max_backoff_failures >= MAX_FAILURES_AT_MAX_BACKOFF) {
        slot.circuit_breaker_tripped = true;
        MQTT_DEBUG_PRINTLN("MQTT%d circuit breaker tripped; probing every 30 min", i + 1);
      }
    }
    return;  // at most one (blocking) connect attempt per cycle
  }
}

void MQTTBridge::setSlotPreset(int slot_index, const char* preset_name) {
  if (slot_index < 0 || slot_index >= RUNTIME_MQTT_SLOTS) return;
  (void)preset_name;  // re-read from prefs by the MQTT task
  // Not running: the next begin() loads all slots from prefs anyway.
  if (_initialized && _task_handle != nullptr) {
    _slot_reconfigure_pending[slot_index] = true;
  }
}

void MQTTBridge::applySlotPreset(int slot_index, const char* preset_name) {
  MQTTSlot& slot = _slots[slot_index];
  teardownSlot(slot_index);
  slot.enabled = false;
  slot.preset = nullptr;

  if (preset_name[0] == '\0' || strcmp(preset_name, MQTT_PRESET_NONE) == 0) return;

  if (strcmp(preset_name, MQTT_PRESET_CUSTOM) == 0) {
    StrHelper::strncpy(slot.host, _prefs->mqtt_slot_host[slot_index], sizeof(slot.host));
    slot.port = _prefs->mqtt_slot_port[slot_index];
    StrHelper::strncpy(slot.username, _prefs->mqtt_slot_username[slot_index], sizeof(slot.username));
    StrHelper::strncpy(slot.password, _prefs->mqtt_slot_password[slot_index], sizeof(slot.password));
    StrHelper::strncpy(slot.audience, _prefs->mqtt_slot_audience[slot_index], sizeof(slot.audience));
    slot.enabled = slot.host[0] != '\0';
  } else {
    const MQTTPresetDef* preset = findMQTTPreset(preset_name);
    if (!preset) return;
    slot.preset = preset;
    slot.enabled = true;
    if (mqttPresetNeedsSlotCredentials(preset)) {
      StrHelper::strncpy(slot.username, _prefs->mqtt_slot_username[slot_index], sizeof(slot.username));
      StrHelper::strncpy(slot.password, _prefs->mqtt_slot_password[slot_index], sizeof(slot.password));
    }
  }

  // Respect the active-slot limit (sockets/RAM).
  if (slot.enabled) {
    int active = 0;
    for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
      if (i != slot_index && _slots[i].enabled) active++;
    }
    if (active >= _max_active_slots) {
      MQTT_DEBUG_PRINTLN("MQTT%d not activated: max active slots (%d) reached", slot_index + 1, _max_active_slots);
      slot.enabled = false;
    }
  }
}

void MQTTBridge::setSlotCustomBroker(int slot_index, const char* host, uint16_t port,
                                     const char* username, const char* password) {
  if (slot_index < 0 || slot_index >= RUNTIME_MQTT_SLOTS) return;
  MQTTSlot& slot = _slots[slot_index];
  StrHelper::strncpy(slot.host, host ? host : "", sizeof(slot.host));
  slot.port = port;
  StrHelper::strncpy(slot.username, username ? username : "", sizeof(slot.username));
  StrHelper::strncpy(slot.password, password ? password : "", sizeof(slot.password));
}

bool MQTTBridge::isIATAValid() const {
  return _iata[0] != '\0' && strcmp(_iata, "XXX") != 0;
}

bool MQTTBridge::isSlotReady(int index, char* reason_buf, size_t reason_size) const {
  if (index < 0 || index >= RUNTIME_MQTT_SLOTS) return false;
  const MQTTSlot& slot = _slots[index];
  if (!slot.enabled) return true;

  if (slot.preset) {
    if (slot.preset->topic_style == MQTT_TOPIC_MESHRANK) {
      if (_prefs->mqtt_slot_token[index][0] == '\0') {
        if (reason_buf) snprintf(reason_buf, reason_size, "set mqtt%d.token <your_token>", index + 1);
        return false;
      }
    } else if (!isIATAValid()) {
      if (reason_buf) snprintf(reason_buf, reason_size, "set mqtt.iata <airport_code>");
      return false;
    }
    if (mqttPresetNeedsSlotCredentials(slot.preset)) {
      if (_prefs->mqtt_slot_username[index][0] == '\0' || _prefs->mqtt_slot_password[index][0] == '\0') {
        if (reason_buf) snprintf(reason_buf, reason_size, "set mqtt%d.username/password", index + 1);
        return false;
      }
    }
  } else if (_prefs->mqtt_slot_topic[index][0] == '\0' && !isIATAValid()) {
    if (reason_buf) snprintf(reason_buf, reason_size, "set mqtt.iata <airport_code> or set mqtt%d.topic <template>", index + 1);
    return false;
  }
  return true;
}

bool MQTTBridge::anySlotConnected() const {
  for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
    if (_slots[i].enabled && _slots[i].connected) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Topics
// ---------------------------------------------------------------------------

bool MQTTBridge::substituteTopicTemplate(const char* tmpl, MQTTMessageType type, int slot_index, char* buf, size_t buf_size) {
  const char* type_str = (type == MSG_STATUS) ? "status" : (type == MSG_PACKETS) ? "packets" : "raw";
  const char* token = _prefs->mqtt_slot_token[slot_index];
  struct { const char* key; const char* value; } vars[] = {
    { "{iata}", _iata }, { "{device}", _device_id }, { "{token}", token }, { "{type}", type_str },
  };

  size_t out = 0;
  const char* p = tmpl;
  while (*p && out < buf_size - 1) {
    bool replaced = false;
    if (*p == '{') {
      for (size_t v = 0; v < sizeof(vars) / sizeof(vars[0]); v++) {
        size_t klen = strlen(vars[v].key);
        if (strncmp(p, vars[v].key, klen) == 0) {
          size_t vlen = strlen(vars[v].value);
          if (out + vlen >= buf_size) return false;
          memcpy(buf + out, vars[v].value, vlen);
          out += vlen;
          p += klen;
          replaced = true;
          break;
        }
      }
    }
    if (!replaced) buf[out++] = *p++;
  }
  buf[out] = '\0';
  return out > 0;
}

bool MQTTBridge::buildTopicForSlot(int index, MQTTMessageType type, char* topic_buf, size_t buf_size) {
  if (index < 0 || index >= RUNTIME_MQTT_SLOTS) return false;
  const MQTTSlot& slot = _slots[index];
  const char* type_str = (type == MSG_STATUS) ? "status" : (type == MSG_PACKETS) ? "packets" : "raw";

  if (slot.preset) {
    if (slot.preset->topic_style == MQTT_TOPIC_MESHRANK) {
      if (type != MSG_PACKETS) return false;
      const char* token = _prefs->mqtt_slot_token[index];
      if (token[0] == '\0') return false;
      snprintf(topic_buf, buf_size, "meshrank/uplink/%s/%s/packets", token, _device_id);
      return true;
    }
  } else if (_prefs->mqtt_slot_topic[index][0] != '\0') {
    return substituteTopicTemplate(_prefs->mqtt_slot_topic[index], type, index, topic_buf, buf_size);
  }
  if (!isIATAValid()) return false;
  snprintf(topic_buf, buf_size, "meshcore/%s/%s/%s", _iata, _device_id, type_str);
  return true;
}

// ---------------------------------------------------------------------------
// Publishing
// ---------------------------------------------------------------------------

bool MQTTBridge::publishToSlot(int index, const char* topic, const char* payload, bool retained) {
  MQTTSlot& slot = _slots[index];
  if (!slot.net || !slot.connected) return false;
  // QoS 0 only (PubSubClient); the transport is TCP so loss only happens on disconnect.
  return slot.net->mqtt.publish(topic, payload, retained);
}

int MQTTBridge::buildStatusJson() {
  refreshOriginFromPrefs();

  char timestamp[40];
  MQTTMessageBuilder::formatIsoTimestampForMqtt(netNow(), &_timezone_utc, timestamp, sizeof(timestamp));
  char radio_info[64];
  snprintf(radio_info, sizeof(radio_info), "%.6f,%.1f,%d,%d", _prefs->freq, _prefs->bw, _prefs->sf, _prefs->cr);
  char client_version[64];
  getClientVersion(client_version, sizeof(client_version));

  int battery_mv = _board ? _board->getBattMilliVolts() : -1;
  int uptime_secs = _ms ? (int)(_ms->getMillis() / 1000) : -1;
  int errors = -1, tx_air_secs = -1, rx_air_secs = -1, packets_sent = -1, packets_received = -1;
  if (_dispatcher) {
    errors = _dispatcher->getErrFlags();
    tx_air_secs = _dispatcher->getTotalAirTime() / 1000;
    rx_air_secs = _dispatcher->getReceiveAirTime() / 1000;
    packets_sent = (int)(_dispatcher->getNumSentFlood() + _dispatcher->getNumSentDirect());
    packets_received = (int)(_dispatcher->getNumRecvFlood() + _dispatcher->getNumRecvDirect());
  }
  int noise_floor = _radio ? (int16_t)_radio->getNoiseFloor() : -999;
  int recv_errors = _radio ? (int)_radio->getPacketsRecvErrors() : -1;
#ifdef NRF52_PLATFORM
  int heap_free = dbgHeapTotal() - dbgHeapUsed();
#else
  int heap_free = -1;
#endif

  return MQTTMessageBuilder::buildStatusMessage(
    _status_json_doc,
    _origin, _device_id, _board_model, _firmware_version, radio_info,
    client_version, "online", timestamp, _status_json_buffer, STATUS_JSON_BUFFER_SIZE,
    battery_mv, uptime_secs, errors, _queue_count, noise_floor,
    tx_air_secs, rx_air_secs, recv_errors, heap_free,
    packets_sent, packets_received,
    _prefs->disable_fwd ? "off" : "on");
}

void MQTTBridge::publishStatusToSlot(int index) {
  if (!_status_enabled || !_slots[index].connected) return;
  char topic[128];
  if (!buildTopicForSlot(index, MSG_STATUS, topic, sizeof(topic))) return;
  if (buildStatusJson() <= 0) return;
  bool retain = _slots[index].preset ? _slots[index].preset->allow_retain : false;
  if (!publishToSlot(index, topic, _status_json_buffer, retain)) {
    MQTT_DEBUG_PRINTLN("MQTT%d status publish failed", index + 1);
  }
}

bool MQTTBridge::publishStatus() {
  if (buildStatusJson() <= 0) return false;
  bool published = false;
  bool any_wants_status = false;
  char topic[128];
  for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
    if (!_slots[i].enabled || !_slots[i].connected) continue;
    if (!buildTopicForSlot(i, MSG_STATUS, topic, sizeof(topic))) continue;
    any_wants_status = true;
    bool retain = _slots[i].preset ? _slots[i].preset->allow_retain : false;
    if (publishToSlot(i, topic, _status_json_buffer, retain)) published = true;
  }
  return published || !any_wants_status;
}

bool MQTTBridge::publishPacket(QueuedPacket& queued) {
  refreshOriginFromPrefs();
  mesh::Packet* packet = &queued.packet_copy;
  int len;

  if (queued.has_raw_data && queued.raw_len > 0) {
    float score = (_radio && !queued.is_tx) ? _radio->packetScore(queued.snr, queued.raw_len) : NAN;
    len = MQTTMessageBuilder::buildPacketJSONFromRaw(
      _packet_json_doc, queued.raw_data, queued.raw_len, packet, queued.is_tx, _origin, _device_id,
      queued.snr, queued.rssi, score, &_timezone_utc, _publish_json_buffer, PUBLISH_JSON_BUFFER_SIZE);
  } else {
    uint8_t reconstructed[256];
    uint8_t rlen = packet->writeTo(reconstructed);
    if (rlen > 0) {
      float score = (_radio && !queued.is_tx) ? _radio->packetScore(queued.snr, rlen) : NAN;
      len = MQTTMessageBuilder::buildPacketJSONFromRaw(
        _packet_json_doc, reconstructed, rlen, packet, queued.is_tx, _origin, _device_id,
        queued.snr, queued.rssi, score, &_timezone_utc, _publish_json_buffer, PUBLISH_JSON_BUFFER_SIZE);
    } else {
      len = MQTTMessageBuilder::buildPacketJSON(
        _packet_json_doc, packet, queued.is_tx, _origin, _device_id, &_timezone_utc,
        _publish_json_buffer, PUBLISH_JSON_BUFFER_SIZE);
    }
  }
  if (len <= 0) return false;

  bool published = false;
  char topic[128];
  for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
    if (!_slots[i].enabled || !_slots[i].connected) continue;
    if (buildTopicForSlot(i, MSG_PACKETS, topic, sizeof(topic)) &&
        publishToSlot(i, topic, _publish_json_buffer, false)) {
      published = true;
    }
  }
  return published;
}

bool MQTTBridge::publishRaw(mesh::Packet* packet) {
  refreshOriginFromPrefs();
  int len = MQTTMessageBuilder::buildRawJSON(packet, _origin, _device_id, &_timezone_utc,
                                             _publish_json_buffer, PUBLISH_JSON_BUFFER_SIZE);
  if (len <= 0) return false;

  bool published = false;
  char topic[128];
  for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
    if (!_slots[i].enabled || !_slots[i].connected) continue;
    if (buildTopicForSlot(i, MSG_RAW, topic, sizeof(topic)) &&
        publishToSlot(i, topic, _publish_json_buffer, false)) {
      published = true;
    }
  }
  return published;
}

void MQTTBridge::processPacketQueue() {
  QueueHandle_t q = (QueueHandle_t)_packet_queue;
  if (!q) return;
  _queue_count = uxQueueMessagesWaiting(q);
  if (_queue_count == 0) {
    _queue_disconnected_since = 0;
    return;
  }

  unsigned long now = millis();
  if (!anySlotConnected()) {
    if (now - _last_no_broker_log > 30000UL) {
      MQTT_DEBUG_PRINTLN("Queue has %d packets but no slots connected", _queue_count);
      _last_no_broker_log = now;
    }
    if (_queue_disconnected_since == 0) {
      _queue_disconnected_since = now;
    } else if (now - _queue_disconnected_since >= QUEUE_STALE_MS) {
      xQueueReset(q);
      _queue_count = 0;
      _queue_disconnected_since = now;
      MQTT_DEBUG_PRINTLN("Flushed stale packet queue");
    }
    return;
  }
  _queue_disconnected_since = 0;

  static const uint8_t MAX_RETRY_ATTEMPTS = 3;
  int max_per_loop = (_queue_count > 5) ? 5 : 1;
  for (int processed = 0; processed < max_per_loop; processed++) {
    static QueuedPacket queued;  // ~550 bytes: keep it off the task stack (task-local use only)
    if (xQueueReceive(q, &queued, 0) != pdTRUE) break;

    bool ok = publishPacket(queued);
    if (_raw_enabled && publishRaw(&queued.packet_copy)) ok = true;

    if (!ok && queued.retry_attempts < MAX_RETRY_ATTEMPTS && anySlotConnected()) {
      queued.retry_attempts++;
      xQueueSendToFront(q, &queued, 0);
      break;
    }
  }
  _queue_count = uxQueueMessagesWaiting(q);
}

// ---------------------------------------------------------------------------
// Packet intake (mesh loop task)
// ---------------------------------------------------------------------------

void MQTTBridge::onPacketReceived(mesh::Packet *packet) {
  if (!_initialized || !_prefs->mqtt_packets_enabled || !_prefs->mqtt_rx_enabled) {
    _staged_raw_valid = false;
    return;
  }
  queuePacket(packet, false);
}

void MQTTBridge::sendPacket(mesh::Packet *packet) {
  uint8_t tx_mode = _prefs->mqtt_tx_enabled;
  if (!_initialized || !_prefs->mqtt_packets_enabled || tx_mode == 0) return;
  if (tx_mode == 2) {
    // Advert mode: only our own adverts
    if (packet->getPayloadType() != PAYLOAD_TYPE_ADVERT || packet->payload_len < PUB_KEY_SIZE) return;
    if (!_identity || memcmp(_identity->pub_key, packet->payload, PUB_KEY_SIZE) != 0) return;
  }
  queuePacket(packet, true);
}

void MQTTBridge::queuePacket(mesh::Packet* packet, bool is_tx) {
  QueueHandle_t q = (QueueHandle_t)_packet_queue;
  if (!q) return;

  static QueuedPacket queued;  // mesh loop task only; avoids ~550 bytes on its stack
  memset(&queued, 0, sizeof(queued));
  queued.packet_copy = *packet;  // value copy: the dispatcher frees the packet after logRx()
  queued.timestamp = millis();
  queued.is_tx = is_tx;

  if (!is_tx && _staged_raw_valid) {
    if (_staged_raw_len <= (int)sizeof(queued.raw_data)) {
      memcpy(queued.raw_data, _staged_raw, _staged_raw_len);
      queued.raw_len = (uint8_t)_staged_raw_len;
      queued.has_raw_data = true;
    }
    queued.snr = _staged_snr;
    queued.rssi = _staged_rssi;
    _staged_raw_valid = false;
  } else if (is_tx) {
    uint8_t tx_len = packet->writeTo(queued.raw_data);
    if (tx_len > 0) {
      queued.raw_len = tx_len;
      queued.has_raw_data = true;
    }
  }

  if (xQueueSend(q, &queued, 0) != pdTRUE) {
    static QueuedPacket dropped;
    xQueueReceive(q, &dropped, 0);  // drop the oldest
    xQueueSend(q, &queued, 0);
  }
  _queue_count = uxQueueMessagesWaiting(q);
}

void MQTTBridge::storeRawRadioData(const uint8_t* raw_data, int len, float snr, float rssi) {
  if (len > 0 && len <= (int)sizeof(_staged_raw)) {
    memcpy(_staged_raw, raw_data, len);
    _staged_raw_len = len;
    _staged_snr = snr;
    _staged_rssi = rssi;
    _staged_raw_valid = true;
  }
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

void MQTTBridge::checkConfigurationMismatch() {
  if (_prefs->mqtt_packets_enabled && !_prefs->mqtt_rx_enabled && _prefs->mqtt_tx_enabled == 0) {
    unsigned long now = millis();
    if (_last_config_warning == 0 || now - _last_config_warning > 300000UL) {
      MQTT_DEBUG_PRINTLN("Both mqtt.rx and mqtt.tx are off - no packets will be published");
      _last_config_warning = now;
    }
  } else {
    _last_config_warning = 0;
  }
}

void MQTTBridge::getClientVersion(char* buffer, size_t buffer_size) const {
  if (!buffer || buffer_size == 0) return;
  snprintf(buffer, buffer_size, "meshcore/%s", _firmware_version);
}

void MQTTBridge::setOrigin(const char* origin) { StrHelper::strncpy(_origin, origin, sizeof(_origin)); }

void MQTTBridge::setIATA(const char* iata) {
  StrHelper::strncpy(_iata, iata, sizeof(_iata));
  for (int i = 0; _iata[i]; i++) _iata[i] = toupper(_iata[i]);
}

void MQTTBridge::setDeviceID(const char* device_id) { StrHelper::strncpy(_device_id, device_id, sizeof(_device_id)); }
void MQTTBridge::setFirmwareVersion(const char* v) { StrHelper::strncpy(_firmware_version, v, sizeof(_firmware_version)); }
void MQTTBridge::setBoardModel(const char* m) { StrHelper::strncpy(_board_model, m, sizeof(_board_model)); }
void MQTTBridge::setBuildDate(const char* d) { StrHelper::strncpy(_build_date, d, sizeof(_build_date)); }

void MQTTBridge::setMessageTypes(bool status, bool packets, bool raw) {
  _status_enabled = status;
  _packets_enabled = packets;
  _raw_enabled = raw;
}

int MQTTBridge::getConnectedBrokers() const {
  int count = 0;
  for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) {
    if (_slots[i].enabled && _slots[i].connected) count++;
  }
  return count;
}

int MQTTBridge::getQueueSize() const { return _queue_count; }

bool MQTTBridge::isReady() const { return _initialized; }

void MQTTBridge::setStatsSources(mesh::Dispatcher* dispatcher, mesh::Radio* radio,
                                 mesh::MainBoard* board, mesh::MillisecondClock* ms) {
  _dispatcher = dispatcher;
  _radio = radio;
  _board = board;
  _ms = ms;
}

#endif  // WITH_MQTT_BRIDGE && ETHERNET_ENABLED
