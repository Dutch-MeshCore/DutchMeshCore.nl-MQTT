#pragma once

/**
 * @file MQTTBridgeEthernet.h
 * @brief MQTT bridge over wired Ethernet (WIZnet W5100S, e.g. RAK13800 on a RAK4631).
 *
 * Drop-in replacement for the ESP32/WiFi MQTTBridge: same class name and public
 * API, so MyMesh, CommonCLI and AlertReporter work unchanged. Selected by
 * MQTTBridge.h when both WITH_MQTT_BRIDGE and ETHERNET_ENABLED are defined.
 *
 * Transport stack per slot:
 *   PubSubClient -> [WSClient] -> [BearTLSClient] -> EthernetClient (W5100S)
 * which supports the same preset URLs as the ESP32 build: mqtt://, mqtts://,
 * ws:// and wss:// (incl. Ed25519 JWT auth used by the DutchMeshCore presets).
 *
 * All network I/O runs in a dedicated FreeRTOS task; the W5100S is never touched
 * from the mesh loop task. CLI status getters only read cached values.
 */

#include "MeshCore.h"
#include "helpers/bridges/BridgeBase.h"
#include "helpers/JWTHelper.h"
#include "helpers/MQTTPresets.h"
#include <ArduinoJson.h>
#include <Timezone.h>

#if defined(MQTT_DEBUG) && defined(ARDUINO)
  #include <Arduino.h>
  #define MQTT_DEBUG_PRINT(F, ...) do { if (Serial.availableForWrite() > 0) { Serial.printf("MQTT: " F, ##__VA_ARGS__); } } while(0)
  #define MQTT_DEBUG_PRINTLN(F, ...) do { if (Serial.availableForWrite() > 0) { Serial.printf("MQTT: " F "\n", ##__VA_ARGS__); } } while(0)
#else
  #define MQTT_DEBUG_PRINT(...) {}
  #define MQTT_DEBUG_PRINTLN(...) {}
#endif

#ifdef WITH_MQTT_BRIDGE

struct MQTTSlotTransport;   // defined in MQTTBridgeEthernet.cpp (keeps network headers private)

class MQTTBridge : public BridgeBase {
private:
  static const size_t AUTH_TOKEN_SIZE = 768;

  enum Scheme : uint8_t { SCHEME_MQTT, SCHEME_MQTTS, SCHEME_WS, SCHEME_WSS };

  struct MQTTSlot {
    MQTTSlotTransport* net;         // allocated once in begin(), reused for every reconnect
    const MQTTPresetDef* preset;    // nullptr for custom/none
    bool enabled;
    volatile bool connected;
    bool initial_connect_done;

    char auth_token[AUTH_TOKEN_SIZE];
    unsigned long token_expires_at;

    // Custom broker settings
    char host[64];
    uint16_t port;
    char username[32];
    char password[64];
    char audience[64];

    // Resolved endpoint
    Scheme scheme;
    char ep_host[64];
    uint16_t ep_port;
    char ep_path[64];

    // Reconnect backoff
    uint8_t reconnect_backoff;
    uint8_t max_backoff_failures;
    bool circuit_breaker_tripped;
    unsigned long last_reconnect_attempt;
    unsigned long last_log_time;

    // Diagnostics (read by CLI)
    int last_tls_err;               // BearTLSClient error (0 = none)
    int last_http_status;           // WebSocket upgrade status
    int last_mqtt_state;            // PubSubClient state()
    unsigned long last_error_time;
    uint32_t disconnect_count;
    unsigned long first_disconnect_time;
    unsigned long current_outage_started_ms;
  };

  MQTTSlot _slots[RUNTIME_MQTT_SLOTS];
  char _jwt_username[70];

  char _origin[32];
  char _iata[8];
  char _device_id[65];
  char _firmware_version[64];
  char _board_model[64];
  char _build_date[32];
  bool _status_enabled;
  bool _packets_enabled;
  bool _raw_enabled;
  unsigned long _last_status_publish;
  unsigned long _last_status_retry;
  unsigned long _status_interval;
  static const unsigned long STATUS_RETRY_INTERVAL = 30000;

  struct QueuedPacket {
    mesh::Packet packet_copy;
    unsigned long timestamp;
    bool is_tx;
    float snr;
    float rssi;
    uint8_t raw_data[256];
    uint8_t raw_len;
    bool has_raw_data;
    uint8_t retry_attempts;
  };
  static const int MAX_QUEUE_SIZE = 16;
  void* _packet_queue;            // FreeRTOS QueueHandle_t
  void* _task_handle;             // FreeRTOS TaskHandle_t; created once, lives for the bridge lifetime
  volatile bool _reload_pending;  // begin() after end(): task reloads slots from prefs
  bool _paused;                   // task-side: slots torn down while the bridge is stopped
  volatile int _queue_count;
  unsigned long _queue_disconnected_since;
  static const unsigned long QUEUE_STALE_MS = 300000UL;

  // Raw radio data staging (mesh loop task only)
  uint8_t _staged_raw[256];
  int _staged_raw_len;
  float _staged_snr;
  float _staged_rssi;
  bool _staged_raw_valid;

  // Time
  bool _ntp_synced;
  unsigned long _last_ntp_sync;
  unsigned long _last_ntp_attempt;
  volatile uint32_t _pending_rtc_epoch;   // applied to the RTC from the mesh loop task
  bool _slots_setup_done;
  int _max_active_slots;
  volatile bool _slot_reconfigure_pending[RUNTIME_MQTT_SLOTS];
  Timezone _timezone_utc;          // MQTTMessageBuilder always emits UTC timestamps

  // JSON scratch (MQTT task only)
  static const size_t PUBLISH_JSON_BUFFER_SIZE = 2048;
  static const size_t STATUS_JSON_BUFFER_SIZE = 768;
  char _publish_json_buffer[PUBLISH_JSON_BUFFER_SIZE];
  char _status_json_buffer[STATUS_JSON_BUFFER_SIZE];
  StaticJsonDocument<PUBLISH_JSON_BUFFER_SIZE> _packet_json_doc;
  StaticJsonDocument<STATUS_JSON_BUFFER_SIZE> _status_json_doc;

  mesh::LocalIdentity* _identity;
  unsigned long _last_slot_connect_ms;
  unsigned long _last_no_broker_log;
  unsigned long _last_config_warning;

  mesh::Dispatcher* _dispatcher;
  mesh::Radio* _radio;
  mesh::MainBoard* _board;
  mesh::MillisecondClock* _ms;

  enum MQTTMessageType { MSG_STATUS, MSG_PACKETS, MSG_RAW };

  // Task
  static void taskEntry(void* param);
  void taskLoop();

  // Network (MQTT task only)
  void ethernetInit();
  bool ethernetBegin();
  void ethernetMaintain(unsigned long now);
  bool isNetworkUp() const;

  // Slots (MQTT task only)
  bool resolveEndpoint(int index);
  bool connectSlot(int index);
  void disconnectSlot(int index, bool count_as_disconnect);
  void teardownSlot(int index);
  void maintainSlots(unsigned long now);
  void applySlotPreset(int slot_index, const char* preset_name);
  bool createSlotAuthToken(int index);
  bool slotUsesJwt(int index) const;
  bool publishToSlot(int index, const char* topic, const char* payload, bool retained);
  void publishStatusToSlot(int index);
  bool buildTopicForSlot(int index, MQTTMessageType type, char* topic_buf, size_t buf_size);
  bool substituteTopicTemplate(const char* tmpl, MQTTMessageType type, int slot_index, char* buf, size_t buf_size);
  bool isSlotReady(int index, char* reason_buf = nullptr, size_t reason_size = 0) const;
  bool isIATAValid() const;
  bool anySlotConnected() const;

  // Publishing (MQTT task only)
  void processPacketQueue();
  bool publishStatus();
  int buildStatusJson();
  bool publishPacket(QueuedPacket& queued);
  bool publishRaw(mesh::Packet* packet);

  // Time (MQTT task only)
  void syncTimeWithNTP();

  void queuePacket(mesh::Packet* packet, bool is_tx);
  void loadSlotsFromPrefs();
  void checkConfigurationMismatch();
  void getClientVersion(char* buffer, size_t buffer_size) const;
  void refreshOriginFromPrefs();

public:
  MQTTBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc, mesh::LocalIdentity *identity);

  void begin() override;
  void end() override;
  /** Called from the mesh loop task: applies NTP time to the RTC (I2C must stay on this task). */
  void loop() override;
  void onPacketReceived(mesh::Packet *packet) override;
  void sendPacket(mesh::Packet *packet) override;

  void setSlotPreset(int slot_index, const char* preset_name);
  void setSlotCustomBroker(int slot_index, const char* host, uint16_t port,
                           const char* username, const char* password);

  void setOrigin(const char* origin);
  void setIATA(const char* iata);
  void setDeviceID(const char* device_id);
  void setFirmwareVersion(const char* firmware_version);
  void setBoardModel(const char* board_model);
  void setBuildDate(const char* build_date);
  void storeRawRadioData(const uint8_t* raw_data, int len, float snr, float rssi);
  void setMessageTypes(bool status, bool packets, bool raw);
  int getConnectedBrokers() const;
  int getQueueSize() const;
  bool isReady() const;

  unsigned long getSlotCurrentOutageStartMs(int slot_index) const;
  bool isSlotEnabledAndAttempted(int slot_index) const;
  const char* getSlotPresetName(int slot_index) const;
  static int getRuntimeSlotCount() { return RUNTIME_MQTT_SLOTS; }

  static void getEffectiveMqttOrigin(const NodePrefs* prefs, char* buf, size_t buf_size);
  static void formatMqttStatusReply(char* buf, size_t bufsize, const NodePrefs* prefs);
  /** True when at least one MQTT slot can run (no WiFi credentials needed for Ethernet). */
  static bool isConfigValid(const NodePrefs* prefs);
  static void formatSlotDiagReply(char* buf, size_t bufsize, int slot_index);
  /** Ethernet link/IP status for 'get eth.status' (cached; safe from any task). */
  static void formatNetStatusReply(char* buf, size_t bufsize);
  /** Cached IPv4 address (0.0.0.0 when down) for the UI. */
  static void getLocalIP(uint8_t ip[4]);

  // WiFi-named accessors kept for API compatibility (AlertReporter, CLI);
  // they report the Ethernet link state.
  static unsigned long getWifiConnectedAtMillis();
  static uint8_t getLastWifiDisconnectReason();
  static unsigned long getLastWifiDisconnectTime();
  static const char* wifiReasonStr(uint8_t reason);
  static const char* tlsErrorStr(int32_t err);

  void setStatsSources(mesh::Dispatcher* dispatcher, mesh::Radio* radio,
                       mesh::MainBoard* board, mesh::MillisecondClock* ms);
};

#endif  // WITH_MQTT_BRIDGE
