#pragma once

#include <Arduino.h>
#include <Client.h>

/**
 * @brief Minimal RFC 6455 WebSocket client exposed as an Arduino Client.
 *
 * Wraps another Client (plain TCP or BearTLSClient) and carries a byte stream
 * inside binary frames, so PubSubClient can speak MQTT-over-WebSockets
 * ("Sec-WebSocket-Protocol: mqtt") without knowing about framing.
 *
 * - Every write() becomes one masked binary frame (PubSubClient writes one
 *   MQTT packet per call).
 * - Ping frames are answered with pong; close frames end the connection.
 */
class WSClient : public Client {
public:
  static const size_t TX_BUFFER_SIZE = 2400;  // largest MQTT packet + 14 byte frame header

  WSClient();
  ~WSClient();

  void setTransport(Client* transport) { _transport = transport; }
  void setPath(const char* path);
  void setHandshakeTimeout(uint32_t ms) { _timeout_ms = ms; }

  int connect(IPAddress ip, uint16_t port) override;
  int connect(const char* host, uint16_t port) override;
  size_t write(uint8_t b) override { return write(&b, 1); }
  size_t write(const uint8_t* buf, size_t size) override;
  int available() override;
  int read() override;
  int read(uint8_t* buf, size_t size) override;
  int peek() override;
  void flush() override;
  void stop() override;
  uint8_t connected() override;
  operator bool() override { return connected(); }

  /** HTTP status code from the last upgrade attempt (101 = OK, 0 = no response). */
  int lastHttpStatus() const { return _last_http_status; }

private:
  bool handshake(const char* host, uint16_t port);
  bool readHttpLine(char* line, size_t size, unsigned long deadline);
  // Parses frame headers/control frames until data payload is available.
  void pump();
  bool sendFrame(uint8_t opcode, const uint8_t* payload, size_t len);

  Client* _transport;
  char _path[96];
  uint32_t _timeout_ms;
  bool _open;
  int _last_http_status;

  uint8_t* _tx_buf;

  // Receive state machine
  uint8_t _rx_state;             // header / data / control / skip
  uint8_t _hdr[14];
  uint8_t _hdr_len;
  uint8_t _opcode;
  uint32_t _payload_remaining;   // bytes left in the current frame payload
  uint8_t _ctrl_buf[125];        // control frame payload (ping/close)
  uint8_t _ctrl_len;
};
