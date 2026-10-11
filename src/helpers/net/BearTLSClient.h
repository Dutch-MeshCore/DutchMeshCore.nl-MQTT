#pragma once

#include <Arduino.h>
#include <Client.h>
#include <bearssl.h>

/**
 * @brief Minimal TLS 1.2 client (BearSSL) layered on top of any Arduino Client.
 *
 * Used by the Ethernet MQTT bridge on platforms without a native TLS stack
 * (nRF52 + W5100S). Unlike SSLClient, the full 16 KB TLS input record buffer
 * is allocated, because most MQTT brokers (and Cloudflare) do not honour the
 * max_fragment_length extension.
 *
 * Trust anchors are decoded at runtime from PEM strings (see BearTrustAnchors),
 * so the existing MQTTPresets CA certificates can be reused as-is.
 */
class BearTrustAnchors {
public:
  static const int MAX_ANCHORS = 4;

  /** Decode a PEM certificate and add it as a CA trust anchor. Duplicates are ignored. */
  bool addPEM(const char* pem);
  const br_x509_trust_anchor* anchors() const { return _anchors; }
  size_t count() const { return _count; }

private:
  static const size_t DN_MAX = 256;
  static const size_t KEY_MAX = 520;  // RSA-4096 modulus (512) + exponent

  struct Storage {
    unsigned char dn[DN_MAX];
    size_t dn_len;
    unsigned char key[KEY_MAX];
  };

  br_x509_trust_anchor _anchors[MAX_ANCHORS];
  Storage _storage[MAX_ANCHORS];
  size_t _count = 0;
};

class BearTLSClient : public Client {
public:
  explicit BearTLSClient(Client& transport);
  ~BearTLSClient();

  void setTrustAnchors(const BearTrustAnchors* anchors) { _anchors = anchors; }
  /** Set the current UNIX time used for certificate validity checks. */
  void setUnixTime(uint32_t unix_time) { _unix_time = unix_time; }
  void setHandshakeTimeout(uint32_t ms) { _handshake_timeout_ms = ms; }

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

  /** Last BearSSL error code (BR_ERR_*), 0 when none. */
  int lastError() const { return _last_error; }
  /** Human-readable description of a BearSSL error code, or nullptr. */
  static const char* errorStr(int err);

private:
  struct Context {
    br_ssl_client_context cc;
    br_x509_minimal_context xc;
    unsigned char iobuf[BR_SSL_BUFSIZE_INPUT + 2048 + 85];
  };

  bool ensureContext();
  bool initEngine(const char* host);
  // Runs the engine until (state & target) != 0. Returns false on error/close,
  // or when non-blocking and no further progress is possible right now.
  bool runUntil(unsigned target, bool blocking, uint32_t timeout_ms);
  void fail(int err);

  Client& _transport;
  const BearTrustAnchors* _anchors;
  Context* _ctx;
  uint32_t _unix_time;
  uint32_t _handshake_timeout_ms;
  bool _session_active;
  int _last_error;
};
