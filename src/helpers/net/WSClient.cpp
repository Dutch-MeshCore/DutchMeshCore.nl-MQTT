#ifdef ETHERNET_ENABLED

#include "WSClient.h"
#include "NetRandom.h"
#include <string.h>
#include <stdlib.h>

namespace {
enum RxState : uint8_t { ST_HDR, ST_DATA, ST_CTRL, ST_SKIP };

const uint8_t OP_CONT = 0x0;
const uint8_t OP_TEXT = 0x1;
const uint8_t OP_BINARY = 0x2;
const uint8_t OP_CLOSE = 0x8;
const uint8_t OP_PING = 0x9;
const uint8_t OP_PONG = 0xA;

size_t base64Encode(const uint8_t* in, size_t len, char* out, size_t out_size) {
  static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t o = 0;
  for (size_t i = 0; i < len; i += 3) {
    uint32_t v = (uint32_t)in[i] << 16;
    if (i + 1 < len) v |= (uint32_t)in[i + 1] << 8;
    if (i + 2 < len) v |= in[i + 2];
    if (o + 4 >= out_size) break;
    out[o++] = tbl[(v >> 18) & 0x3F];
    out[o++] = tbl[(v >> 12) & 0x3F];
    out[o++] = (i + 1 < len) ? tbl[(v >> 6) & 0x3F] : '=';
    out[o++] = (i + 2 < len) ? tbl[v & 0x3F] : '=';
  }
  out[o] = '\0';
  return o;
}
}  // namespace

WSClient::WSClient()
    : _transport(nullptr), _timeout_ms(10000), _open(false), _last_http_status(0),
      _tx_buf(nullptr), _rx_state(ST_HDR), _hdr_len(0), _opcode(0),
      _payload_remaining(0), _ctrl_len(0) {
  strcpy(_path, "/");
}

WSClient::~WSClient() {
  free(_tx_buf);
}

void WSClient::setPath(const char* path) {
  if (!path || path[0] == '\0') {
    strcpy(_path, "/");
  } else {
    strncpy(_path, path, sizeof(_path) - 1);
    _path[sizeof(_path) - 1] = '\0';
  }
}

int WSClient::connect(IPAddress ip, uint16_t port) {
  if (!_transport) return 0;
  char host[16];
  snprintf(host, sizeof(host), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return connect(host, port);
}

int WSClient::connect(const char* host, uint16_t port) {
  if (!_transport) return 0;
  if (!_tx_buf) {
    _tx_buf = (uint8_t*)malloc(TX_BUFFER_SIZE);
    if (!_tx_buf) return 0;
  }
  _open = false;
  _hdr_len = 0;
  _rx_state = ST_HDR;
  _payload_remaining = 0;
  _ctrl_len = 0;
  _last_http_status = 0;

  if (!_transport->connected() && !_transport->connect(host, port)) {
    return 0;
  }
  if (!handshake(host, port)) {
    _transport->stop();
    return 0;
  }
  _open = true;
  return 1;
}

bool WSClient::readHttpLine(char* line, size_t size, unsigned long deadline) {
  size_t n = 0;
  while ((long)(deadline - millis()) > 0) {
    if (_transport->available() <= 0) {
      if (!_transport->connected()) return false;
      delay(1);
      continue;
    }
    int c = _transport->read();
    if (c < 0) continue;
    if (c == '\n') {
      if (n > 0 && line[n - 1] == '\r') n--;
      line[n] = '\0';
      return true;
    }
    if (n < size - 1) line[n++] = (char)c;
  }
  return false;
}

bool WSClient::handshake(const char* host, uint16_t port) {
  uint8_t key_raw[16];
  netFillRandom(key_raw, sizeof(key_raw));
  char key[32];
  base64Encode(key_raw, sizeof(key_raw), key, sizeof(key));

  char port_suffix[8] = "";
  if (port != 80 && port != 443) snprintf(port_suffix, sizeof(port_suffix), ":%u", (unsigned)port);

  int len = snprintf((char*)_tx_buf, TX_BUFFER_SIZE,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s%s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "Sec-WebSocket-Protocol: mqtt\r\n"
                     "User-Agent: MeshCore\r\n"
                     "\r\n",
                     _path, host, port_suffix, key);
  if (len <= 0 || len >= (int)TX_BUFFER_SIZE) return false;
  if (_transport->write(_tx_buf, len) != (size_t)len) return false;

  unsigned long deadline = millis() + _timeout_ms;
  char line[128];
  if (!readHttpLine(line, sizeof(line), deadline)) return false;
  // "HTTP/1.1 101 Switching Protocols"
  const char* sp = strchr(line, ' ');
  _last_http_status = sp ? atoi(sp + 1) : 0;

  // Drain the remaining response headers up to the blank line.
  while (true) {
    if (!readHttpLine(line, sizeof(line), deadline)) return false;
    if (line[0] == '\0') break;
  }
  return _last_http_status == 101;
}

bool WSClient::sendFrame(uint8_t opcode, const uint8_t* payload, size_t len) {
  if (!_transport || !_tx_buf) return false;

  size_t pos = 0;
  _tx_buf[pos++] = 0x80 | opcode;  // FIN + opcode
  if (len < 126) {
    _tx_buf[pos++] = 0x80 | (uint8_t)len;  // client frames are always masked
  } else if (len <= 0xFFFF) {
    _tx_buf[pos++] = 0x80 | 126;
    _tx_buf[pos++] = (uint8_t)(len >> 8);
    _tx_buf[pos++] = (uint8_t)len;
  } else {
    return false;  // never needed for MQTT packets of this size
  }
  if (pos + 4 + len > TX_BUFFER_SIZE) return false;

  uint8_t mask[4];
  netFillRandom(mask, sizeof(mask));
  memcpy(_tx_buf + pos, mask, 4);
  pos += 4;
  for (size_t i = 0; i < len; i++) {
    _tx_buf[pos++] = payload[i] ^ mask[i & 3];
  }
  return _transport->write(_tx_buf, pos) == pos;
}

size_t WSClient::write(const uint8_t* buf, size_t size) {
  if (!_open) return 0;
  return sendFrame(OP_BINARY, buf, size) ? size : 0;
}

void WSClient::pump() {
  while (_open) {
    if (_rx_state == ST_DATA) {
      if (_payload_remaining > 0) return;
      _rx_state = ST_HDR;
      _hdr_len = 0;
    }

    if (_transport->available() <= 0) return;

    if (_rx_state == ST_HDR) {
      int c = _transport->read();
      if (c < 0) return;
      _hdr[_hdr_len++] = (uint8_t)c;
      if (_hdr_len < 2) continue;

      uint8_t len7 = _hdr[1] & 0x7F;
      bool masked = (_hdr[1] & 0x80) != 0;
      uint8_t need = 2 + (len7 == 126 ? 2 : (len7 == 127 ? 8 : 0)) + (masked ? 4 : 0);
      if (_hdr_len < need) continue;

      if (masked) {
        // Servers must not mask frames (RFC 6455 5.1) — treat as protocol error.
        stop();
        return;
      }
      uint32_t plen = len7;
      if (len7 == 126) {
        plen = ((uint32_t)_hdr[2] << 8) | _hdr[3];
      } else if (len7 == 127) {
        plen = ((uint32_t)_hdr[6] << 24) | ((uint32_t)_hdr[7] << 16) | ((uint32_t)_hdr[8] << 8) | _hdr[9];
      }
      _opcode = _hdr[0] & 0x0F;
      _hdr_len = 0;
      _payload_remaining = plen;

      if (_opcode == OP_BINARY || _opcode == OP_TEXT || _opcode == OP_CONT) {
        _rx_state = ST_DATA;
      } else if ((_opcode == OP_PING || _opcode == OP_PONG || _opcode == OP_CLOSE) && plen <= sizeof(_ctrl_buf)) {
        _ctrl_len = 0;
        _rx_state = ST_CTRL;
      } else {
        _rx_state = ST_SKIP;
      }
    } else if (_rx_state == ST_CTRL || _rx_state == ST_SKIP) {
      if (_payload_remaining > 0) {
        uint8_t scratch[32];
        size_t want = _payload_remaining;
        uint8_t* dst = scratch;
        if (_rx_state == ST_CTRL) {
          dst = _ctrl_buf + _ctrl_len;
        } else if (want > sizeof(scratch)) {
          want = sizeof(scratch);
        }
        int r = _transport->read(dst, want);
        if (r <= 0) return;
        _payload_remaining -= r;
        if (_rx_state == ST_CTRL) _ctrl_len += r;
        if (_payload_remaining > 0) continue;
      }

      if (_rx_state == ST_CTRL) {
        if (_opcode == OP_PING) {
          sendFrame(OP_PONG, _ctrl_buf, _ctrl_len);
        } else if (_opcode == OP_CLOSE) {
          sendFrame(OP_CLOSE, _ctrl_buf, _ctrl_len >= 2 ? 2 : 0);
          _open = false;
          _transport->stop();
          return;
        }
      }
      _rx_state = ST_HDR;
      _hdr_len = 0;
    }
  }
}

int WSClient::available() {
  if (!_open) return 0;
  pump();
  if (_rx_state != ST_DATA || _payload_remaining == 0) return 0;
  int avail = _transport->available();
  if (avail <= 0) return 0;
  return (uint32_t)avail < _payload_remaining ? avail : (int)_payload_remaining;
}

int WSClient::read(uint8_t* buf, size_t size) {
  int avail = available();
  if (avail <= 0) return -1;
  if (size > (size_t)avail) size = avail;
  int r = _transport->read(buf, size);
  if (r > 0) _payload_remaining -= r;
  return r;
}

int WSClient::read() {
  uint8_t b;
  return (read(&b, 1) == 1) ? b : -1;
}

int WSClient::peek() {
  if (available() <= 0) return -1;
  return _transport->peek();
}

void WSClient::flush() {
  if (_transport) _transport->flush();
}

void WSClient::stop() {
  if (_open && _transport && _transport->connected()) {
    static const uint8_t normal_close[2] = { 0x03, 0xE8 };  // 1000 = normal closure
    sendFrame(OP_CLOSE, normal_close, sizeof(normal_close));
  }
  _open = false;
  _rx_state = ST_HDR;
  _hdr_len = 0;
  _payload_remaining = 0;
  if (_transport) _transport->stop();
}

uint8_t WSClient::connected() {
  return _open && _transport && _transport->connected();
}

#endif  // ETHERNET_ENABLED
