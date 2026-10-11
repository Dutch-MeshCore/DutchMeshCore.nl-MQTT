#ifdef ETHERNET_ENABLED

#include "BearTLSClient.h"
#include "NetRandom.h"
#include <string.h>
#include <stdlib.h>

// Custom (negative) error codes, alongside BearSSL's positive BR_ERR_* codes.
static const int TLS_ERR_NO_MEMORY = -1;
static const int TLS_ERR_TCP_CONNECT = -2;
static const int TLS_ERR_TIMEOUT = -3;
static const int TLS_ERR_NO_ANCHORS = -4;
static const int TLS_ERR_NO_IP_SNI = -5;

// TLS 1.2 AEAD suites only: keeps flash usage down while covering Cloudflare,
// Mosquitto, EMQX and HiveMQ defaults.
static const uint16_t TLS_SUITES[] = {
  BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
  BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
  BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};

// ---------------------------------------------------------------------------
// Trust anchors
// ---------------------------------------------------------------------------

namespace {
struct AppendBuf {
  unsigned char* buf;
  size_t len;
  size_t max;
  bool overflow;
};

void appendCallback(void* ctx, const void* data, size_t len) {
  AppendBuf* ab = static_cast<AppendBuf*>(ctx);
  if (ab->overflow) return;
  if (ab->len + len > ab->max) {
    ab->overflow = true;
    return;
  }
  memcpy(ab->buf + ab->len, data, len);
  ab->len += len;
}
}  // namespace

bool BearTrustAnchors::addPEM(const char* pem) {
  if (!pem || _count >= MAX_ANCHORS) return false;

  static const size_t DER_MAX = 2048;
  unsigned char* der = (unsigned char*)malloc(DER_MAX);
  if (!der) return false;

  // PEM -> DER
  br_pem_decoder_context pc;
  br_pem_decoder_init(&pc);
  AppendBuf der_buf = { der, 0, DER_MAX, false };
  bool in_obj = false;
  bool done = false;
  bool error = false;
  const char* p = pem;
  size_t len = strlen(pem);
  // A trailing newline is pushed after the input so the END line is always terminated.
  for (int pass = 0; pass < 2 && !done && !error; pass++) {
    if (pass == 1) {
      p = "\n";
      len = 1;
    }
    while (len > 0 && !done && !error) {
      size_t n = br_pem_decoder_push(&pc, p, len);
      p += n;
      len -= n;
      switch (br_pem_decoder_event(&pc)) {
        case BR_PEM_BEGIN_OBJ:
          in_obj = true;
          der_buf.len = 0;
          br_pem_decoder_setdest(&pc, appendCallback, &der_buf);
          break;
        case BR_PEM_END_OBJ:
          if (in_obj) done = true;
          break;
        case BR_PEM_ERROR:
          error = true;
          break;
        default:
          break;
      }
    }
  }
  if (!done || error || der_buf.overflow || der_buf.len == 0) {
    free(der);
    return false;
  }

  // DER -> DN + public key
  Storage& st = _storage[_count];
  AppendBuf dn_buf = { st.dn, 0, DN_MAX, false };
  br_x509_decoder_context dc;
  br_x509_decoder_init(&dc, appendCallback, &dn_buf);
  br_x509_decoder_push(&dc, der, der_buf.len);
  free(der);

  const br_x509_pkey* pk = br_x509_decoder_get_pkey(&dc);
  if (!pk || dn_buf.overflow) return false;
  st.dn_len = dn_buf.len;

  // Skip duplicates (several presets share the same root CA)
  for (size_t i = 0; i < _count; i++) {
    if (_anchors[i].dn.len == st.dn_len && memcmp(_anchors[i].dn.data, st.dn, st.dn_len) == 0) {
      return true;
    }
  }

  br_x509_trust_anchor& ta = _anchors[_count];
  memset(&ta, 0, sizeof(ta));
  ta.dn.data = st.dn;
  ta.dn.len = st.dn_len;
  ta.flags = BR_X509_TA_CA;

  if (pk->key_type == BR_KEYTYPE_RSA) {
    size_t nlen = pk->key.rsa.nlen;
    size_t elen = pk->key.rsa.elen;
    if (nlen + elen > KEY_MAX) return false;
    memcpy(st.key, pk->key.rsa.n, nlen);
    memcpy(st.key + nlen, pk->key.rsa.e, elen);
    ta.pkey.key_type = BR_KEYTYPE_RSA;
    ta.pkey.key.rsa.n = st.key;
    ta.pkey.key.rsa.nlen = nlen;
    ta.pkey.key.rsa.e = st.key + nlen;
    ta.pkey.key.rsa.elen = elen;
  } else if (pk->key_type == BR_KEYTYPE_EC) {
    size_t qlen = pk->key.ec.qlen;
    if (qlen > KEY_MAX) return false;
    memcpy(st.key, pk->key.ec.q, qlen);
    ta.pkey.key_type = BR_KEYTYPE_EC;
    ta.pkey.key.ec.curve = pk->key.ec.curve;
    ta.pkey.key.ec.q = st.key;
    ta.pkey.key.ec.qlen = qlen;
  } else {
    return false;
  }

  _count++;
  return true;
}

// ---------------------------------------------------------------------------
// TLS client
// ---------------------------------------------------------------------------

BearTLSClient::BearTLSClient(Client& transport)
    : _transport(transport), _anchors(nullptr), _ctx(nullptr), _unix_time(0),
      _handshake_timeout_ms(20000), _session_active(false), _last_error(0) {}

BearTLSClient::~BearTLSClient() {
  stop();
  free(_ctx);
  _ctx = nullptr;
}

bool BearTLSClient::ensureContext() {
  if (_ctx) return true;
  // Allocated once and reused for every reconnect (avoids heap churn).
  _ctx = (Context*)calloc(1, sizeof(Context));
  return _ctx != nullptr;
}

void BearTLSClient::fail(int err) {
  // The transport is gone or stuck: the TLS session cannot be resumed.
  _last_error = err;
  _session_active = false;
  _transport.stop();
}

bool BearTLSClient::initEngine(const char* host) {
  Context* c = _ctx;
  br_ssl_engine_context* eng = &c->cc.eng;

  if (!_anchors || _anchors->count() == 0) {
    _last_error = TLS_ERR_NO_ANCHORS;
    return false;
  }

  br_ssl_client_zero(&c->cc);
  br_ssl_engine_set_versions(eng, BR_TLS12, BR_TLS12);
  br_x509_minimal_init(&c->xc, &br_sha256_vtable, _anchors->anchors(), _anchors->count());
  br_ssl_engine_set_suites(eng, TLS_SUITES, sizeof(TLS_SUITES) / sizeof(TLS_SUITES[0]));

  static const struct {
    int id;
    const br_hash_class* impl;
  } HASHES[] = {
    { br_sha1_ID, &br_sha1_vtable },
    { br_sha256_ID, &br_sha256_vtable },
    { br_sha384_ID, &br_sha384_vtable },
    { br_sha512_ID, &br_sha512_vtable },
  };
  for (size_t i = 0; i < sizeof(HASHES) / sizeof(HASHES[0]); i++) {
    br_ssl_engine_set_hash(eng, HASHES[i].id, HASHES[i].impl);
    br_x509_minimal_set_hash(&c->xc, HASHES[i].id, HASHES[i].impl);
  }
  br_ssl_engine_set_prf_sha256(eng, &br_tls12_sha256_prf);
  br_ssl_engine_set_prf_sha384(eng, &br_tls12_sha384_prf);

  br_ssl_engine_set_default_rsavrfy(eng);
  br_ssl_engine_set_default_ecdsa(eng);
  br_x509_minimal_set_rsa(&c->xc, br_ssl_engine_get_rsavrfy(eng));
  br_x509_minimal_set_ecdsa(&c->xc, br_ssl_engine_get_ec(eng), br_ssl_engine_get_ecdsa(eng));
  br_ssl_engine_set_default_aes_gcm(eng);
  br_ssl_engine_set_default_chapol(eng);
  br_ssl_engine_set_x509(eng, &c->xc.vtable);

  // Certificate validity check needs wall-clock time (BearSSL counts days from year 0).
  br_x509_minimal_set_time(&c->xc, _unix_time / 86400UL + 719528UL, _unix_time % 86400UL);

  // Bidirectional buffer: full 16 KB input records + 2 KB output records.
  br_ssl_engine_set_buffer(eng, c->iobuf, sizeof(c->iobuf), 1);

  uint8_t seed[32];
  netFillRandom(seed, sizeof(seed));
  br_ssl_engine_inject_entropy(eng, seed, sizeof(seed));

  if (!br_ssl_client_reset(&c->cc, host, 0)) {
    _last_error = br_ssl_engine_last_error(eng);
    return false;
  }
  return true;
}

bool BearTLSClient::runUntil(unsigned target, bool blocking, uint32_t timeout_ms) {
  if (!_ctx) return false;
  br_ssl_engine_context* eng = &_ctx->cc.eng;
  unsigned long start = millis();

  for (;;) {
    unsigned state = br_ssl_engine_current_state(eng);
    if (state & BR_SSL_CLOSED) {
      int err = br_ssl_engine_last_error(eng);
      if (err != BR_ERR_OK && _last_error == 0) _last_error = err;
      return false;
    }

    if (state & BR_SSL_SENDREC) {
      size_t len;
      unsigned char* buf = br_ssl_engine_sendrec_buf(eng, &len);
      size_t wlen = _transport.write(buf, len);
      if (wlen == 0) {
        if (!_transport.connected() || (millis() - start) > timeout_ms) {
          fail(BR_ERR_IO);
          return false;
        }
        delay(1);
        continue;
      }
      br_ssl_engine_sendrec_ack(eng, wlen);
      continue;
    }

    if (state & target) return true;

    // Application data is pending and must be consumed before the engine can move on.
    if (state & BR_SSL_RECVAPP) return false;

    if (state & BR_SSL_RECVREC) {
      int avail = _transport.available();
      if (avail <= 0) {
        if (!_transport.connected()) {
          fail(BR_ERR_IO);
          return false;
        }
        if (!blocking) return false;
        if ((millis() - start) > timeout_ms) {
          _last_error = TLS_ERR_TIMEOUT;
          return false;
        }
        delay(1);  // yield to the mesh loop while waiting for the network
        continue;
      }
      size_t len;
      unsigned char* buf = br_ssl_engine_recvrec_buf(eng, &len);
      if ((size_t)avail < len) len = avail;
      int rlen = _transport.read(buf, len);
      if (rlen <= 0) {
        if (!blocking) return false;
        delay(1);
        continue;
      }
      br_ssl_engine_recvrec_ack(eng, rlen);
      continue;
    }

    // Nothing to do: force-flush buffered records, then re-evaluate.
    br_ssl_engine_flush(eng, 0);
    if (br_ssl_engine_current_state(eng) == state) return false;
  }
}

int BearTLSClient::connect(IPAddress ip, uint16_t port) {
  // Certificate validation requires the server name; IP-only TLS is not supported.
  (void)ip;
  (void)port;
  _last_error = TLS_ERR_NO_IP_SNI;
  return 0;
}

int BearTLSClient::connect(const char* host, uint16_t port) {
  if (_session_active) stop();
  _last_error = 0;

  if (!ensureContext()) {
    _last_error = TLS_ERR_NO_MEMORY;
    return 0;
  }
  if (!_transport.connect(host, port)) {
    _last_error = TLS_ERR_TCP_CONNECT;
    return 0;
  }
  if (!initEngine(host)) {
    _transport.stop();
    return 0;
  }
  _session_active = true;

  if (!runUntil(BR_SSL_SENDAPP | BR_SSL_RECVAPP, true, _handshake_timeout_ms)) {
    if (_last_error == 0) _last_error = br_ssl_engine_last_error(&_ctx->cc.eng);
    _session_active = false;
    _transport.stop();
    return 0;
  }
  return 1;
}

size_t BearTLSClient::write(const uint8_t* buf, size_t size) {
  if (!_session_active || !_ctx) return 0;
  br_ssl_engine_context* eng = &_ctx->cc.eng;

  size_t written = 0;
  while (written < size) {
    if (!runUntil(BR_SSL_SENDAPP, true, 10000)) break;
    size_t len;
    unsigned char* app = br_ssl_engine_sendapp_buf(eng, &len);
    size_t n = size - written;
    if (n > len) n = len;
    memcpy(app, buf + written, n);
    br_ssl_engine_sendapp_ack(eng, n);
    written += n;
  }

  // Push the record(s) out now; MQTT packets must not linger in the TLS buffer.
  br_ssl_engine_flush(eng, 0);
  runUntil(BR_SSL_SENDAPP, true, 10000);
  return written;
}

int BearTLSClient::available() {
  if (!_session_active || !_ctx) return 0;
  br_ssl_engine_context* eng = &_ctx->cc.eng;

  if (!(br_ssl_engine_current_state(eng) & BR_SSL_RECVAPP)) {
    runUntil(BR_SSL_RECVAPP, false, 0);
  }
  if (br_ssl_engine_current_state(eng) & BR_SSL_RECVAPP) {
    size_t len;
    br_ssl_engine_recvapp_buf(eng, &len);
    return (int)len;
  }
  return 0;
}

int BearTLSClient::read(uint8_t* buf, size_t size) {
  int avail = available();
  if (avail <= 0) return -1;
  size_t len;
  unsigned char* app = br_ssl_engine_recvapp_buf(&_ctx->cc.eng, &len);
  if (size > len) size = len;
  memcpy(buf, app, size);
  br_ssl_engine_recvapp_ack(&_ctx->cc.eng, size);
  return (int)size;
}

int BearTLSClient::read() {
  uint8_t b;
  return (read(&b, 1) == 1) ? b : -1;
}

int BearTLSClient::peek() {
  if (available() <= 0) return -1;
  size_t len;
  unsigned char* app = br_ssl_engine_recvapp_buf(&_ctx->cc.eng, &len);
  return app[0];
}

void BearTLSClient::flush() {
  if (!_session_active || !_ctx) return;
  br_ssl_engine_flush(&_ctx->cc.eng, 0);
  runUntil(BR_SSL_SENDAPP, true, 5000);
}

void BearTLSClient::stop() {
  if (_session_active && _ctx) {
    // Best-effort close_notify; don't wait for the peer's reply.
    br_ssl_engine_close(&_ctx->cc.eng);
    runUntil(BR_SSL_CLOSED, false, 0);
  }
  _session_active = false;
  _transport.stop();
}

uint8_t BearTLSClient::connected() {
  if (!_session_active || !_ctx) return 0;
  if (br_ssl_engine_current_state(&_ctx->cc.eng) & BR_SSL_CLOSED) return 0;
  return _transport.connected();
}

const char* BearTLSClient::errorStr(int err) {
  switch (err) {
    case 0: return "none";
    case TLS_ERR_NO_MEMORY: return "out of memory";
    case TLS_ERR_TCP_CONNECT: return "TCP connect/DNS failed";
    case TLS_ERR_TIMEOUT: return "TLS timeout";
    case TLS_ERR_NO_ANCHORS: return "no CA configured";
    case TLS_ERR_NO_IP_SNI: return "TLS needs hostname";
    case BR_ERR_IO: return "connection lost";
    case BR_ERR_BAD_VERSION: return "TLS version rejected";
    case BR_ERR_BAD_CIPHER_SUITE: return "no common cipher";
    case BR_ERR_X509_EXPIRED: return "cert expired / clock wrong";
    case BR_ERR_X509_NOT_TRUSTED: return "cert not trusted";
    case BR_ERR_X509_BAD_SERVER_NAME: return "cert name mismatch";
    case BR_ERR_X509_TIME_UNKNOWN: return "clock not set";
    default:
      if (err >= BR_ERR_RECV_FATAL_ALERT && err < BR_ERR_SEND_FATAL_ALERT) return "server alert";
      return nullptr;
  }
}

#endif  // ETHERNET_ENABLED
