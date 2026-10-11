#ifdef ETHERNET_ENABLED

#include "NetRandom.h"
#include <Arduino.h>

#ifdef NRF52_PLATFORM
#include <nrf_sdm.h>
#include <nrf_soc.h>
#endif

void netFillRandom(uint8_t* buf, size_t len) {
#ifdef NRF52_PLATFORM
  uint8_t sd_enabled = 0;
  sd_softdevice_is_enabled(&sd_enabled);
  if (sd_enabled) {
    // The SoftDevice owns the RNG peripheral; use its random pool.
    size_t pos = 0;
    while (pos < len) {
      uint8_t avail = 0;
      sd_rand_application_bytes_available_get(&avail);
      if (avail == 0) {
        delay(1);
        continue;
      }
      uint8_t n = (len - pos) < avail ? (uint8_t)(len - pos) : avail;
      if (sd_rand_application_vector_get(buf + pos, n) == NRF_SUCCESS) pos += n;
    }
    return;
  }

  NRF_RNG->CONFIG = RNG_CONFIG_DERCEN_Enabled;  // bias correction
  NRF_RNG->EVENTS_VALRDY = 0;
  NRF_RNG->TASKS_START = 1;
  for (size_t i = 0; i < len; i++) {
    while (NRF_RNG->EVENTS_VALRDY == 0) {}
    NRF_RNG->EVENTS_VALRDY = 0;
    buf[i] = (uint8_t)NRF_RNG->VALUE;
  }
  NRF_RNG->TASKS_STOP = 1;
#else
  for (size_t i = 0; i < len; i++) {
    buf[i] = (uint8_t)(random(256) ^ (micros() >> (i % 8)));
  }
#endif
}

#endif  // ETHERNET_ENABLED
