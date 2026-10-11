#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * Fill a buffer with random bytes for TLS entropy and WebSocket keys.
 * On nRF52 this uses the hardware RNG (through the SoftDevice when it is enabled).
 */
void netFillRandom(uint8_t* buf, size_t len);
