/********************************************************************************
 * This file is part of the OTP Generator for N900.                             *
 *                                                                              *
 * OTP is a Hildon program thats generates one-time passwords. It supports      *
 * OAUTH tokens (HOTP, TOTP) as weel as the Mobile-OTP algorithms.              *
 * Copyright (C) 2011  Sean Whitbeck <sean@neush.net>                           *
 *                                                                              *
 * This program is free software: you can redistribute it and/or modify         *
 * it under the terms of the GNU General Public License as published by         *
 * the Free Software Foundation, either version 3 of the License, or            *
 * (at your option) any later version.                                          *
 *                                                                              *
 * This program is distributed in the hope that it will be useful,              *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of               *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                *
 * GNU General Public License for more details.                                 *
 *                                                                              *
 * You should have received a copy of the GNU General Public License            *
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.        *
 ********************************************************************************/

#include "base32.h"
#include <string.h>
#include <stdlib.h>

/* RFC 4648 base32 decoding table.
 * Returns 0xFF for invalid characters. */
static const guchar b32_rev[256] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
  0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
  0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF
};

guchar*
base32_decode(const gchar *str, gsize len, gsize *out_len, base32_error_t *err)
{
  gsize i, buf, bits, n;
  guchar *out, *p;

  if (!str || len == 0) {
    if (err) *err = BASE32_ERROR_INVALID_LENGTH;
    return NULL;
  }

  /* Strip padding '=' characters and count valid chars */
  n = 0;
  for (i = 0; i < len; i++) {
    if (str[i] != '=') n++;
  }

  if (n == 0) {
    if (err) *err = BASE32_ERROR_INVALID_LENGTH;
    return NULL;
  }

  /* Output size: ceil(n * 5 / 8) bytes */
  *out_len = (n * 5 + 7) / 8;
  out = g_malloc(*out_len);
  p = out;

  buf = 0;
  bits = 0;
  for (i = 0; i < len; i++) {
    guchar c = (guchar)str[i];
    if (c == '=') break; /* padding starts */

    guchar v = b32_rev[c];
    if (v == 0xFF) {
      g_free(out);
      if (err) *err = BASE32_ERROR_INVALID_CHAR;
      return NULL;
    }

    buf = (buf << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      *p++ = (guchar)(buf >> bits) & 0xFF;
    }
  }

  return out;
}

gchar*
base32_decode_to_hex(const gchar *str, gsize len, base32_error_t *err)
{
  gsize out_len, i;
  guchar *decoded;
  gchar *hex;

  decoded = base32_decode(str, len, &out_len, err);
  if (!decoded) return NULL;

  /* 2 hex chars per byte + null terminator */
  hex = g_malloc(out_len * 2 + 1);
  for (i = 0; i < out_len; i++) {
    g_snprintf(hex + i * 2, 3, "%02X", decoded[i]);
  }
  hex[out_len * 2] = '\0';

  g_free(decoded);
  return hex;
}
