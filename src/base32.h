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

#ifndef BASE32_H
#define BASE32_H

#include <glib.h>

typedef enum {
  BASE32_SUCCESS,
  BASE32_ERROR_INVALID_CHAR,
  BASE32_ERROR_INVALID_LENGTH
} base32_error_t;

/* Decode a base32-encoded string to raw bytes.
 * Returns allocated buffer with decoded bytes. Caller must free.
 * Output length is written to out_len.
 * Returns NULL on error, with error code in err. */
guchar* base32_decode(const gchar *str, gsize len, gsize *out_len, base32_error_t *err);

/* Decode a base32-encoded string and return hex-encoded string.
 * Returns allocated hex string. Caller must free.
 * Returns NULL on error. */
gchar* base32_decode_to_hex(const gchar *str, gsize len, base32_error_t *err);

#endif
