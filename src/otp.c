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


#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "otp.h"
#include "strconv.h"
#include "config.h"

#include <cotp.h>


/* Error quarks */
GQuark 
otp_error_quark ( void )
{
  return g_quark_from_static_string ("otp-error-quark");
}


/* Labels */
const gchar* algorithm_labels[] = { "HOTP", "MOTP" };
const gchar* counter_type_labels[] = { "event-based", "time-based" };


/* Tokens */
Token* 
token_new ( const gchar *name )
{
  Token *token;
  token = g_malloc ( sizeof ( Token ) );
  token->name = g_strdup ( name );
  token->key = NULL ;
  token->key_l = 0;
  token->pin = NULL;
  token->pin_size = DEFAULT_PIN_SIZE;
  token->digits = DEFAULT_DIGITS;
  token->modified = FALSE;
  return token;
}


void 
token_free ( Token *token )
{
  g_free ( (gpointer)token->name );
  if ( token->key )
    g_free ( (gpointer)token->key );
  if ( token->pin )
    g_free ( (gpointer)token->pin );
  g_free ( token );
}


const guint8* 
token_key_new ( Algorithm algorithm, guint *length )
{
  const guint8 *key;
  GRand *rng;
  guint32 *buf;
  guint i, il=0;

  rng = g_rand_new ();

  switch ( algorithm )
    {
    case HOTP: il = DEFAULT_HOTP_KEY_LENGTH / 32; break;
    case MOTP: il = DEFAULT_MOTP_KEY_LENGTH / 32; break;
    default:;
    }

  buf = g_malloc ( il * 32 );
  for ( i=0; i < il ; ++ i )
    buf[i] = g_rand_int ( rng );

  key = (guint8*)buf;
  *length = il * 4; // 4 guint8's per guint32

  g_rand_free ( rng );

  return key;
}

const gchar*
token_key_new_as_str ( Algorithm algorithm )
{
  const guint8 *raw_key;
  const gchar *str_key;
  guint l;
  cotp_error_t err;
  char *b32;

  raw_key = token_key_new ( algorithm, &l );

  switch ( algorithm )
    {
    case HOTP:
      err = NO_ERROR;
      b32 = base32_encode ( raw_key, l, &err );
      if ( b32 && err == NO_ERROR ) {
        str_key = g_strdup ( b32 );
        free ( b32 );
      } else {
        /* fallback: hex (should not happen) */
        str_key = hex_keytostr ( raw_key, l );
      }
      g_free ( (gpointer)raw_key );
      break;
    case MOTP:
    default:
      str_key = hex_keytostr ( raw_key, l );
      g_free ( (gpointer)raw_key );
      break;
    }

  return str_key;
}


const gchar*
token_otp ( Token *token )
{
  const gchar *otp;

  if ( token->counter_t == TIME ) {
    token->counter = token_epoch ( token );
  }

  otp = NULL;
  switch ( token->algorithm )
    {
    case HOTP: otp = token_hotp ( token ); break;
    case MOTP: otp = token_motp ( token ); break;
    default:;
    }

  return otp;
}


const gchar*
token_motp ( Token *token )
{
  GChecksum *md5;
  const gchar *otp;
  const gchar *key_str;
  guchar *buffer;

  md5 = g_checksum_new ( G_CHECKSUM_MD5 );

  key_str = token_get_key_as_str ( token );
  
  buffer = (guchar*)g_strdup_printf ( "%lu%s%s", (gulong)token->counter, key_str , token->pin );

  g_checksum_update ( md5, buffer, -1 );

  otp = g_strndup ( g_checksum_get_string ( md5 ), token->digits );

  g_checksum_free ( md5 );
  g_free ( (gpointer)key_str );
  g_free ( buffer );
  return otp;
}


const gchar*
token_hotp ( Token *token )
{
  const gchar *otp;
  const gchar *b32_secret;
  gchar *result;
  cotp_error_t err;

  /* HOTP keys are stored as base32-encoded strings (see token_set_key).
     libcotp expects the secret in base32 form. */
  b32_secret = (const gchar*) token->key;

  err = NO_ERROR;
  result = get_hotp ( b32_secret, (long) token->counter, token->digits, SHA1, &err );
  if ( result == NULL || err != NO_ERROR ) {
    if ( result ) free ( result );
    return g_strdup ( "" );
  }

  otp = g_strdup ( result );
  free ( result );
  return otp;
}


guint64
token_epoch ( Token *token )
{
  if ( token->counter_t == TIME )
    return ((guint64)( time ( NULL )) / token->interval );
  return 0;
}

void
token_set_key ( Token *token, const gchar *str, GError **err )
{
  const guint8 *key;
  KeyType key_t;
  guint key_l;
  gchar *str_up;
  cotp_error_t berr;
  gchar *b32;
  const guint8 *raw;
  guint raw_l;
  GError *lerr;

  key_l = 0;
  key = NULL;
  key_t = 0;

  switch ( token->algorithm )
    {
    case HOTP: /* HOTP keys are stored as base32-encoded strings */
      if ( str && *str ) {
        /* libcotp's is_string_valid_b32 only accepts uppercase base32,
           so check an uppercased copy */
        str_up = g_ascii_strup ( str, -1 );
        if ( is_string_valid_b32 ( str_up ) ) {
          /* input is already base32-encoded; store as-is */
          g_free ( str_up );
          key = (guint8*) g_strdup ( str );
          key_l = strlen ( str );
          key_t = BASE32;
          break;
        }
        g_free ( str_up );
      }

      /* try to interpret as a hex string */
      lerr = NULL;
      raw = hex_strtokey ( str, &raw_l, &lerr );
      if ( !lerr ) {
        /* encode the raw key bytes as base32 */
        berr = NO_ERROR;
        b32 = base32_encode ( raw, raw_l, &berr );
        g_free ( (gpointer)raw );
        if ( b32 && berr == NO_ERROR ) {
          key = (guint8*) g_strdup ( b32 );
          key_l = strlen ( b32 );
          key_t = BASE32;
          free ( b32 );
          break;
        }
        if ( b32 ) free ( b32 );
      } else {
        g_error_free ( lerr );
      }

      /* otherwise, use key as raw ascii: base32-encode the bytes */
      berr = NO_ERROR;
      b32 = base32_encode ( (const guint8*) str, strlen ( str ), &berr );
      if ( b32 && berr == NO_ERROR ) {
        key = (guint8*) g_strdup ( b32 );
        key_l = strlen ( b32 );
        key_t = BASE32;
        free ( b32 );
      } else {
        g_set_error ( err, OTP_ERROR, OTP_ERROR_INVALID_TOKEN,
                      "Could not encode key" );
        if ( b32 ) free ( b32 );
        return;
      }
      break;

    case MOTP: /* MOTP passwords are always ascii */
      key = (guint8*) g_strdup ( str );
      key_l = strlen ( str );
      key_t = ASCII;
      break;

    default:;
    }

  /* if there is an existing key, free it */
  if ( token->key )
    g_free ( (gpointer)token->key );

  token->key = key;
  token->key_l = key_l;
  token->key_t = key_t;
}


void
token_set_algorithm ( Token *token, const gchar *str, GError **err)
{
  gchar* str_up;
  Algorithm alg;
  
  str_up = g_ascii_strup ( str, -1 );
  for ( alg=0; alg < N_OTP_ALGORITHMS; ++alg ){
    if ( g_strcmp0( algorithm_labels[alg], str_up ) == 0 )
      break;
  }
  g_free ( str_up );
  if ( alg == N_OTP_ALGORITHMS ){
    g_set_error ( err, OTP_ERROR, OTP_ERROR_INVALID_TOKEN,
		  "Invalid algorithm '%s'.", str );
    return;
  }
  
  token->algorithm = alg;
  switch ( alg )
    {
    case HOTP: 
      token->interval = DEFAULT_HOTP_INTERVAL;
      token->counter = DEFAULT_COUNTER; 
      break;
      
    case MOTP:
	token->interval = DEFAULT_MOTP_INTERVAL;
	token->counter = DEFAULT_COUNTER;
	break;

    default:;
    }

}


void
token_set_counter_type ( Token *token, const gchar *str, GError **err )
{
  gchar *str_up, *label_up;
  CounterType counter_t;

  str_up = g_ascii_strup ( str, -1 );
  for ( counter_t=0; counter_t < N_OTP_COUNTER_TYPES; ++counter_t ){
    label_up = g_ascii_strup ( counter_type_labels[counter_t], -1 );
    if ( g_strcmp0( label_up, str_up ) == 0 ){
      g_free ( label_up );
      break;
    } else {
      g_free ( label_up );
    }
  }
  g_free ( str_up );
  if ( counter_t == N_OTP_COUNTER_TYPES ){
    g_set_error ( err, OTP_ERROR, OTP_ERROR_INVALID_TOKEN,
		  "Invalid counter type '%s'.", str );
    return;
  }

  token->counter_t = counter_t;
}


void
token_set_interval ( Token *token, const gchar *str, GError **err )
{
  guint interval;
  GError *lerr;

  lerr = NULL;
  interval = strtouint ( str, &lerr );
  if ( lerr ){
    g_propagate_error ( err, lerr );
    return;
  }

  if ( interval == 0 ){ /* prevent 0 intervals */
    g_set_error ( err, OTP_ERROR, OTP_ERROR_INVALID_TOKEN,
		  "Interval must be greater than 1" );
    return;
  }

  token->interval = interval;
}


void
token_set_counter ( Token *token, const gchar *str, GError **err )
{
  guint64 counter;
  GError *lerr;

  lerr = NULL;
  counter = strtouint64 ( str, &lerr );
  if ( lerr ){
    g_propagate_error ( err, lerr );
    return;
  }

  token->counter = counter;
}


void
token_set_digits ( Token *token,  const gchar *str, GError **err )
{
  guint digits;
  GError *lerr; 

  lerr = NULL;
  digits = strtouint ( str, &lerr );
  if ( lerr ){
    g_propagate_error ( err, lerr );
    return;
  }

  if ( digits < MIN_DIGITS || digits > MAX_DIGITS ){
    g_set_error ( err, OTP_ERROR, OTP_ERROR_INVALID_TOKEN,
		  "Number of digits must be between %d and %d",
		  MIN_DIGITS, MAX_DIGITS );
    return;
  }

  token->digits = digits;
}


void
token_set_pin_size ( Token *token,  const gchar *str, GError **err )
{
  guint pin_size;
  GError *lerr; 

  lerr = NULL;
  pin_size = strtouint ( str, &lerr );
  if ( lerr ){
    g_propagate_error ( err, lerr );
    return;
  }

  if ( pin_size < MIN_PIN_SIZE || pin_size > MAX_PIN_SIZE ){
    g_set_error ( err, OTP_ERROR, OTP_ERROR_INVALID_TOKEN,
		  "Pin size must be between %d and %d",
		  MIN_PIN_SIZE, MAX_PIN_SIZE );
    return;
  }

  token->pin_size = pin_size;
}


void
token_set_pin ( Token *token,  const gchar *str, GError **err )
{
  if ( token->pin )
    g_free ( (gpointer)token->pin );
  token->pin = str;
}


const gchar*
token_get_key_as_str ( Token *token )
{
  if ( token->key_t == HEX )
    return hex_keytostr ( token->key, token->key_l );
  /* BASE32 and ASCII keys are stored as their string form */
  return g_strdup ( (gchar*)token->key );
}


const gchar*
token_get_counter_as_str ( Token *token )
{
  return uint64tostr ( token->counter );
}
