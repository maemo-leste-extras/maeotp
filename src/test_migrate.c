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
 * (at your option) any later version.                                            *
 *                                                                              *
 * This program is distributed in the hope that it will be useful,              *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of               *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                *
 * GNU General Public License for more details.                                 *
 *                                                                              *
 * You should have received a copy of the GNU General Public License            *
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.        *
 ********************************************************************************/


#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <cotp.h>
#include "otp.h"
#include "tokendb.h"
#include "strconv.h"

/* RFC 4226 HOTP test vector key (hex of "12345678901234567890") */
#define HEX_KEY "3132333435363738393031323334353637383930"

/* A hex key that is also a valid base32 string when uppercased
   (only chars from {a-f, 2-7}). Pre-0.3.0 stored this as a hex
   string; the migration must decode it as hex (not treat it as a
   base32 literal). */
#define HEX_AS_B32_KEY "abcdef2345abcdef2345"

/* MOTP test key (ASCII passphrase) */
#define MOTP_KEY "0123456789abcdef"

static const gchar *hotp_vectors[] = {
  "755224", "287082", "359152", "969429", "338314",
  "254676", "287922", "162583", "399871", "520489"
};


static char *
make_old_tokens_file ( const gchar *dir )
{
  gchar *path, *file_name;
  const char *contents;

  path = g_build_filename ( dir, ".config", "maeotp", NULL );
  g_mkdir_with_parents ( path, 0700 );
  file_name = g_build_filename ( path, "tokens", NULL );
  g_free ( path );

  /* Old-format (pre-0.3.0) tokens file: no "key type" marker.
     HOTP keys stored as hex; MOTP key stored as ASCII. */
  contents =
    "# OTP tokens\n"
    "[Hexc]\n"
    "key=" HEX_KEY "\n"
    "algorithm=HOTP\n"
    "counter type=event-based\n"
    "counter value=0\n"
    "digits=6\n"
    "[Regb]\n"
    "key=" HEX_AS_B32_KEY "\n"
    "algorithm=HOTP\n"
    "counter type=event-based\n"
    "counter value=0\n"
    "digits=6\n"
    "[Motp]\n"
    "key=" MOTP_KEY "\n"
    "algorithm=MOTP\n"
    "counter type=time-based\n"
    "pin size=4\n";

  g_file_set_contents ( file_name, contents, -1, NULL );
  return file_name;
}


int
main ()
{
  const gchar *tmp;
  gchar *dir, *file_name, *kt;
  TokenDB *db;
  Token *token;
  GError *err;
  const gchar *otp, *expected_b32, *wrong_b32;
  const guint8 *raw;
  guint raw_l, i;
  cotp_error_t berr;
  gboolean ok;
  int failures = 0;

  /* Use a scratch HOME so token_db_new reads our old-format file */
  tmp = g_get_tmp_dir ();
  dir = g_build_filename ( tmp, "maeotp-migrate-test-XXXXXX", NULL );
  dir = g_mkdtemp ( dir );  /* g_mkdtemp mutates in place and returns it */
  g_setenv ( "HOME", dir, TRUE );

  file_name = make_old_tokens_file ( dir );

  /* Load + migrate. The file exists, so no DB_NOT_FOUND error. */
  err = NULL;
  db = token_db_new ( &err );
  if ( err ) {
    g_error ( "token_db_new failed: %s", err->message );
    g_error_free ( err );
    return 1;
  }
  if ( err ) g_error_free ( err );

  /* Hexc: hex key migrated to base32, must produce RFC 4226 OTPs */
  err = NULL;
  token = token_db_get_token ( db, "Hexc", &err );
  if ( err || !token ) { g_error ( "Hexc: get_token failed" ); return 1; }
  if ( token->key_t != BASE32 ) {
    g_error ( "Hexc: expected BASE32 key type, got %d", token->key_t );
    return 1;
  }
  for ( i = 0; i < 10; ++i ) {
    token->counter = i;
    otp = token_hotp ( token );
    ok = ( g_strcmp0 ( otp, hotp_vectors[i] ) == 0 );
    if ( !ok ) {
      g_error ( "Hexc: counter %u expected '%s' got '%s'", i, hotp_vectors[i], otp );
      return 1;
    }
    g_free ( (gpointer)otp );
  }
  token_free ( token );

  /* Regb: hex-key-that-looks-like-base32. Migration must decode it as
     hex (not store it as a base32 literal). */
  err = NULL;
  token = token_db_get_token ( db, "Regb", &err );
  if ( err || !token ) { g_error ( "Regb: get_token failed" ); return 1; }
  if ( token->key_t != BASE32 ) {
    g_error ( "Regb: expected BASE32 key type, got %d", token->key_t );
    return 1;
  }
  /* expected = base32( hex_decode( HEX_AS_B32_KEY ) ) */
  raw = hex_strtokey ( HEX_AS_B32_KEY, &raw_l, NULL );
  /* libcotp base32_encode reads input via strlen: NUL-terminate */
  {
    guint8 *rz = g_malloc ( raw_l + 1 );
    memcpy ( rz, raw, raw_l );
    rz[raw_l] = 0;
    g_free ( (gpointer)raw );
    berr = NO_ERROR;
    expected_b32 = base32_encode ( rz, raw_l, &berr );
    g_free ( rz );
  }
  /* wrong = base32( literal bytes of HEX_AS_B32_KEY ) -- what we'd get
     if the migration mis-treated the string as a base32/ASCII secret */
  berr = NO_ERROR;
  wrong_b32 = base32_encode ( (const guint8*)HEX_AS_B32_KEY, strlen ( HEX_AS_B32_KEY ), &berr );
  if ( g_strcmp0 ( (const gchar*)token->key, expected_b32 ) != 0 ) {
    g_error ( "Regb: migrated key '%s' != expected base32 '%s'",
              (const gchar*)token->key, expected_b32 );
    failures++;
  }
  if ( g_strcmp0 ( (const gchar*)token->key, wrong_b32 ) == 0 ) {
    g_error ( "Regb: migrated key matches the WRONG (literal) base32 -- "
              "migration treated hex as a literal secret" );
    failures++;
  }
  token->counter = 0;
  otp = token_hotp ( token );
  if ( !otp || otp[0] == '\0' ) {
    g_error ( "Regb: token_hotp returned empty" );
    failures++;
  }
  g_free ( (gpointer)otp );
  token_free ( token );
  g_free ( (gpointer)expected_b32 );
  g_free ( (gpointer)wrong_b32 );

  /* Motp: ASCII passphrase, must be tagged ascii and unchanged */
  err = NULL;
  token = token_db_get_token ( db, "Motp", &err );
  if ( err || !token ) { g_error ( "Motp: get_token failed" ); return 1; }
  if ( token->key_t != ASCII ) {
    g_error ( "Motp: expected ASCII key type, got %d", token->key_t );
    return 1;
  }
  if ( g_strcmp0 ( (const gchar*)token->key, MOTP_KEY ) != 0 ) {
    g_error ( "Motp: key changed: expected '%s' got '%s'", MOTP_KEY, (const gchar*)token->key );
    return 1;
  }
  token->counter = 129612120;
  token->pin = g_strdup ( "6666" );
  otp = token_motp ( token );
  ok = ( g_strcmp0 ( otp, "6ed4e4" ) == 0 );
  if ( !ok ) {
    g_error ( "Motp: expected '6ed4e4' got '%s'", otp );
    return 1;
  }
  g_free ( (gpointer)otp );
  token_free ( token ); /* frees token->pin */

  /* Persist the migration and reload to verify the new-format round-trip */
  err = NULL;
  token_db_save ( db, &err );
  if ( err ) { g_error ( "token_db_save failed: %s", err->message ); return 1; }
  if ( err ) g_error_free ( err );
  token_db_free ( db );

  err = NULL;
  db = token_db_new ( &err );
  if ( err ) { g_error ( "reload token_db_new failed: %s", err->message ); return 1; }
  if ( err ) g_error_free ( err );

  /* After reload, key type markers should be present (new format). */
  kt = g_key_file_get_value ( db->key_file, "Hexc", "key type", NULL );
  if ( g_strcmp0 ( kt, "base32" ) != 0 ) {
    g_error ( "Hexc: expected key type 'base32' in persisted DB, got '%s'", kt ? kt : "(null)" );
    return 1;
  }
  g_free ( kt );

  kt = g_key_file_get_value ( db->key_file, "Motp", "key type", NULL );
  if ( g_strcmp0 ( kt, "ascii" ) != 0 ) {
    g_error ( "Motp: expected key type 'ascii' in persisted DB, got '%s'", kt ? kt : "(null)" );
    return 1;
  }
  g_free ( kt );

  /* Reloaded Hexc must still produce correct OTPs */
  err = NULL;
  token = token_db_get_token ( db, "Hexc", &err );
  if ( err || !token ) { g_error ( "Hexc reload: get_token failed" ); return 1; }
  token->counter = 0;
  otp = token_hotp ( token );
  if ( g_strcmp0 ( otp, hotp_vectors[0] ) != 0 ) {
    g_error ( "Hexc reload: expected '%s' got '%s'", hotp_vectors[0], otp );
    return 1;
  }
  g_free ( (gpointer)otp );
  token_free ( token );

  token_db_free ( db );

  /* Cleanup */
  g_unlink ( file_name );
  g_free ( file_name );
  g_rmdir ( g_build_filename ( dir, ".config", "maeotp", NULL ) );
  g_rmdir ( g_build_filename ( dir, ".config", NULL ) );
  g_rmdir ( dir );
  g_free ( dir );

  if ( failures ) {
    g_error ( "Regb assertions failed (%d)", failures );
    return 1;
  }

  return 0;
}
