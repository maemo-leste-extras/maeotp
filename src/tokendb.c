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


#include <glib/gstdio.h>
#include <string.h>
#include <cotp.h>
#include "config.h"
#include "tokendb.h"
#include "strconv.h"

#define KEY_KEY        "key"
#define KEY_ALGORITHM  "algorithm"
#define KEY_COUNTER_T  "counter type"
#define KEY_DIGITS     "digits"
#define KEY_COUNTER    "counter value"
#define KEY_INTERVAL   "interval"
#define KEY_PIN_SIZE   "pin size"
#define KEY_KEY_TYPE   "key type"


static void token_db_migrate_keys ( TokenDB *self );

#define TOKEN_DB_FILE_TITLE "# OTP tokens"


TokenDB* 
token_db_new ( GError **err ) 
{
  TokenDB *self;
  const gchar *home_dir, *dot_config_dir, *app_config_dir;
  gint retv;
  GError *tmp_err, *tmp_err2;

  self = g_malloc ( sizeof (TokenDB) );

  /* Define paths */
  home_dir = g_get_home_dir ();
  dot_config_dir = g_strjoin ( "/", home_dir, USER_CONFIG_DIR, NULL );
  app_config_dir = g_strjoin ( "/", dot_config_dir, PACKAGE, NULL );
  self->file_name = g_strjoin ( "/", app_config_dir, TOKEN_DB_FILE_NAME, NULL );
  
  /* init key file */
  self->key_file = g_key_file_new ();
  
  /* initially not modified */
  self->modified = FALSE;

  /* Make sure that we have *write* access to the config directory */
  retv = g_mkdir_with_parents ( dot_config_dir, DIR_PUBLIC_MODE );
  retv += g_mkdir_with_parents ( app_config_dir, DIR_PRIVATE_MODE );
  if ( retv != 0 ){
    g_set_error ( err, OTP_ERROR, OTP_ERROR_DB_READ,
		  "Could not create config directory %s",
		  app_config_dir);
  }

  /* Now try to read the tokens file */
  else {
    tmp_err = NULL;
    g_key_file_load_from_file ( self->key_file, self->file_name,
				G_KEY_FILE_KEEP_COMMENTS,
				&tmp_err );
    if ( tmp_err ){
      switch ( tmp_err->code )
	{
	case G_FILE_ERROR_NOENT : /* Could not find tokens file */
	  tmp_err2 = NULL;
	  token_db_save ( self, &tmp_err2 );
	  if ( tmp_err2 ) { /* error writing initial configuration file */
	    g_propagate_error ( err, tmp_err2 );
	  } else { /* successfully initalized tokens */
	    g_set_error ( err, OTP_ERROR, OTP_ERROR_DB_NOT_FOUND,
			  "Creating tokens file in %s",
			  self->file_name);
	  }
	  g_error_free ( tmp_err );
	  break;
	default : 
	  g_propagate_error ( err, tmp_err );
      };
    } else {
      /* Migrate old-format keys (pre-0.3.0) to the base32 storage
	 used by libcotp. Sets self->modified if any token was rewritten,
	 so the upgraded file is persisted on the next token_db_save. */
      token_db_migrate_keys ( self );
    }
  }
  
  /* Clean up temporary strings. home_dir is owned by GLib (returned
     by g_get_home_dir) and must not be freed; freeing it would cause
     a use-after-free on the next token_db_new in the same process. */
  g_free ( (gpointer)dot_config_dir );
  g_free ( (gpointer)app_config_dir );

  return self;
}


void 
token_db_free ( TokenDB *self )
{
  g_free ( (gpointer)(self->file_name) );
  if ( self->key_file )
    g_key_file_free ( self->key_file );
  g_free ( self );
}


void 
token_db_save ( TokenDB *self, GError **err )
{
  gchar *data;
  gsize length;
  GError *tmp_error;
  
  data = g_key_file_to_data ( self->key_file, &length, NULL );

  tmp_error = NULL;
  if ( length == 0 ){ /* This is probably the creation of the initial tokens file */
    g_file_set_contents ( self->file_name, 
			  TOKEN_DB_FILE_TITLE, -1, &tmp_error );
  }  else {
    g_file_set_contents ( self->file_name, data, length, &tmp_error );
  }

  if ( tmp_error ){
    g_set_error ( err, OTP_ERROR, OTP_ERROR_DB_WRITE,
		  "Error writing tokens file %s: %s",
		  self->file_name, g_strdup(tmp_error->message) );
    g_error_free ( tmp_error );
  } else { // success !!
    self->modified = FALSE;
  }
  g_free ( data );
}


gboolean 
token_db_has_token ( TokenDB *self, const gchar *name )
{
  return g_key_file_has_group( self->key_file, name );
}


#define SET_STRING(key,value)  g_key_file_set_value ( self->key_file, token->name, key, value )
#define SET_INTEGER(key,value)  g_key_file_set_integer ( self->key_file, token->name, key, value )
#define SET_BOOLEAN(key,value)  g_key_file_set_boolean ( self->key_file, token->name, key, value )
void 
token_db_add_token ( TokenDB *self, Token *token )
{
  /* key */
  SET_STRING ( KEY_KEY, token_get_key_as_str ( token ) );
  SET_STRING ( KEY_KEY_TYPE, key_type_labels[token->key_t] );

  /* algorithm and counter type */
  SET_STRING ( KEY_ALGORITHM, algorithm_labels[token->algorithm] );
  SET_STRING ( KEY_COUNTER_T, counter_type_labels[token->counter_t] );

  /* algorithm specific parameters */
  switch ( token->algorithm )
    {
    case HOTP:
      switch ( token->counter_t )
	{
	case EVENT: SET_STRING ( KEY_COUNTER, token_get_counter_as_str (token) ); break;
	case TIME: SET_INTEGER ( KEY_INTERVAL, token->interval ); break;
	default:;
	}
      SET_INTEGER ( KEY_DIGITS, token->digits );
      break;
      
    case MOTP:
      if ( token->counter_t == EVENT ){
	SET_STRING ( KEY_COUNTER, token_get_counter_as_str (token) );
      }
      SET_INTEGER ( KEY_PIN_SIZE, token->pin_size );
      break;

    default:;
  }

  self->modified = TRUE;
}


void
token_db_del_token ( TokenDB *self, const gchar *name )
{
  GError *err;
  err = NULL;
  g_key_file_remove_group ( self->key_file, name, &err );
  if ( err ){
    g_error_free ( err );
  }
  self->modified = TRUE;
}



#define SET_REQ_VALUE(KEY,FUNC)						\
  buffer = g_key_file_get_value ( self->key_file, name, KEY, &lerr );	\
  FUNC ( token, buffer, &lerr );					\
  if ( lerr ){								\
    g_propagate_error ( err, lerr );					\
    goto err;								\
  }									\
  g_free ( buffer );							\
  buffer = NULL;

#define SET_OPT_VALUE(KEY,FUNC)						\
  buffer = g_key_file_get_value ( self->key_file, name, KEY, &lerr );	\
  FUNC ( token, buffer, &lerr );					\
  if ( lerr ){								\
    if ( lerr->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND ){		\
      g_propagate_error ( err, lerr );					\
      goto err;								\
    } else {								\
      g_error_free ( lerr );						\
    }									\
  }									\
  g_free ( buffer );							\
  buffer = NULL;


Token*
token_db_get_token ( TokenDB *self, const gchar *name, GError **err )
{
  Token *token;
  gchar *buffer;
  GError *lerr;

  buffer = NULL;
  lerr = NULL;
  
  token = token_new ( g_strdup ( name ) );

  /* get algorithm */
  SET_REQ_VALUE ( KEY_ALGORITHM, token_set_algorithm );

  /* get counter type */
  SET_REQ_VALUE ( KEY_COUNTER_T, token_set_counter_type );

  /* read key */
  buffer = g_key_file_get_value ( self->key_file, name, KEY_KEY_TYPE, &lerr );
  if ( lerr ) {
    /* legacy entry without a key type marker: fall back to the
       input heuristic in token_set_key, which accepts base32, hex,
       or ASCII input for HOTP and ASCII for MOTP. */
    g_error_free ( lerr );
    lerr = NULL;
    SET_REQ_VALUE ( KEY_KEY, token_set_key );
  } else {
    /* new format: trust the stored key type and assign the key
       directly, without re-running the input heuristic. */
    KeyType kt;
    if ( g_strcmp0 ( buffer, "base32" ) == 0 )
      kt = BASE32;
    else if ( g_strcmp0 ( buffer, "ascii" ) == 0 )
      kt = ASCII;
    else if ( g_strcmp0 ( buffer, "hex" ) == 0 )
      kt = HEX;
    else
      kt = BASE32; /* sensible default for HOTP */
    g_free ( buffer );

    lerr = NULL;
    buffer = g_key_file_get_value ( self->key_file, name, KEY_KEY, &lerr );
    if ( lerr ) {
      g_propagate_error ( err, lerr );
      goto err;
    }
    token->key = (guint8*) g_strdup ( buffer );
    token->key_l = strlen ( buffer );
    token->key_t = kt;
    g_free ( buffer );
    buffer = NULL;
  }

  /* Read algorithm-specific params */
  switch ( token->algorithm )
    {
    case HOTP:
      /* get required parameters */
      switch ( token->counter_t )
	{
	case EVENT: SET_REQ_VALUE ( KEY_COUNTER, token_set_counter ); break;
	case TIME:  SET_REQ_VALUE ( KEY_INTERVAL, token_set_interval ); break;
	default:;
	}
      /* optional parameters */
      SET_OPT_VALUE ( KEY_DIGITS, token_set_digits );
      break;

    case MOTP:
      if ( token->counter_t == EVENT ){
	SET_REQ_VALUE ( KEY_COUNTER, token_set_counter );
      }
      SET_OPT_VALUE ( KEY_PIN_SIZE, token_set_pin_size );
      break;

    default:;
    }

  return token;

 err:
  if ( buffer )
    g_free ( buffer );
  token_free ( token );
  return NULL;
      
}


gchar** 
token_db_get_names ( TokenDB *self, gsize *length )
{
  return g_key_file_get_groups ( self->key_file, length );
}


/* Migrate old-format (pre-0.3.0) keys to the base32 storage used by
   libcotp.

   Before 0.3.0, HOTP keys were stored either as a hexadecimal string
   (the normal case: both hex input and base32 input were decoded to
   raw bytes and re-hex'd) or as a raw ASCII passphrase (the fallback
   when input was neither valid hex nor valid base32). MOTP keys were
   always stored as raw ASCII.

   0.3.0 stores HOTP keys as base32 strings, so on load token_set_key
   would misclassify an old hex key that happens to also be a valid
   base32 string (e.g. one composed only of the characters
   {a,b,c,d,e,f,2,3,4,5,6,7}), silently producing wrong OTPs.

   This pass runs once on load: for every token lacking a "key type"
   marker, it re-encodes HOTP keys to base32 (hex -> raw -> base32,
   or ASCII -> raw -> base32) and tags every token with its key type.
   It sets self->modified so the upgraded file is written back. */
static void
token_db_migrate_keys ( TokenDB *self )
{
  gchar **names;
  gsize n, i;
  gchar *kt_value, *alg_value, *old_key, *b32;
  const guint8 *raw;
  guint raw_l;
  GError *lerr;
  cotp_error_t berr;

  names = token_db_get_names ( self, &n );

  for ( i = 0; i < n; ++i ) {
    /* Skip tokens that already record a key type (new format). */
    lerr = NULL;
    kt_value = g_key_file_get_value ( self->key_file, names[i],
                                      KEY_KEY_TYPE, &lerr );
    if ( kt_value ) {
      g_free ( kt_value );
      if ( lerr ) g_error_free ( lerr );
      continue;
    }
    if ( lerr ) g_error_free ( lerr );

    lerr = NULL;
    alg_value = g_key_file_get_value ( self->key_file, names[i],
                                       KEY_ALGORITHM, &lerr );
    if ( alg_value == NULL ) {
      if ( lerr ) g_error_free ( lerr );
      continue;
    }

    lerr = NULL;
    old_key = g_key_file_get_value ( self->key_file, names[i],
                                     KEY_KEY, &lerr );
    if ( old_key == NULL ) {
      if ( lerr ) g_error_free ( lerr );
      g_free ( alg_value );
      continue;
    }

    if ( g_strcmp0 ( alg_value, algorithm_labels[HOTP] ) == 0 ) {
      /* Old-format HOTP keys were stored as hex or raw ASCII.
         Re-encode both to base32. */
      lerr = NULL;
      raw = hex_strtokey ( old_key, &raw_l, &lerr );
      if ( !lerr ) {
        /* hex string -> raw bytes -> base32. libcotp's base32_encode
           reads its input via strlen, so NUL-terminate the raw buffer
           (hex_strtokey allocates exactly raw_l bytes). */
        guint8 *raw_z = g_malloc ( raw_l + 1 );
        memcpy ( raw_z, raw, raw_l );
        raw_z[raw_l] = 0;
        g_free ( (gpointer)raw );
        berr = NO_ERROR;
        b32 = base32_encode ( raw_z, raw_l, &berr );
        g_free ( raw_z );
      } else {
        /* not hex: treat the stored string as raw ASCII bytes */
        g_error_free ( lerr );
        berr = NO_ERROR;
        b32 = base32_encode ( (const guint8*)old_key, strlen ( old_key ), &berr );
      }

      if ( b32 && berr == NO_ERROR ) {
        g_key_file_set_value ( self->key_file, names[i], KEY_KEY, b32 );
        g_key_file_set_value ( self->key_file, names[i],
                               KEY_KEY_TYPE, key_type_labels[BASE32] );
        self->modified = TRUE;
        free ( b32 );
      } else {
        /* Leave the key untouched; token_set_key will attempt its
           own conversion when the token is read. */
        if ( b32 ) free ( b32 );
      }
    } else {
      /* MOTP keys are stored as ASCII; just tag them. */
      g_key_file_set_value ( self->key_file, names[i],
                             KEY_KEY_TYPE, key_type_labels[ASCII] );
      self->modified = TRUE;
    }

    g_free ( alg_value );
    g_free ( old_key );
  }

  g_strfreev ( names );
}

