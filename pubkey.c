/*
    This file is part of telegram-purple

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA

    Copyright Ben Wiederhake 2015
*/

#include <assert.h> /* FIXME: Remove in release? */
#include <stdlib.h> /* malloc, free */
#include <stdio.h>
#include <string.h> /* memcmp */

#define LTC_MRSA
#include <tomcrypt.h>
#include <tomcrypt_pk.h>

#include "pubkey.h"

#ifndef PUBKEY_USE_MAX_MOD_LEN
/* Support up to 8192-bit RSA. This is over-overkill. */
#define PUBKEY_USE_MAX_MOD_LEN 1024
#endif

#ifndef PUBKEY_USE_MAX_FILE_LEN
/* Support files of size up to 2K. This is over-overkill. */
#define PUBKEY_USE_MAX_FILE_LEN 2048
#endif

struct pubkey_data {
  unsigned int exponent;
  unsigned int modulus_length;
  unsigned char modulus[PUBKEY_USE_MAX_MOD_LEN];
};

/* == Read == */

pubkey_error_code pubkey_from_file (const char *filename, pubkey_data **dst) {
  FILE *fp = fopen (filename, "rb");
  if (!fp) {
    return pubkey_ec_io_error;
  }

  char buf[PUBKEY_USE_MAX_FILE_LEN];
  size_t actual_size = fread (buf, 1, PUBKEY_USE_MAX_FILE_LEN, fp);
  if (!feof (fp)) {
    fclose (fp);
    return pubkey_ec_too_large;
  }
  /* Ignore if an error occurred during fread(), we'll detect it during the next step anyway. */
  fclose (fp);

  return pubkey_from_guarded (buf, actual_size, dst);
}

pubkey_error_code pubkey_from_guarded (char *const data, const size_t length, pubkey_data **dst) {
  const char expect_begin_guard[] = "-----BEGIN RSA PUBLIC KEY-----\n";
  unsigned int expect_begin_guard_len = sizeof (expect_begin_guard) - 1 /* NUL */;
  assert (31 == expect_begin_guard_len);
  const char expect_end_guard[] = "-----END RSA PUBLIC KEY-----\n";
  unsigned int expect_end_guard_len = sizeof (expect_end_guard) - 1 /* NUL */;
  assert (29 == expect_end_guard_len);

  /* == Expect the 'begin' guard == */
  if (length <= 2 * expect_begin_guard_len || length > PUBKEY_USE_MAX_FILE_LEN) {
    /* The rounding errors have the effect that we require pubkeys of length at least 4 bytes. */
    return pubkey_ec_too_large;
  }
  if (memcmp (expect_begin_guard, data, expect_begin_guard_len)) {
    return pubkey_ec_corrupt;
  }

  /* == Extract actual content, strip newlines == */
  /* Points to the first unprocessed byte. */
  char *in = data + expect_begin_guard_len;
  /* Points to the first "undefined" byte. */
  char *out = data;
  int had_equals = 0;
  int is_newline = 0; // Disallow empty RSA key.
  int end = 0;
  while (!end) {
    /* Could end earlier, but I'm too lazy for that. */
    if (in + 1 > data + length) {
      return pubkey_ec_corrupt;
    }
    switch (*in) {
    case '=':
      had_equals = 1;
      is_newline = 0;
      *out = *in; // Copy
      ++out;
      break;
    case '\n':
      /* MAYBE BAD IDEA: Ignores the position or existence of newlines. Note that:
       * - The de-base64-ing will either completely corrupt the data stream or cause superfluous or missing bytes.
       * - The underlying ASN.1 should be checking for superfluous or missing bytes.
       * So we have pretty high standards. Why is there no clear definition of PEM? */
      is_newline = 1;
      if (had_equals) {
        /* The NEXT char is the end. */
        ++in;
        end = 1;
      }
      break;
    case '-':
      if (!is_newline) {
        return pubkey_ec_corrupt;
      }
      end = 1;
      break;
    default:
      /* Only very rough filtering, since the actual base64 decoder will do the real thing. */
      if (*in < 3) {
        return pubkey_ec_corrupt;
      }
      *out = *in; // Copy
      ++out;
    }
    if (!end) {
      ++in;
    }
  }

  /* == Expect 'end' guard == */
  /*
   * "sizeof(expect_begin_guard) + in" points to the first byte we will ignore
   * "data + length" points to the first byte after the given buffer ('data')
   */
  if (expect_end_guard_len + in != data + length) {
    /* Sizes mismatch: We would either read beyong end, or ignore trailing bytes. */
    return pubkey_ec_corrupt;
  }
  if (memcmp (expect_end_guard, in, expect_end_guard_len)) {
    return pubkey_ec_corrupt;
  }

  /* == Accepted! == */
  *out = 0; // NUL termination for NSS.
  //data[length] = 0;
  return pubkey_from_base64 (data, dst);
}

pubkey_error_code pubkey_from_base64 (const char *pubkstr, pubkey_data **dst) {
  // FIXME: Decode base64, then:

  // FIXME: Init libtomcrypt; currently fails LTC_ARGCHK(ltc_mp.name != NULL);

  rsa_key key;
  int res = rsa_import(buf, actual_size, &key);
  assert (res);

  // Code verbatim from nss solution:

  if (!ec) {
    assert(*dst);
    (*dst)->exponent = 0;
    const unsigned int e_len = pubkey->u.rsa.publicExponent.len;
    for (unsigned int i = 0; i < e_len; ++i) {
      (*dst)->exponent <<= 8;
      (*dst)->exponent |= pubkey->u.rsa.publicExponent.data[i];
    }
    const unsigned int m_len = pubkey->u.rsa.modulus.len;
    assert (m_len <= PUBKEY_USE_MAX_MOD_LEN);
    (*dst)->modulus_length = m_len;
    memcpy ((*dst)->modulus, pubkey->u.rsa.modulus.data, m_len);
  }

  if (pubkey) {
    SECKEY_DestroyPublicKey (pubkey);
  }
  assert (slot);
  PK11_FreeSlot (slot);

  return ec;
}

/* == Access == */

unsigned int pubkey_get_exponent (const pubkey_data *pubkey) {
  return pubkey->exponent;
}

unsigned int pubkey_get_modulus_length (const pubkey_data *pubkey) {
  return pubkey->modulus_length;
}

const unsigned char* pubkey_get_modulus (const pubkey_data *pubkey) {
  return pubkey->modulus;
}

/* == Destruction == */

void pubkey_free (pubkey_data *pubkey) {
  free (pubkey);
}
