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

#include <nss/nss.h>
#include <../nss.h> // outer
#include <nss/pk11pub.h>
#include <nss/base64.h>
#include <nss/keyhi.h>
#include <nss/keythi.h>
#include <nspr/prerror.h>
#include <nspr/plarenas.h>

#include <secerr.h>
#include <secasn1.h> /* for SEC_ASN1GetSubtemplate */
#include <secitem.h>

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

/* What the hell?
 * https://mxr.mozilla.org/security/source/security/nss/lib/cryptohi/seckey.c#1346 */
SECKEYPublicKey *my_SECKEY_DecodeDERPublicKey (SECItem *pubkder) {
  PRArenaPool *arena;
  SECKEYPublicKey *pubk;
  SECStatus rv;
  SECItem newPubkder;

  arena = PORT_NewArena (DER_DEFAULT_CHUNKSIZE);
  if (arena == NULL) {
    return NULL;
  }

  pubk = (SECKEYPublicKey *) PORT_ArenaZAlloc (arena, sizeof (SECKEYPublicKey));
  if (pubk != NULL) {
    pubk->arena = arena;
    pubk->pkcs11Slot = NULL;
    pubk->pkcs11ID = 0;
    pubk->u.rsa.modulus.type = siUnsignedInteger;
    pubk->u.rsa.publicExponent.type = siUnsignedInteger;
    /* copy the DER into the arena, since Quick DER returns data that points
    into the DER input, which may get freed by the caller */
    rv = SECITEM_CopyItem(arena, &newPubkder, pubkder);
    if ( rv == SECSuccess ) {
      rv = SEC_QuickDERDecodeItem(arena, pubk, SECKEY_RSAPublicKeyTemplate,&newPubkder);
    }

    if (rv == SECSuccess)
      return pubk;
    //SECKEY_DestroyPublicKey (pubk);
  }

  PORT_FreeArena (arena, PR_FALSE);
  return NULL;
}

pubkey_error_code pubkey_from_base64 (const char *pubkstr, pubkey_data **dst) {
  /* This is the ugly part. Inspired by https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/nss_sample_code/NSS_Sample_Code_sample5 */

  if (!NSS_IsInitialized ()) {
    if (SECSuccess != NSS_NoDB_Init (".")) {
      return pubkey_ec_nss_internal;
    }
  }

  PK11SlotInfo *slot = PK11_GetInternalKeySlot ();
  if (slot == NULL) {
    return pubkey_ec_nss_internal;
  }

  SECItem der;
  der.data = NULL;
  der.len = 0;
  der.type = 0;
  if (SECSuccess != ATOB_ConvertAsciiToItem (&der, pubkstr)) {
    PK11_FreeSlot(slot);
    return pubkey_ec_nss_internal;
  }

  SECKEYPublicKey *pubkey = my_SECKEY_DecodeDERPublicKey (&der);
  pubkey_error_code ec = pubkey_ec_ok;
  if (!pubkey) {
    ec = pubkey_ec_nss_internal;
  }
  SECITEM_FreeItem (&der, 0);
//  if (!ec && rsaKey != pubkey->keyType) {
//    ec = pubkey_ec_nss_internal;
//  }
  if (!ec && (siUnsignedInteger != pubkey->u.rsa.modulus.type)) {
    ec = pubkey_ec_nss_internal;
  }
  if (!ec && (siUnsignedInteger != pubkey->u.rsa.publicExponent.type)) {
    ec = pubkey_ec_nss_internal;
  }
  if (!ec && (PUBKEY_USE_MAX_MOD_LEN < pubkey->u.rsa.modulus.len)) {
    ec = pubkey_ec_too_large;
  }
  if (!ec && (4 < pubkey->u.rsa.publicExponent.len)) {
    ec = pubkey_ec_too_large;
  }

  *dst = NULL;
  if (!ec) {
    *dst = malloc (sizeof (pubkey_data));
    if (!*dst) {
      ec = pubkey_ec_nss_internal; // Lie.
    }
  }

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
