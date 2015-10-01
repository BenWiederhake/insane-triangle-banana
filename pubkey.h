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

#ifndef __PUBKEY_H__
#define __PUBKEY_H__

#include <stdlib.h> /* size_t */

typedef struct pubkey_data pubkey_data;

/* == Error codes == */

typedef enum pubkey_error_code {
  pubkey_ec_ok = 0,
  pubkey_ec_io_error = 1, // Can only be returned from 'pubkey_from_file'
  pubkey_ec_too_large = 2,
  pubkey_ec_corrupt = 3,
  pubkey_ec_nss_internal = 4,
} pubkey_error_code;

/* == Read == */

/* Reads a RSA pubkey from a PEM-encoded file, beginning with "-----BEGIN RSA PUBLIC KEY-----". If you're unsure what you need, this function is probably it. */
pubkey_error_code pubkey_from_file (const char *filename, pubkey_data **dst);

/* Destructively reads a RSA pubkey from a PEM-encoded chunk of data, beginning with "-----BEGIN RSA PUBLIC KEY-----" */
pubkey_error_code pubkey_from_guarded (char *data, size_t length, pubkey_data **dst);

/* Reads a RSA pubkey from a NUL terminated, PEM-encoded chunk of data, with ASCII guards and newlines removed (raw base64 data). */
pubkey_error_code pubkey_from_base64 (const char *data, pubkey_data **dst);

/* == Access == */

unsigned int pubkey_get_exponent (const pubkey_data *pubkey);

unsigned int pubkey_get_modulus_length (const pubkey_data *pubkey);

const unsigned char* pubkey_get_modulus (const pubkey_data *pubkey);

/* == Destruction == */

/* Note that there is no need to operate "securely" by overwriting anything with zeros since we're handling a PUBLIC key here. */

void pubkey_free (pubkey_data *pubkey);

#endif
