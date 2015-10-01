/* insane-triangle-banana Copyright (C) Ben Wiederhake 2015
 * Released to public domain.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Dependencies: libnss3-dev
 * Compile: gcc -o insane-triangle-banana insane-triangle-banana.c pubkey.c `pkg-config --cflags --libs nss`
 * Suggested options: -Wall -Wextra -pedantic
 * Run: ./insane-triangle-banana
 * (Need to put a "key.pub" PEM file in the current directory.)
 */

#include <stdio.h>

#include "pubkey.h"

int main() {
  pubkey_data *pubkey = NULL;
  pubkey_error_code ec = pubkey_from_file ("key.pub", &pubkey);
  if (ec) {
    printf ("Had error: %d\n", ec);
    exit (1);
  }

  const unsigned int m_len = pubkey_get_modulus_length (pubkey);
  printf ("Exponent: %d\nModulus (%d bytes):\n", pubkey_get_exponent (pubkey), m_len);

  const unsigned char *mod = pubkey_get_modulus (pubkey);
  for (unsigned int i = 0; i < m_len; ++i) {
    if (0 == (i % 32)) {
      printf ("\n");
    }
    printf ("%02x", mod[i]);
  }
  printf ("\nDone.\n");

  return 0;
}
