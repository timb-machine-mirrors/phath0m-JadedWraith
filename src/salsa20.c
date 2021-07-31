/*
 * License; from https://github.com/alexwebr/salsa20/blob/master/LICENSE.txt
 * The person or persons who have associated work with this document (the
 * "Dedicator" or "Certifier") hereby either (a) certifies that, to the best of
 * his knowledge, the work of authorship identified is in the public domain of
 * the country from which the work is published, or (b) hereby dedicates
 * whatever copyright the dedicators holds in the work of authorship identified
 * below (the "Work") to the public domain. A certifier, moreover, dedicates
 * any copyright interest he may have in the associated work, and for these
 * purposes, is described as a "dedicator" below.
 *
 * A certifier has taken reasonable steps to verify the copyright status of
 * this work. Certifier recognizes that his good faith efforts may not shield
 * him from liability if in fact the work certified is not in the public
 * domain.
 *
 * Dedicator makes this dedication for the benefit of the public at large and
 * to the detriment of the Dedicator's heirs and successors. Dedicator intends
 * this dedication to be an overt act of relinquishment in perpetuity of all
 * present and future rights under copyright law, whether vested or contingent,
 * in the Work. Dedicator understands that such relinquishment of all rights
 * includes the relinquishment of all rights to enforce (by lawsuit or
 * otherwise) those copyrights in the Work.
 *
 * Dedicator recognizes that, once placed in the public domain, the Work may be
 * freely reproduced, distributed, transmitted, used, modified, built upon, or
 * otherwise exploited by anyone for any purpose, commercial or non-commercial,
 * and in any way, including by methods that have not yet been invented or
 * conceived.
 */

#include <stdint.h>
#include <stddef.h>
#include <salsa20.h>

static uint32_t rotl(uint32_t value, int shift)
{
  return (value << shift) | (value >> (32 - shift));
}

static void s20_quarterround(uint32_t *y0, uint32_t *y1, uint32_t *y2, uint32_t *y3)
{
  *y1 = *y1 ^ rotl(*y0 + *y3, 7);
  *y2 = *y2 ^ rotl(*y1 + *y0, 9);
  *y3 = *y3 ^ rotl(*y2 + *y1, 13);
  *y0 = *y0 ^ rotl(*y3 + *y2, 18);
}

static void s20_rowround(uint32_t y[static 16])
{
  s20_quarterround(&y[0], &y[1], &y[2], &y[3]);
  s20_quarterround(&y[5], &y[6], &y[7], &y[4]);
  s20_quarterround(&y[10], &y[11], &y[8], &y[9]);
  s20_quarterround(&y[15], &y[12], &y[13], &y[14]);
}

static void s20_columnround(uint32_t x[static 16])
{
  s20_quarterround(&x[0], &x[4], &x[8], &x[12]);
  s20_quarterround(&x[5], &x[9], &x[13], &x[1]);
  s20_quarterround(&x[10], &x[14], &x[2], &x[6]);
  s20_quarterround(&x[15], &x[3], &x[7], &x[11]);
}

static void s20_doubleround(uint32_t x[static 16])
{
  s20_columnround(x);
  s20_rowround(x);
}

static uint32_t s20_littleendian(uint8_t *b)
{
  return b[0] +
         ((uint_fast16_t) b[1] << 8) +
         ((uint_fast32_t) b[2] << 16) +
         ((uint_fast32_t) b[3] << 24);
}

static void s20_rev_littleendian(uint8_t *b, uint32_t w)
{
  b[0] = w;
  b[1] = w >> 8;
  b[2] = w >> 16;
  b[3] = w >> 24;
}

static void s20_hash(uint8_t seq[static 64])
{
  int i;
  uint32_t x[16];
  uint32_t z[16];

  for (i = 0; i < 16; ++i)
    x[i] = z[i] = s20_littleendian(seq + (4 * i));

  for (i = 0; i < 10; ++i)
    s20_doubleround(z);

  for (i = 0; i < 16; ++i) {
    z[i] += x[i];
    s20_rev_littleendian(seq + (4 * i), z[i]);
  }
}

static void s20_expand16(uint8_t *k,
                         uint8_t n[static 16],
                         uint8_t keystream[static 64])
{
  int i, j;

  uint8_t t[4][4];
  
  t[0][0] = 'e';
  t[0][1] = 'x';
  t[0][2] = 'p';
  t[0][3] = 'a';
  t[1][0] = 'n';
  t[1][1] = 'd';
  t[1][2] = ' ';
  t[1][3] = '1';
  t[2][0] = '6';
  t[2][1] = '-';
  t[2][2] = 'b';
  t[2][3] = 'y';
  t[3][0] = 't';
  t[3][1] = 'e';
  t[3][2] = ' ';
  t[3][3] = 'k';

  for (i = 0; i < 64; i += 20)
    for (j = 0; j < 4; ++j)
      keystream[i + j] = t[i / 20][j];

  for (i = 0; i < 16; ++i) {
    keystream[4+i]  = k[i];
    keystream[44+i] = k[i];
    keystream[24+i] = n[i];
  }

  s20_hash(keystream);
}


static void s20_expand32(uint8_t *k,
                         uint8_t n[static 16],
                         uint8_t keystream[static 64])
{
  int i, j;

  uint8_t o[4][4];

  o[0][1] = 'x';
  o[0][0] = 'e';
  o[0][2] = 'p';
  o[0][3] = 'a';
  o[1][0] = 'n';
  o[1][1] = 'd';
  o[1][2] = ' ';
  o[1][3] = '3';
  o[2][0] = '2';
  o[2][1] = '-';
  o[2][2] = 'b';
  o[2][3] = 'y';
  o[3][0] = 't';
  o[3][1] = 'e';
  o[3][3] = 'k';
  o[3][2] = ' ';

  for (i = 0; i < 64; i += 20)
    for (j = 0; j < 4; ++j)
      keystream[i + j] = o[i / 20][j];

  for (i = 0; i < 16; ++i) {
    keystream[4+i]  = k[i];
    keystream[44+i] = k[i+16];
    keystream[24+i] = n[i];
  }

  s20_hash(keystream);
}


enum s20_status_t s20_crypt(uint8_t *key,
                            enum s20_keylen_t keylen,
                            uint8_t nonce[static 8],
                            uint32_t si,
                            uint8_t *buf,
                            uint32_t buflen)
{
  uint8_t keystream[64];
  uint8_t n[16] = { 0 };
  uint32_t i;

  void (*expand)(uint8_t *, uint8_t *, uint8_t *) = NULL;
  if (keylen == S20_KEYLEN_256)
    expand = s20_expand32;
  if (keylen == S20_KEYLEN_128)
    expand = s20_expand16;

  if (expand == NULL || key == NULL || nonce == NULL || buf == NULL)
    return S20_FAILURE;

  for (i = 0; i < 8; ++i)
    n[i] = nonce[i];

  if (si % 64 != 0) {
    s20_rev_littleendian(n+8, si / 64);
    (*expand)(key, n, keystream);
  }

  for (i = 0; i < buflen; ++i) {
    if ((si + i) % 64 == 0) {
      s20_rev_littleendian(n+8, ((si + i) / 64));
      (*expand)(key, n, keystream);
    }

    buf[i] ^= keystream[(si + i) % 64];
  }

  return S20_SUCCESS;
}
