/*
    Mac-Telnet - Connect to RouterOS or mactelnetd devices via MAC address
    Copyright (C) 2022, Yandex <kmeaw@yandex-team.ru>
    Copyright (C) 2024, Google <kmeaw@google.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
/*
  Independent implementation of the Elliptic Curve Secure Remote Protocol
  (EC-SRP) key sharing and authentication protocol.

  This code implements the EC-SRP Algorithm defined in IEEE P1363.2 draft,
  whose text is available at
	https://web.archive.org/web/20131228182531/http://grouper.ieee.org/groups/1363/passwdPK/submissions/p1363ecsrp.pdf
  The code is derived from the text of the RFC and another PoC Python
  implementation from Margin Research
        https://github.com/MarginResearch/mikrotik_authentication
*/

#include "mtwei.h"
#include "config.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#if !defined(__FreeBSD__) && !defined(__APPLE__)
#include <sys/random.h>
#endif

#if !defined(HAVE_GETRANDOM) && defined(HAVE_ARC4RANDOM)
int getrandom(char *buf, size_t size, int flags) {
	arc4random_buf(buf, size);
	return size;
}
#endif

void
mtwei_init (mtwei_state_t *state)
{
    BIGNUM *a = NULL, *b = NULL, *gx = NULL, *gy = NULL;
    BIGNUM *cofactor = BN_new();
    state->order = NULL;

    state->ctx = BN_CTX_new();

    state->curve25519 = EC_GROUP_new(EC_GFp_simple_method());
    assert(state->curve25519 != NULL);

    state->g = EC_POINT_new(state->curve25519);
    assert(state->g != NULL);

    state->mod = NULL;
    BN_hex2bn(&state->mod, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
    BN_hex2bn(&a, "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144");
    BN_hex2bn(&b, "7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864");
    BN_hex2bn(&gx, "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a");
    BN_hex2bn(&gy, "5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14");
    BN_hex2bn(&state->order, "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
    BN_set_word(cofactor, 8);

    state->w2m = NULL;
    state->m2w = NULL;
    BN_hex2bn(&state->w2m, "555555555555555555555555555555555555555555555555555555555552db9c");
    BN_hex2bn(&state->m2w, "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad2451");

    EC_GROUP_set_curve_GFp(state->curve25519, state->mod, a, b, 0);
    EC_POINT_set_affine_coordinates_GFp(state->curve25519, state->g, gx, gy, 0);
    EC_GROUP_set_generator(state->curve25519, state->g, state->order, cofactor);
}

static BIGNUM*
tangle (mtwei_state_t *state, EC_POINT *target, uint8_t *validator, int negate)
{
    EC_POINT *validator_pt = EC_POINT_new(state->curve25519);
    BIGNUM *v = BN_bin2bn(validator, 32, NULL);
    EC_POINT_mul(state->curve25519, validator_pt, NULL, state->g, v, state->ctx);
    BIGNUM *vpub_x = BN_new();

    unsigned char buf_out[32];
    EC_POINT_get_affine_coordinates_GFp(state->curve25519, validator_pt, vpub_x, NULL, NULL);
    BN_mod_add(vpub_x, vpub_x, state->w2m, state->mod, state->ctx);
    BN_bn2binpad(vpub_x, buf_out, 32);
    SHA256_CTX keys;
    SHA256_Init(&keys);
    SHA256_Update(&keys, buf_out, 32);
    SHA256_Final(buf_out, &keys);

    BIGNUM *edpx = BN_bin2bn(buf_out, 32, NULL);
    BIGNUM *edpxm = BN_new();

    while (1) {
        SHA256_Init(&keys);
        BN_bn2binpad(edpx, buf_out, 32);
        SHA256_Update(&keys, buf_out, 32);
        SHA256_Final(buf_out, &keys);
        BN_bin2bn(buf_out, 32, edpxm);
        BN_mod_add(edpxm, edpxm, state->m2w, state->mod, state->ctx);
        if (EC_POINT_set_compressed_coordinates(state->curve25519, validator_pt, edpxm, negate, state->ctx) == 1) break;
        BN_add_word(edpx, 1);
    }

    if (!EC_POINT_add(state->curve25519, target, target, validator_pt, state->ctx)) {
        fprintf(stderr, "Cannot mix gamma into pubkey: %s\n", ERR_error_string(ERR_get_error(), NULL));
        abort();
    }

    return v;
}

BIGNUM*
mtwei_keygen (mtwei_state_t *state, uint8_t *pubkey_out, uint8_t *validator)
{
    uint8_t client_priv[32];
    EC_POINT *pubkey = EC_POINT_new(state->curve25519);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    if (getrandom (client_priv, sizeof(client_priv), 0) != sizeof(client_priv))
    {
        perror ("getrandom");
        abort ();
    }
    client_priv[0] &= 248;
    client_priv[31] &= 127;
    client_priv[31] |= 64;

    BIGNUM *privkey = BN_bin2bn(client_priv, sizeof(client_priv), NULL);
    if (!EC_POINT_mul(state->curve25519, pubkey, NULL, state->g, privkey, state->ctx)) {
        fprintf(stderr, "Cannot make a public key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        abort();
    }

    if (validator != NULL) {
        tangle(state, pubkey, validator, 0);
    }

    EC_POINT_get_affine_coordinates_GFp(state->curve25519, pubkey, x, y, NULL);
    BN_mod_add(x, x, state->w2m, state->mod, state->ctx);
    BN_bn2binpad(x, pubkey_out, 32);
    pubkey_out[32] = BN_is_odd(y) ? 1 : 0;

    return privkey;
}

void
mtwei_id(const char *username, const char *password, const unsigned char *salt, uint8_t *validator_out)
{
    SHA256_CTX v, v1;
    SHA256_Init(&v1);
    SHA256_Update(&v1, username, strlen(username));
    SHA256_Update(&v1, ":", 1);
    SHA256_Update(&v1, password, strlen(password));
    SHA256_Final(validator_out, &v1);

    SHA256_Init(&v);
    SHA256_Update(&v, salt, 16);
    SHA256_Update(&v, validator_out, SHA256_DIGEST_LENGTH);
    SHA256_Final(validator_out, &v);
}

void
mtwei_docrypto(mtwei_state_t *state, BIGNUM *privkey, const uint8_t *server_key, const uint8_t *client_key, uint8_t *validator, uint8_t *buf_out)
{
    EC_POINT *pub = EC_POINT_new(state->curve25519);
    EC_POINT_mul(state->curve25519, pub, NULL, state->g, privkey, state->ctx);

    EC_POINT *server_pubkey = EC_POINT_new(state->curve25519);
    BIGNUM *server_pubkey_x = BN_bin2bn(server_key, 32, NULL);
    BN_mod_add(server_pubkey_x, server_pubkey_x, state->m2w, state->mod, state->ctx);
    if (EC_POINT_set_compressed_coordinates(state->curve25519, server_pubkey, server_pubkey_x, server_key[32], state->ctx) != 1)
    {
        fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
        abort();
    }

    SHA256_CTX keys;
    BIGNUM *v = tangle (state, server_pubkey, validator, 1);

    SHA256_Init(&keys);
    SHA256_Update(&keys, client_key, 32);
    SHA256_Update(&keys, server_key, 32);
    SHA256_Final(buf_out, &keys);

    BIGNUM *vh = BN_bin2bn(buf_out, 32, NULL);

    BN_mod_mul(vh, v, vh, state->order, state->ctx);
    BN_mod_add(vh, vh, privkey, state->order, state->ctx);

    EC_POINT *pt = EC_POINT_new(state->curve25519);
    EC_POINT_mul(state->curve25519, pt, NULL, server_pubkey, vh, state->ctx);

    BIGNUM *pt_x = BN_new();
    EC_POINT_get_affine_coordinates_GFp(state->curve25519, pt, pt_x, NULL, NULL);

    BIGNUM *z_input = BN_new();
    BN_mod_add(z_input, pt_x, state->w2m, state->mod, state->ctx);

    SHA256_Init(&keys);
    SHA256_Update(&keys, buf_out, 32);
    BN_bn2binpad(z_input, buf_out, 32);
    SHA256_Update(&keys, buf_out, 32);
    SHA256_Final(buf_out, &keys);
}

void
mtwei_docryptos(mtwei_state_t *state, BIGNUM *privkey, const uint8_t *client_key, const uint8_t *server_key, uint8_t *validator, uint8_t *buf_out)
{
    EC_POINT *pub = EC_POINT_new(state->curve25519);
    EC_POINT_mul(state->curve25519, pub, NULL, state->g, privkey, state->ctx);

    EC_POINT *client_pubkey = EC_POINT_new(state->curve25519);
    BIGNUM *client_pubkey_x = BN_bin2bn(client_key, 32, NULL);
    BN_mod_add(client_pubkey_x, client_pubkey_x, state->m2w, state->mod, state->ctx);
    if (EC_POINT_set_compressed_coordinates(state->curve25519, client_pubkey, client_pubkey_x, client_key[32], state->ctx) != 1)
    {
        fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
        abort();
    }

    SHA256_CTX keys;
    BIGNUM *v = BN_bin2bn(validator, 32, NULL);

    SHA256_Init(&keys);
    SHA256_Update(&keys, client_key, 32);
    SHA256_Update(&keys, server_key, 32);
    SHA256_Final(buf_out, &keys);

    EC_POINT *validator_pt = EC_POINT_new(state->curve25519);
    EC_POINT_mul(state->curve25519, validator_pt, NULL, state->g, v, state->ctx);

    BIGNUM *h = BN_bin2bn(buf_out, 32, NULL);
    EC_POINT *hv = EC_POINT_new(state->curve25519);

    EC_POINT_mul(state->curve25519, hv, NULL, validator_pt, h, state->ctx);
    EC_POINT_add(state->curve25519, client_pubkey, client_pubkey, hv, state->ctx);

    EC_POINT *pt = EC_POINT_new(state->curve25519);
    EC_POINT_mul(state->curve25519, pt, NULL, client_pubkey, privkey, state->ctx);

    BIGNUM *pt_x = BN_new();
    EC_POINT_get_affine_coordinates_GFp(state->curve25519, pt, pt_x, NULL, NULL);

    BIGNUM *z_input = BN_new();
    BN_mod_add(z_input, pt_x, state->w2m, state->mod, state->ctx);

    SHA256_Init(&keys);
    SHA256_Update(&keys, buf_out, 32);
    BN_bn2binpad(z_input, buf_out, 32);
    SHA256_Update(&keys, buf_out, 32);
    SHA256_Final(buf_out, &keys);
}
