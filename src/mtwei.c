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
#if defined(__linux__)
#include <linux/random.h>
#endif

#if !defined(HAVE_GETRANDOM) && defined(HAVE_ARC4RANDOM)
int getrandom(char *buf, size_t size, int flags) {
	arc4random_buf(buf, size);
	return size;
}
#endif

// assert, output message to stderr, and jump to abort label for cleanup
#define assertjmp(exp) do { if (!(exp)) { fprintf(stderr, "assertion failed: %s", #exp); goto abort; } } while (0)

void mtwei_init(mtwei_state_t *state) {
	BIGNUM *a = NULL, *b = NULL, *gx = NULL, *gy = NULL;
	BIGNUM *cofactor = BN_new();
	assertjmp(cofactor != NULL);

	state->ctx = BN_CTX_new();
	assertjmp(state->ctx != NULL);

	state->curve25519 = EC_GROUP_new(EC_GFp_simple_method());
	assertjmp(state->curve25519 != NULL);

	state->g = EC_POINT_new(state->curve25519);
	assertjmp(state->g != NULL);

	state->mod = NULL;
	BN_hex2bn(&state->mod, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
	assertjmp(state->mod != NULL);
 
	BN_hex2bn(&a, "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144");
	assertjmp(a != NULL);
 
	BN_hex2bn(&b, "7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864");
	assertjmp(b != NULL);
 
	BN_hex2bn(&gx, "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a");
	assertjmp(gx != NULL);
 
	BN_hex2bn(&gy, "5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14");
	assertjmp(gy != NULL);
 
	state->order = NULL;
	BN_hex2bn(&state->order, "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
	assertjmp(state->order != NULL);

	BN_set_word(cofactor, 8);

	state->w2m = NULL;
	state->m2w = NULL;
	BN_hex2bn(&state->w2m, "555555555555555555555555555555555555555555555555555555555552db9c");
	assertjmp(state->w2m != NULL);
	BN_hex2bn(&state->m2w, "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad2451");
	assertjmp(state->m2w != NULL);

	EC_GROUP_set_curve_GFp(state->curve25519, state->mod, a, b, 0);
	EC_POINT_set_affine_coordinates_GFp(state->curve25519, state->g, gx, gy, 0);
	EC_GROUP_set_generator(state->curve25519, state->g, state->order, cofactor);

	BN_clear_free(a);
	BN_clear_free(b);
	BN_clear_free(gx);
	BN_clear_free(gy);
	BN_clear_free(cofactor);

	return;

	abort:
	if (cofactor != NULL) {
		BN_clear_free(cofactor);
	}
	if (state->ctx != NULL) {
		BN_CTX_free(state->ctx);
	}
	if (state->curve25519 != NULL) {
		EC_GROUP_clear_free(state->curve25519);
	}
	if (state->g != NULL) {
		EC_POINT_clear_free(state->g);
	}
	if (state->mod != NULL) {
		BN_clear_free(state->mod);
	}
	if (state->order != NULL) {
		BN_clear_free(state->order);
	}
	if (state->w2m != NULL) {
		BN_clear_free(state->w2m);
	}
	if (state->m2w != NULL) {
		BN_clear_free(state->m2w);
	}
	if (a != NULL) {
		BN_clear_free(a);
	}
	if (b != NULL) {
		BN_clear_free(b);
	}
	if (gx != NULL) {
		BN_clear_free(gx);
	}
	if (gy != NULL) {
		BN_clear_free(gy);
	}
	abort();
}

static BIGNUM* tangle(mtwei_state_t *state, EC_POINT *target, uint8_t *validator, int negate) {
	EC_POINT *validator_pt = EC_POINT_new(state->curve25519);
	assertjmp(validator_pt != NULL);
	BIGNUM *v = BN_bin2bn(validator, 32, NULL);
	EC_POINT_mul(state->curve25519, validator_pt, NULL, state->g, v, state->ctx);
	BIGNUM *vpub_x = BN_new();
	assertjmp(vpub_x != NULL);

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
	assertjmp(edpxm != NULL);

	while (1) {
		SHA256_Init(&keys);
		BN_bn2binpad(edpx, buf_out, 32);
		SHA256_Update(&keys, buf_out, 32);
		SHA256_Final(buf_out, &keys);
		BN_bin2bn(buf_out, 32, edpxm);
		BN_mod_add(edpxm, edpxm, state->m2w, state->mod, state->ctx);
		if (EC_POINT_set_compressed_coordinates(state->curve25519, validator_pt, edpxm, negate, state->ctx) == 1) {
			break;
		}
		BN_add_word(edpx, 1);
	}

	if (!EC_POINT_add(state->curve25519, target, target, validator_pt, state->ctx)) {
		fprintf(stderr, "Cannot mix gamma into pubkey: %s\n", ERR_error_string(ERR_get_error(), NULL));
		abort();
	}

	EC_POINT_clear_free(validator_pt);
	BN_clear_free(vpub_x);
	BN_clear_free(edpxm);

	return v;

	abort:
	if (validator_pt != NULL) {
		EC_POINT_clear_free(validator_pt);
	}
	if (vpub_x != NULL) {
		BN_clear_free(vpub_x);
	}
	if (edpxm != NULL) {
		BN_clear_free(edpxm);
	}
	abort();
}

BIGNUM* mtwei_keygen(mtwei_state_t *state, uint8_t *pubkey_out, uint8_t *validator) {
	uint8_t client_priv[32];
	EC_POINT *pubkey = EC_POINT_new(state->curve25519);
	assertjmp(pubkey != NULL);

	BIGNUM *x = BN_new();
	assertjmp(x != NULL);
	BIGNUM *y = BN_new();
	assertjmp(y != NULL);

	if (getrandom (client_priv, sizeof(client_priv), 0) != sizeof(client_priv)) {
		perror ("getrandom");
		goto abort;
	}
	client_priv[0] &= 248;
	client_priv[31] &= 127;
	client_priv[31] |= 64;

	BIGNUM *privkey = BN_bin2bn(client_priv, sizeof(client_priv), NULL);
	assertjmp(privkey != NULL);
	if (!EC_POINT_mul(state->curve25519, pubkey, NULL, state->g, privkey, state->ctx)) {
		fprintf(stderr, "Cannot make a public key: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto abort;
	}

	if (validator != NULL) {
		tangle(state, pubkey, validator, 0);
	}

	EC_POINT_get_affine_coordinates_GFp(state->curve25519, pubkey, x, y, NULL);
	BN_mod_add(x, x, state->w2m, state->mod, state->ctx);
	BN_bn2binpad(x, pubkey_out, 32);
	pubkey_out[32] = BN_is_odd(y) ? 1 : 0;

	EC_POINT_clear_free(pubkey);
	BN_clear_free(x);
	BN_clear_free(y);

	return privkey;

	abort:
	if (pubkey != NULL) {
		EC_POINT_clear_free(pubkey);
	}
	if (x != NULL) {
		BN_clear_free(x);
	}
	if (y != NULL) {
		BN_clear_free(y);
	}
	if (privkey != NULL) {
		BN_clear_free(privkey);
	}
	abort();
}

void mtwei_id(const char *username, const char *password, const unsigned char *salt, uint8_t *validator_out) {
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

void mtwei_docrypto(mtwei_state_t *state, BIGNUM *privkey, const uint8_t *server_key, const uint8_t *client_key, uint8_t *validator, uint8_t *buf_out) {
	EC_POINT *pub = EC_POINT_new(state->curve25519);
	assertjmp(pub != NULL);
	EC_POINT_mul(state->curve25519, pub, NULL, state->g, privkey, state->ctx);

	EC_POINT *server_pubkey = EC_POINT_new(state->curve25519);
	assertjmp(server_pubkey != NULL);
	BIGNUM *server_pubkey_x = BN_bin2bn(server_key, 32, NULL);
	assertjmp(server_pubkey_x != NULL);
	BN_mod_add(server_pubkey_x, server_pubkey_x, state->m2w, state->mod, state->ctx);
	if (EC_POINT_set_compressed_coordinates(state->curve25519, server_pubkey, server_pubkey_x, server_key[32], state->ctx) != 1) {
		fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		goto abort;
	}

	SHA256_CTX keys;
	BIGNUM *v = tangle (state, server_pubkey, validator, 1);

	SHA256_Init(&keys);
	SHA256_Update(&keys, client_key, 32);
	SHA256_Update(&keys, server_key, 32);
	SHA256_Final(buf_out, &keys);

	BIGNUM *vh = BN_bin2bn(buf_out, 32, NULL);
	assertjmp(vh != NULL);

	BN_mod_mul(vh, v, vh, state->order, state->ctx);
	BN_mod_add(vh, vh, privkey, state->order, state->ctx);

	EC_POINT *pt = EC_POINT_new(state->curve25519);
	assertjmp(pt != NULL);
	EC_POINT_mul(state->curve25519, pt, NULL, server_pubkey, vh, state->ctx);

	BIGNUM *pt_x = BN_new();
	assertjmp(pt_x != NULL);
	EC_POINT_get_affine_coordinates_GFp(state->curve25519, pt, pt_x, NULL, NULL);

	BIGNUM *z_input = BN_new();
	assertjmp(z_input != NULL);
	BN_mod_add(z_input, pt_x, state->w2m, state->mod, state->ctx);

	SHA256_Init(&keys);
	SHA256_Update(&keys, buf_out, 32);
	BN_bn2binpad(z_input, buf_out, 32);
	SHA256_Update(&keys, buf_out, 32);
	SHA256_Final(buf_out, &keys);

	EC_POINT_clear_free(pub);
	EC_POINT_clear_free(server_pubkey);
	BN_clear_free(server_pubkey_x);
	BN_clear_free(v);
	BN_clear_free(vh);
	EC_POINT_clear_free(pt);
	BN_clear_free(pt_x);
	BN_clear_free(z_input);

	return;

	abort:
	if (pub != NULL) {
		EC_POINT_clear_free(pub);
	}
	if (server_pubkey != NULL) {
		EC_POINT_clear_free(server_pubkey);
	}
	if (server_pubkey_x != NULL) {
		BN_clear_free(server_pubkey_x);
	}
	if (v != NULL) {
		BN_clear_free(v);
	}
	if (vh != NULL) {
		BN_clear_free(vh);
	}
	if (pt != NULL) {
		EC_POINT_clear_free(pt);
	}
	if (pt_x != NULL) {
		BN_clear_free(pt_x);
	}
	if (z_input != NULL) {
		BN_clear_free(z_input);
	}
	abort();
}

void mtwei_docryptos(mtwei_state_t *state, BIGNUM *privkey, const uint8_t *client_key, const uint8_t *server_key, uint8_t *validator, uint8_t *buf_out) {
	EC_POINT *pub = EC_POINT_new(state->curve25519);
	assertjmp(pub != NULL);
	EC_POINT_mul(state->curve25519, pub, NULL, state->g, privkey, state->ctx);

	EC_POINT *client_pubkey = EC_POINT_new(state->curve25519);
	assertjmp(client_pubkey != NULL);
	BIGNUM *client_pubkey_x = BN_bin2bn(client_key, 32, NULL);
	assertjmp(client_pubkey_x != NULL);
	BN_mod_add(client_pubkey_x, client_pubkey_x, state->m2w, state->mod, state->ctx);
	if (EC_POINT_set_compressed_coordinates(state->curve25519, client_pubkey, client_pubkey_x, client_key[32], state->ctx) != 1) {
		fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		goto abort;
	}

	SHA256_CTX keys;
	BIGNUM *v = BN_bin2bn(validator, 32, NULL);
	assertjmp(v != NULL);

	SHA256_Init(&keys);
	SHA256_Update(&keys, client_key, 32);
	SHA256_Update(&keys, server_key, 32);
	SHA256_Final(buf_out, &keys);

	EC_POINT *validator_pt = EC_POINT_new(state->curve25519);
	assertjmp(validator_pt != NULL);
	EC_POINT_mul(state->curve25519, validator_pt, NULL, state->g, v, state->ctx);

	BIGNUM *h = BN_bin2bn(buf_out, 32, NULL);
	assertjmp(h != NULL);
	EC_POINT *hv = EC_POINT_new(state->curve25519);
	assertjmp(hv != NULL);

	EC_POINT_mul(state->curve25519, hv, NULL, validator_pt, h, state->ctx);
	EC_POINT_add(state->curve25519, client_pubkey, client_pubkey, hv, state->ctx);

	EC_POINT *pt = EC_POINT_new(state->curve25519);
	assertjmp(pt != NULL);
	EC_POINT_mul(state->curve25519, pt, NULL, client_pubkey, privkey, state->ctx);

	BIGNUM *pt_x = BN_new();
	assertjmp(pt_x != NULL);
	EC_POINT_get_affine_coordinates_GFp(state->curve25519, pt, pt_x, NULL, NULL);

	BIGNUM *z_input = BN_new();
	assertjmp(z_input != NULL);
	BN_mod_add(z_input, pt_x, state->w2m, state->mod, state->ctx);

	SHA256_Init(&keys);
	SHA256_Update(&keys, buf_out, 32);
	BN_bn2binpad(z_input, buf_out, 32);
	SHA256_Update(&keys, buf_out, 32);
	SHA256_Final(buf_out, &keys);

	EC_POINT_clear_free(pub);
	EC_POINT_clear_free(client_pubkey);
	BN_clear_free(client_pubkey_x);
	BN_clear_free(v);
	EC_POINT_clear_free(validator_pt);
	BN_clear_free(h);
	EC_POINT_clear_free(hv);
	EC_POINT_clear_free(pt);
	BN_clear_free(pt_x);
	BN_clear_free(z_input);

	return;

	abort:
	if (pub != NULL) {
		EC_POINT_clear_free(pub);
	}
	if (client_pubkey != NULL) {
		EC_POINT_clear_free(client_pubkey);
	}
	if (client_pubkey_x != NULL) {
		BN_clear_free(client_pubkey_x);
	}
	if (v != NULL) {
		BN_clear_free(v);
	}
	if (validator_pt != NULL) {
		EC_POINT_clear_free(validator_pt);
	}
	if (h != NULL) {
		BN_clear_free(h);
	}
	if (hv != NULL) {
		EC_POINT_clear_free(hv);
	}
	if (pt != NULL) {
		EC_POINT_clear_free(pt);
	}
	if (pt_x != NULL) {
		BN_clear_free(pt_x);
	}
	if (z_input != NULL) {
		BN_clear_free(z_input);
	}
	abort();
}
