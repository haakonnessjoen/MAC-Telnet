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
#include <libintl.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

#define _(STRING) gettext(STRING)

#if !defined(HAVE_GETRANDOM) && defined(HAVE_ARC4RANDOM)
int getrandom(char *buf, size_t size, int flags) {
	arc4random_buf(buf, size);
	return size;
}
#endif

// assert, output message to stderr, and jump to abort label for cleanup
#define CHECKNULL(exp)                                                                                           \
	do {                                                                                                         \
		if ((exp) == 0) {                                                                                        \
			fprintf(stderr, _("FATAL ERROR: Function returned NULL at %s:%d: %s;\n"), __FILE__, __LINE__, #exp); \
			goto abort;                                                                                          \
		}                                                                                                        \
	} while (0)

void mtwei_init(mtwei_state_t *state) {
	BIGNUM *a = NULL, *b = NULL, *gx = NULL, *gy = NULL;
	BIGNUM *cofactor = NULL;

	CHECKNULL(cofactor = BN_new());
	CHECKNULL(state->ctx = BN_CTX_new());

	state->mod = NULL;
	CHECKNULL(BN_hex2bn(&state->mod, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"));

	CHECKNULL(BN_hex2bn(&a, "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144"));
	CHECKNULL(BN_hex2bn(&b, "7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864"));
	CHECKNULL(BN_hex2bn(&gx, "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a"));
	CHECKNULL(BN_hex2bn(&gy, "5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14"));

#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
	CHECKNULL(state->curve25519 = EC_GROUP_new_curve_GFp(state->mod, a, b, 0));
#else
	CHECKNULL(state->curve25519 = EC_GROUP_new(EC_GFp_simple_method()));
#endif
	CHECKNULL(state->g = EC_POINT_new(state->curve25519));

	CHECKNULL(state->order = BN_new());
	CHECKNULL(BN_hex2bn(&state->order, "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"));

	BN_set_word(cofactor, 8);
	state->w2m = NULL;
	state->m2w = NULL;
	CHECKNULL(BN_hex2bn(&state->w2m, "555555555555555555555555555555555555555555555555555555555552db9c"));
	CHECKNULL(BN_hex2bn(&state->m2w, "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad2451"));

#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
	CHECKNULL(EC_POINT_set_affine_coordinates(state->curve25519, state->g, gx, gy, 0));
#else
	CHECKNULL(EC_GROUP_set_curve_GFp(state->curve25519, state->mod, a, b, 0));
	CHECKNULL(EC_POINT_set_affine_coordinates_GFp(state->curve25519, state->g, gx, gy, 0));
#endif
	CHECKNULL(EC_GROUP_set_generator(state->curve25519, state->g, state->order, cofactor));

	BN_clear_free(a);
	BN_clear_free(b);
	BN_clear_free(gx);
	BN_clear_free(gy);
	BN_clear_free(cofactor);

	return;

abort:
	BN_clear_free(cofactor);
	BN_CTX_free(state->ctx);
#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
	EC_GROUP_free(state->curve25519);
#else
	EC_GROUP_clear_free(state->curve25519);
#endif
	EC_POINT_clear_free(state->g);
	BN_clear_free(state->mod);
	BN_clear_free(state->order);
	BN_clear_free(state->w2m);
	BN_clear_free(state->m2w);
	BN_clear_free(a);
	BN_clear_free(b);
	BN_clear_free(gx);
	BN_clear_free(gy);
	abort();
}

static BIGNUM *tangle(mtwei_state_t *state, EC_POINT *target, uint8_t *validator, int negate) {
	EC_POINT *validator_pt = NULL;
	BIGNUM *v = NULL, *vpub_x = NULL, *edpx = NULL, *edpxm = NULL;

	CHECKNULL(validator_pt = EC_POINT_new(state->curve25519));

	CHECKNULL(v = BN_bin2bn(validator, 32, NULL));
	EC_POINT_mul(state->curve25519, validator_pt, NULL, state->g, v, state->ctx);

	CHECKNULL(vpub_x = BN_new());

	unsigned char buf_out[32];
#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
	EC_POINT_get_affine_coordinates(state->curve25519, validator_pt, vpub_x, NULL, NULL);
#else
	EC_POINT_get_affine_coordinates_GFp(state->curve25519, validator_pt, vpub_x, NULL, NULL);
#endif
	BN_mod_add(vpub_x, vpub_x, state->w2m, state->mod, state->ctx);
	BN_bn2binpad(vpub_x, buf_out, 32);

#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
	EVP_Digest(buf_out, 32, buf_out, NULL, EVP_sha256(), NULL);
#else
	SHA256_CTX keys;
	SHA256_Init(&keys);
	SHA256_Update(&keys, buf_out, 32);
	SHA256_Final(buf_out, &keys);
#endif

	CHECKNULL(edpx = BN_bin2bn(buf_out, 32, NULL));
	CHECKNULL(edpxm = BN_new());

	while (1) {
		BN_bn2binpad(edpx, buf_out, 32);
#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
		EVP_Digest(buf_out, 32, buf_out, NULL, EVP_sha256(), NULL);
#else
		SHA256_Init(&keys);
		SHA256_Update(&keys, buf_out, 32);
		SHA256_Final(buf_out, &keys);
#endif
		BN_bin2bn(buf_out, 32, edpxm);
		BN_mod_add(edpxm, edpxm, state->m2w, state->mod, state->ctx);
		if (EC_POINT_set_compressed_coordinates(state->curve25519, validator_pt, edpxm, negate, state->ctx) == 1) {
			break;
		}
		BN_add_word(edpx, 1);
	}

	if (!EC_POINT_add(state->curve25519, target, target, validator_pt, state->ctx)) {
		fprintf(stderr, _("Cannot mix gamma into pubkey: %s\n"), ERR_error_string(ERR_get_error(), NULL));
		abort();
	}

	EC_POINT_clear_free(validator_pt);
	BN_clear_free(vpub_x);
	BN_clear_free(edpxm);

	return v;

abort:
	EC_POINT_clear_free(validator_pt);
	BN_clear_free(vpub_x);
	BN_clear_free(edpx);
	BN_clear_free(edpxm);
	abort();
}

BIGNUM *mtwei_keygen(mtwei_state_t *state, uint8_t *pubkey_out, uint8_t *validator) {
	uint8_t client_priv[32];
	EC_POINT *pubkey = NULL;
	BIGNUM *x = NULL, *y = NULL, *privkey = NULL;

	CHECKNULL(pubkey = EC_POINT_new(state->curve25519));

	CHECKNULL(x = BN_new());
	CHECKNULL(y = BN_new());

	if (getrandom((char *)client_priv, sizeof(client_priv), 0) != sizeof(client_priv)) {
		perror("getrandom");
		goto abort;
	}
	client_priv[0] &= 248;
	client_priv[31] &= 127;
	client_priv[31] |= 64;

	CHECKNULL(privkey = BN_bin2bn(client_priv, sizeof(client_priv), NULL));
	if (!EC_POINT_mul(state->curve25519, pubkey, NULL, state->g, privkey, state->ctx)) {
		fprintf(stderr, _("Cannot make a public key: %s\n"), ERR_error_string(ERR_get_error(), NULL));
		goto abort;
	}

	if (validator != NULL) {
		CHECKNULL(tangle(state, pubkey, validator, 0));
	}

#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
	EC_POINT_get_affine_coordinates(state->curve25519, pubkey, x, y, NULL);
#else
	EC_POINT_get_affine_coordinates_GFp(state->curve25519, pubkey, x, y, NULL);
#endif
	BN_mod_add(x, x, state->w2m, state->mod, state->ctx);
	BN_bn2binpad(x, pubkey_out, 32);
	pubkey_out[32] = BN_is_odd(y) ? 1 : 0;

	EC_POINT_clear_free(pubkey);
	BN_clear_free(x);
	BN_clear_free(y);

	return privkey;

abort:
	EC_POINT_clear_free(pubkey);
	BN_clear_free(x);
	BN_clear_free(y);
	BN_clear_free(privkey);
	abort();
}

void mtwei_id(const char *username, const char *password, const unsigned char *salt, uint8_t *validator_out) {
#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex2(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, username, strlen(username));
	EVP_DigestUpdate(mdctx, ":", 1);
	EVP_DigestUpdate(mdctx, password, strlen(password));
	EVP_DigestFinal_ex(mdctx, validator_out, NULL);

	EVP_DigestInit_ex2(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, salt, 16);
	EVP_DigestUpdate(mdctx, validator_out, SHA256_DIGEST_LENGTH);
	EVP_DigestFinal_ex(mdctx, validator_out, NULL);

	EVP_MD_CTX_free(mdctx);
#else
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
#endif
}

void mtwei_docrypto(mtwei_state_t *state, BIGNUM *privkey, const uint8_t *server_key, const uint8_t *client_key,
					uint8_t *validator, uint8_t *buf_out) {
	EC_POINT *pub = NULL, *server_pubkey = NULL, *pt = NULL;
	BIGNUM *server_pubkey_x = NULL, *v = NULL, *vh = NULL, *pt_x = NULL, *z_input = NULL;

	CHECKNULL(pub = EC_POINT_new(state->curve25519));
	EC_POINT_mul(state->curve25519, pub, NULL, state->g, privkey, state->ctx);

	CHECKNULL(server_pubkey = EC_POINT_new(state->curve25519));
	CHECKNULL(server_pubkey_x = BN_bin2bn(server_key, 32, NULL));
	BN_mod_add(server_pubkey_x, server_pubkey_x, state->m2w, state->mod, state->ctx);
	if (EC_POINT_set_compressed_coordinates(state->curve25519, server_pubkey, server_pubkey_x, server_key[32],
											state->ctx) != 1) {
		fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		goto abort;
	}

	SHA256_CTX keys;
	CHECKNULL(v = tangle(state, server_pubkey, validator, 1));

#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex2(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, client_key, 32);
	EVP_DigestUpdate(mdctx, server_key, 32);
	EVP_DigestFinal_ex(mdctx, buf_out, NULL);
	EVP_MD_CTX_free(mdctx);
#else
	SHA256_Init(&keys);
	SHA256_Update(&keys, client_key, 32);
	SHA256_Update(&keys, server_key, 32);
	SHA256_Final(buf_out, &keys);
#endif

	CHECKNULL(vh = BN_bin2bn(buf_out, 32, NULL));

	BN_mod_mul(vh, v, vh, state->order, state->ctx);
	BN_mod_add(vh, vh, privkey, state->order, state->ctx);

	CHECKNULL(pt = EC_POINT_new(state->curve25519));
	EC_POINT_mul(state->curve25519, pt, NULL, server_pubkey, vh, state->ctx);

	CHECKNULL(pt_x = BN_new());
#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
	EC_POINT_get_affine_coordinates(state->curve25519, pt, pt_x, NULL, NULL);
#else
	EC_POINT_get_affine_coordinates_GFp(state->curve25519, pt, pt_x, NULL, NULL);
#endif

	CHECKNULL(z_input = BN_new());
	BN_mod_add(z_input, pt_x, state->w2m, state->mod, state->ctx);

#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex2(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, buf_out, 32);
	BN_bn2binpad(z_input, buf_out, 32);
	EVP_DigestUpdate(mdctx, buf_out, 32);
	EVP_DigestFinal_ex(mdctx, buf_out, NULL);
	EVP_MD_CTX_free(mdctx);
#else
	SHA256_Init(&keys);
	SHA256_Update(&keys, buf_out, 32);
	BN_bn2binpad(z_input, buf_out, 32);
	SHA256_Update(&keys, buf_out, 32);
	SHA256_Final(buf_out, &keys);
#endif

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
	EC_POINT_clear_free(pub);
	EC_POINT_clear_free(server_pubkey);
	BN_clear_free(server_pubkey_x);
	BN_clear_free(v);
	BN_clear_free(vh);
	EC_POINT_clear_free(pt);
	BN_clear_free(pt_x);
	BN_clear_free(z_input);
	abort();
}

void mtwei_docryptos(mtwei_state_t *state, BIGNUM *privkey, const uint8_t *client_key, const uint8_t *server_key,
					 uint8_t *validator, uint8_t *buf_out) {
	EC_POINT *pub = NULL, *client_pubkey = NULL, *validator_pt = NULL, *hv = NULL, *pt = NULL;
	BIGNUM *client_pubkey_x = NULL, *v = NULL, *h = NULL, *pt_x = NULL, *z_input = NULL;

	CHECKNULL(pub = EC_POINT_new(state->curve25519));
	EC_POINT_mul(state->curve25519, pub, NULL, state->g, privkey, state->ctx);

	CHECKNULL(client_pubkey = EC_POINT_new(state->curve25519));
	CHECKNULL(client_pubkey_x = BN_bin2bn(client_key, 32, NULL));
	BN_mod_add(client_pubkey_x, client_pubkey_x, state->m2w, state->mod, state->ctx);
	if (EC_POINT_set_compressed_coordinates(state->curve25519, client_pubkey, client_pubkey_x, client_key[32],
											state->ctx) != 1) {
		fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		goto abort;
	}

	SHA256_CTX keys;
	CHECKNULL(v = BN_bin2bn(validator, 32, NULL));

#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex2(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, client_key, 32);
	EVP_DigestUpdate(mdctx, server_key, 32);
	EVP_DigestFinal_ex(mdctx, buf_out, NULL);
	EVP_MD_CTX_free(mdctx);
#else
	SHA256_Init(&keys);
	SHA256_Update(&keys, client_key, 32);
	SHA256_Update(&keys, server_key, 32);
	SHA256_Final(buf_out, &keys);
#endif

	CHECKNULL(validator_pt = EC_POINT_new(state->curve25519));
	EC_POINT_mul(state->curve25519, validator_pt, NULL, state->g, v, state->ctx);

	CHECKNULL(h = BN_bin2bn(buf_out, 32, NULL));
	CHECKNULL(hv = EC_POINT_new(state->curve25519));

	EC_POINT_mul(state->curve25519, hv, NULL, validator_pt, h, state->ctx);
	EC_POINT_add(state->curve25519, client_pubkey, client_pubkey, hv, state->ctx);

	CHECKNULL(pt = EC_POINT_new(state->curve25519));
	EC_POINT_mul(state->curve25519, pt, NULL, client_pubkey, privkey, state->ctx);

	CHECKNULL(pt_x = BN_new());
#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
	EC_POINT_get_affine_coordinates(state->curve25519, pt, pt_x, NULL, NULL);
#else
	EC_POINT_get_affine_coordinates_GFp(state->curve25519, pt, pt_x, NULL, NULL);
#endif
	CHECKNULL(z_input = BN_new());
	BN_mod_add(z_input, pt_x, state->w2m, state->mod, state->ctx);

#if OPENSSL_VERSION_NUMBER >= 0x030000000  // 3.0.0
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex2(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, buf_out, 32);
	BN_bn2binpad(z_input, buf_out, 32);
	EVP_DigestUpdate(mdctx, buf_out, 32);
	EVP_DigestFinal_ex(mdctx, buf_out, NULL);
	EVP_MD_CTX_free(mdctx);
#else
	SHA256_Init(&keys);
	SHA256_Update(&keys, buf_out, 32);
	BN_bn2binpad(z_input, buf_out, 32);
	SHA256_Update(&keys, buf_out, 32);
	SHA256_Final(buf_out, &keys);
#endif

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
	abort();
}
