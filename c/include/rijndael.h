#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include <stddef.h>
#include <stdint.h>

typedef struct
{
	const uint8_t *S;
	const uint8_t *Si;

	const uint32_t *Rcon;

	const uint32_t *T0;
	const uint32_t *T1;
	const uint32_t *T2;
	const uint32_t *T3;
	const uint32_t *T4;
	const uint32_t *T5;
	const uint32_t *T6;
	const uint32_t *T7;

	const uint32_t *U0;
	const uint32_t *U1;
	const uint32_t *U2;
	const uint32_t *U3;
}
Rijndael_Tables;

typedef struct
{
	// Key columns.
	uint8_t Nk;
	// State columns.
	uint8_t Nb;
	// Number of rounds.
	uint8_t Nr;
	// ShiftRow offset for row 1.
	uint8_t C1;
	// ShiftRow offset for row 2.
	uint8_t C2;
	// ShiftRow offset for row 3.
	uint8_t C3;

	// Expanded key for encryption.
	// Nb * (Nr + 1) elements, allocated with respect to maximum bound (blocksize=32).
	uint32_t We[(32 / 4) * ((32 + 6) + 1)];
	// Expanded key for decryption.
	// Nb * (Nr + 1) elements, allocated with respect to maximum bound (blocksize=32).
	uint32_t Wd[(32 / 4) * ((32 + 6) + 1)];

	const Rijndael_Tables *T;
}
Rijndael_Ctx;

typedef struct
{
	const Rijndael_Ctx *R;
}
Rijndael_ECB_Ctx;

typedef struct
{
	uint8_t C_i_e[32];
	uint8_t C_i_d[32];
	const Rijndael_Ctx *R;
}
Rijndael_CBC_Ctx;

int
rijndael_init(Rijndael_Ctx *ctx, const uint8_t *key, uint8_t key_len, uint8_t block_len);

void
rijndael_set_mode_ECB(Rijndael_ECB_Ctx *ecb_ctx, const Rijndael_Ctx *ctx);
int
rijndael_set_mode_CBC(Rijndael_CBC_Ctx *cbc_ctx, const Rijndael_Ctx *ctx, const uint8_t *iv, size_t iv_len);

int
rijndael_encrypt_ECB(const Rijndael_ECB_Ctx *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);
int
rijndael_encrypt_CBC(Rijndael_CBC_Ctx *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);

int
rijndael_decrypt_ECB(const Rijndael_ECB_Ctx *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);
int
rijndael_decrypt_CBC(Rijndael_CBC_Ctx *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);

#endif // RIJNDAEL_H

