#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../include/rijndael.h"
#include "../include/tables.h"

#define MAX(a, b) ((a) < (b) ? (b) : (a))

static const Rijndael_Tables T = {
	.S = S, .Si = Si,
	.Rcon = Rcon,
	.T0 = T0, .T1 = T1, .T2 = T2, .T3 = T3,
	.T4 = T4, .T5 = T5, .T6 = T6, .T7 = T7,
	.U0 = U0, .U1 = U1, .U2 = U2, .U3 = U3
};

static inline void
cipher(const Rijndael_Ctx *ctx, const uint8_t *in, uint8_t *out)
{
	const uint32_t *We = ctx->We;
	const uint32_t *T0 = ctx->T->T0;
	const uint32_t *T1 = ctx->T->T1;
	const uint32_t *T2 = ctx->T->T2;
	const uint32_t *T3 = ctx->T->T3;
	const uint8_t  *S  = ctx->T->S;

	uint8_t C1 = ctx->C1;
	uint8_t C2 = ctx->C2;
	uint8_t C3 = ctx->C3;

	uint8_t Nb = ctx->Nb;
	uint8_t Nr = ctx->Nr;

	uint32_t s_1[32] = {0};
	uint32_t s_2[32] = {0};
	uint32_t *state  = s_1;
	uint32_t *state_ = s_2;
	uint32_t *temp   = state;
	
	uint32_t a;

	int i, j;

	for (i = 0; i < Nb; i++) {
		state[i] = ((uint32_t)in[(4 * i)    ] << 24) |
				   ((uint32_t)in[(4 * i) + 1] << 16) |
				   ((uint32_t)in[(4 * i) + 2] <<  8) |
				   ((uint32_t)in[(4 * i) + 3]      );
	}

	for (i = 0; i < Nb; i++)
		state[i] ^= We[i];

	for (i = 1; i < Nr; i++) {
		for (j = 0; j < Nb; j++) {
			a = ((uint32_t)T0[(state[(j     )     ] >> 24)       ]) ^
				((uint32_t)T1[(state[(j + C1) % Nb] >> 16) & 0xFF]) ^
				((uint32_t)T2[(state[(j + C2) % Nb] >>  8) & 0xFF]) ^
				((uint32_t)T3[(state[(j + C3) % Nb]      ) & 0xFF]);
			state_[j] = a ^ We[Nb * i + j];
		}
		state  = state_;
		state_ = temp;
		temp   = state;
	}
	for (i = 0; i < Nb; i++) {
		a = ((uint32_t)S[(state[(i     )     ] >> 24)       ] << 24) |
			((uint32_t)S[(state[(i + C1) % Nb] >> 16) & 0xFF] << 16) |
			((uint32_t)S[(state[(i + C2) % Nb] >>  8) & 0xFF] <<  8) |
			((uint32_t)S[(state[(i + C3) % Nb]      ) & 0xFF]      );
		state_[i] = a ^ We[Nb * Nr + i];
	}
	state = state_;

	for (i = 0; i < Nb; i++) {
		out[(4 * i)    ] = (state[i] >> 24)       ;
		out[(4 * i) + 1] = (state[i] >> 16) & 0xFF;
		out[(4 * i) + 2] = (state[i] >>  8) & 0xFF;
		out[(4 * i) + 3] = (state[i]      ) & 0xFF;
	}
}

static inline void
invcipher(const Rijndael_Ctx *ctx, const uint8_t *in, uint8_t *out)
{
	const uint32_t *Wd = ctx->Wd;
	const uint32_t *T4 = ctx->T->T4;
	const uint32_t *T5 = ctx->T->T5;
	const uint32_t *T6 = ctx->T->T6;
	const uint32_t *T7 = ctx->T->T7;
	const uint8_t  *Si = ctx->T->Si;

	uint8_t C1 = ctx->C1;
	uint8_t C2 = ctx->C2;
	uint8_t C3 = ctx->C3;

	uint8_t Nb = ctx->Nb;
	uint8_t Nr = ctx->Nr;

	uint32_t s_1[32] = {0};
	uint32_t s_2[32] = {0};
	uint32_t *state  = s_1;
	uint32_t *state_ = s_2;
	uint32_t *temp   = state;
	
	uint32_t a;

	int i, j;

	for (i = 0; i < Nb; i++) {
		state[i] = ((uint32_t)in[(4 * i)    ] << 24) |
				   ((uint32_t)in[(4 * i) + 1] << 16) |
				   ((uint32_t)in[(4 * i) + 2] <<  8) |
				   ((uint32_t)in[(4 * i) + 3]      );
	}

	for (i = 0; i < Nb; i++)
		state[i] ^= Wd[Nb * Nr + i];

	for (i = Nr - 1; i > 0; i--) {
		for (j = 0; j < Nb; j++) {
			a = ((uint32_t)T4[(state[(j          )     ] >> 24)       ]) ^
				((uint32_t)T5[(state[(j + Nb - C1) % Nb] >> 16) & 0xFF]) ^
				((uint32_t)T6[(state[(j + Nb - C2) % Nb] >>  8) & 0xFF]) ^
				((uint32_t)T7[(state[(j + Nb - C3) % Nb]      ) & 0xFF]);
			state_[j] = a ^ Wd[Nb * i + j];
		}
		state  = state_;
		state_ = temp;
		temp   = state;
	}
	for (i = 0; i < Nb; i++) {
		a = ((uint32_t)Si[(state[(i          )     ] >> 24)       ] << 24) |
			((uint32_t)Si[(state[(i + Nb - C1) % Nb] >> 16) & 0xFF] << 16) |
			((uint32_t)Si[(state[(i + Nb - C2) % Nb] >>  8) & 0xFF] <<  8) |
			((uint32_t)Si[(state[(i + Nb - C3) % Nb]      ) & 0xFF]      );
		state_[i] = a ^ Wd[i];
	}
	state = state_;

	for (i = 0; i < Nb; i++) {
		out[(4 * i)    ] = (state[i] >> 24)       ;
		out[(4 * i) + 1] = (state[i] >> 16) & 0xFF;
		out[(4 * i) + 2] = (state[i] >>  8) & 0xFF;
		out[(4 * i) + 3] = (state[i]      ) & 0xFF;
	}
}

int
rijndael_init(Rijndael_Ctx *ctx,
			  const uint8_t *key, uint8_t key_len,
			  uint8_t block_len)
{
	assert(ctx != NULL);
	assert(key != NULL);

	uint32_t *We = ctx->We;
	uint32_t *Wd = ctx->Wd;

	if (ctx->T == NULL)
		ctx->T = &T;

	const uint8_t  *S    = ctx->T->S;
	const uint32_t *Rcon = ctx->T->Rcon;
	const uint32_t *U0   = ctx->T->U0;
	const uint32_t *U1   = ctx->T->U1;
	const uint32_t *U2   = ctx->T->U2;
	const uint32_t *U3   = ctx->T->U3;

	uint8_t Nk, Nb, Nr;

	switch (key_len) {
		case 16:
		case 20:
		case 24:
		case 28:
		case 32:
			break;
		default:
			return -1;
	}
	switch (block_len) {
		case 16:
		case 20:
		case 24:
		case 28:
		case 32:
			break;
		default:
			return -2;
	}

	Nk = key_len / 4;
	Nb = block_len / 4;
	Nr = MAX(Nk, Nb) + 6;

	ctx->Nk = Nk;
	ctx->Nb = Nb;
	ctx->Nr = Nr;
	switch (ctx->Nb) {
		case 4:
		case 5:
		case 6:
			ctx->C1 = 1;
			ctx->C2 = 2;
			ctx->C3 = 3;
			break;
		case 7:
			ctx->C1 = 1;
			ctx->C2 = 2;
			ctx->C3 = 4;
			break;
		case 8:
			ctx->C1 = 1;
			ctx->C2 = 3;
			ctx->C3 = 4;
			break;
	}
	
	uint32_t a;
	int i, j;
	for (i = 0; i < Nk; i++) {
		We[i] = ((uint32_t)key[4 * i    ] << 24) |
				((uint32_t)key[4 * i + 1] << 16) |
				((uint32_t)key[4 * i + 2] <<  8) |
				((uint32_t)key[4 * i + 3]      );
	}
	if (Nk <= 6) {
		for (i = Nk; i < Nb * (Nr + 1); i++) {
			a = We[i - 1];
			if (i % Nk == 0) {
				a = (
					 ((uint32_t)S[(a >> 16) & 0xFF] << 24) |
					 ((uint32_t)S[(a >>  8) & 0xFF] << 16) |
					 ((uint32_t)S[(a      ) & 0xFF] <<  8) |
					 ((uint32_t)S[(a >> 24)       ]      )
					) ^ Rcon[i / Nk];
			}
			We[i] = We[i - Nk] ^ a;
		}
	}
	else {
		for (i = Nk; i < Nb * (Nr + 1); i++) {
			a = We[i - 1];
			if (i % Nk == 0) {
				a = (
					 ((uint32_t)S[(a >> 16) & 0xFF] << 24) |
					 ((uint32_t)S[(a >>  8) & 0xFF] << 16) |
					 ((uint32_t)S[(a      ) & 0xFF] <<  8) |
					 ((uint32_t)S[(a >> 24)       ]      )
					) ^ Rcon[i / Nk];
			}
			else if (i % Nk == 4) {
				a = (
					 ((uint32_t)S[(a >> 16) & 0xFF] << 24) |
					 ((uint32_t)S[(a >>  8) & 0xFF] << 16) |
					 ((uint32_t)S[(a      ) & 0xFF] <<  8) |
					 ((uint32_t)S[(a >> 24)       ]      )
					);
			}
			We[i] = We[i - Nk] ^ a;
		}
	}
	memcpy(Wd, We, sizeof(ctx->Wd));
	for (i = 1; i < Nr; i++) {
		for (j = 0; j < Nb; j++) {
			a = Wd[Nb * i + j];
			Wd[Nb * i + j] = U0[(a >> 24)       ] ^
							 U1[(a >> 16) & 0xFF] ^
							 U2[(a >>  8) & 0xFF] ^
							 U3[(a      ) & 0xFF];
		}
	}

	return 0;
}

void
rijndael_set_mode_ECB(Rijndael_ECB_Ctx *ecb_ctx, const Rijndael_Ctx *ctx)
{
	assert(ecb_ctx != NULL);
	assert(ctx != NULL);

	ecb_ctx->R = ctx;
}

int
rijndael_set_mode_CBC(Rijndael_CBC_Ctx *cbc_ctx, const Rijndael_Ctx *ctx,
					  const uint8_t *iv, size_t iv_len)
{
	assert(cbc_ctx != NULL);
	assert(ctx != NULL);
	assert(iv != NULL);

	uint8_t block_len = ctx->Nb * 4;
	if (iv_len != block_len)
		return -1;

	cbc_ctx->R = ctx;
	memcpy(cbc_ctx->C_i_e, iv, block_len);
	memcpy(cbc_ctx->C_i_d, iv, block_len);

	return 0;
}

int
rijndael_set_mode_CTR(Rijndael_CTR_Ctx *ctr_ctx, const Rijndael_Ctx *ctx,
					  const uint8_t *nonce, size_t nonce_len,
					  const uint8_t *initial_value, size_t initial_value_len)
{
	assert(ctr_ctx != NULL);
	assert(ctx != NULL);
	assert(initial_value != NULL);

	uint8_t block_len = ctx->Nb * 4;
	if (nonce == NULL && nonce_len != 0)
		return -1;
	if (nonce_len > (uint8_t)(block_len - 1))
		return -2;
	if (nonce_len + initial_value_len != block_len)
		return -3;

	ctr_ctx->R = ctx;

	if (nonce_len != 0)
		ctr_ctx->ctr_start = nonce_len - 1;
	else
		ctr_ctx->ctr_start = 0;
	ctr_ctx->ctr_end = ctr_ctx->ctr_start + initial_value_len;

	ctr_ctx->ks_i_e = block_len;
	ctr_ctx->ks_i_d = block_len;

	if (nonce != NULL) {
		memcpy(ctr_ctx->obj_e, nonce, nonce_len);
		memcpy(ctr_ctx->obj_d, nonce, nonce_len);
	}
	memcpy(ctr_ctx->obj_e + nonce_len, initial_value, initial_value_len);
	memcpy(ctr_ctx->obj_d + nonce_len, initial_value, initial_value_len);

	return 0;
}

int
rijndael_encrypt_ECB(const Rijndael_ECB_Ctx *ctx,
					 const uint8_t *in, size_t in_len,
					 uint8_t *out, size_t out_len)
{
	assert(ctx != NULL);
	assert(in != NULL);
	assert(out != NULL);

	if (out_len < in_len)
		return -1;
	uint8_t block_len = ctx->R->Nb * 4;
	if (in_len % block_len != 0)
		return -2;

	for (size_t i = 0; i < in_len; i += block_len)
		cipher(ctx->R, in + i, out + i);

	return 0;
}

int
rijndael_encrypt_CBC(Rijndael_CBC_Ctx *ctx,
					 const uint8_t *in, size_t in_len,
					 uint8_t *out, size_t out_len)
{
	assert(ctx != NULL);
	assert(in != NULL);
	assert(out != NULL);

	if (out_len < in_len)
		return -1;
	uint8_t block_len = ctx->R->Nb * 4;
	if (in_len % block_len != 0)
		return -2;

	for (size_t i = 0; i < in_len; i += block_len) {
		memcpy(out + i, in + i, block_len);
		for (uint8_t j = 0; j < block_len; j++)
			out[i + j] ^= ctx->C_i_e[j];
		cipher(ctx->R, out + i, out + i);
		memcpy(ctx->C_i_e, out + i, block_len);
	}

	return 0;
}

int
rijndael_encrypt_CTR(Rijndael_CTR_Ctx *ctx,
					 const uint8_t *in, size_t in_len,
					 uint8_t *out, size_t out_len)
{
	assert(ctx != NULL);
	assert(in != NULL);
	assert(out != NULL);

	if (out_len < in_len)
		return -1;
	uint8_t block_len = ctx->R->Nb * 4;

	size_t i = 0;
	while (i < out_len) {
		if (ctx->ks_i_e != block_len) {
			out[i] = in[i] ^ ctx->ks_e[ctx->ks_i_e];
			ctx->ks_i_e++;
			i++;
			continue;
		}

		cipher(ctx->R, ctx->obj_e, ctx->ks_e);
		for (int j = ctx->ctr_end; j >= ctx->ctr_start; j--) {
			ctx->obj_e[j]++;
			if (ctx->obj_e[j] != 0)
				break;
		}
		ctx->ks_i_e = 0;
	}

	return 0;
}

int
rijndael_decrypt_ECB(const Rijndael_ECB_Ctx *ctx,
					 const uint8_t *in, size_t in_len,
					 uint8_t *out, size_t out_len)
{
	assert(ctx != NULL);
	assert(in != NULL);
	assert(out != NULL);

	if (out_len < in_len)
		return -1;
	uint8_t block_len = ctx->R->Nb * 4;
	if (in_len % block_len != 0)
		return -2;

	for (size_t i = 0; i < in_len; i += block_len)
		invcipher(ctx->R, in + i, out + i);

	return 0;
}

int
rijndael_decrypt_CBC(Rijndael_CBC_Ctx *ctx,
					 const uint8_t *in, size_t in_len,
					 uint8_t *out, size_t out_len)
{
	assert(ctx != NULL);
	assert(in != NULL);
	assert(out != NULL);

	if (out_len < in_len)
		return -1;
	uint8_t block_len = ctx->R->Nb * 4;
	if (in_len % block_len != 0)
		return -2;
	uint8_t C_i[32] = {0};

	for (size_t i = 0; i < in_len; i += block_len) {
		memcpy(C_i, in + i, block_len);
		invcipher(ctx->R, in + i, out + i);
		for (int j = 0; j < block_len; j++)
			out[i + j] ^= ctx->C_i_d[j];
		memcpy(ctx->C_i_d, C_i, block_len);
	}

	return 0;
}

int
rijndael_decrypt_CTR(Rijndael_CTR_Ctx *ctx,
					 const uint8_t *in, size_t in_len,
					 uint8_t *out, size_t out_len)
{
	assert(ctx != NULL);
	assert(in != NULL);
	assert(out != NULL);

	if (out_len < in_len)
		return -1;
	uint8_t block_len = ctx->R->Nb * 4;

	size_t i = 0;
	while (i < out_len) {
		if (ctx->ks_i_d != block_len) {
			out[i] = in[i] ^ ctx->ks_d[ctx->ks_i_d];
			ctx->ks_i_d++;
			i++;
			continue;
		}

		cipher(ctx->R, ctx->obj_d, ctx->ks_d);
		for (int j = ctx->ctr_end; j >= ctx->ctr_start; j--) {
			ctx->obj_d[j]++;
			if (ctx->obj_d[j] != 0)
				break;
		}
		ctx->ks_i_d = 0;
	}

	return 0;
}

