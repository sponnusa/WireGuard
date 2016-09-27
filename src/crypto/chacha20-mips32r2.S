#include <linux/linkage.h>

#define CHACHA20_CTX_STATE 0
#define CHACHA20_CTX_STREAM (4*16)

#define POLY1305_CTX_R 0
#define POLY1305_CTX_S POLY1305_CTX_R + (5*4)
#define POLY1305_CTX_H POLY1305_CTX_S + (4*4)
#define POLY1305_CTX_BUF POLY1305_CTX_H + (5*4)
#define POLY1305_CTX_BUFLEN POLY1305_CTX_BUF + (4*4)

#ifndef CONFIG_32BIT
#error Only 32-bits
#endif
#ifndef CONFIG_CPU_MIPS32_R2
#error Only MIPS32R2
#endif
#ifndef ENTRY
#define ENTRY(x) .ent(x)
#endif
#ifndef END
#define END(x) .end(x)
#endif
.data
// asmlinkage void chacha20_keysetup(struct chacha20_ctx *ctx, const u8 key[static 32], const u8 nonce[static 8]);
	.text
	.set reorder
	.ent chacha20_keysetup
ENTRY(chacha20_keysetup)
	// Load upper part of Constant
	lui		$t0, 0x6170
	lui		$t1, 0x3320
	lui		$t2, 0x7962
	lui		$t3, 0x6b20
	// Load first part of key data
	lw 		$t4, 0($a1)
	lw 		$t5, 4($a1)
	lw 		$t6, 8($a1)
	lw 		$t7, 12($a1)
	lw 		$t8, 16($a1)
	lw 		$t9, 20($a1)
	// Load lower part of Constant
	ori		$t0, 0x7865
	ori		$t1, 0x646e
	ori		$t2, 0x2d32
	ori		$t3, 0x6574
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	// Convert to Little Endian
	wsbh 	$t4
	wsbh 	$t5
	wsbh 	$t6
	wsbh 	$t7
	wsbh 	$t8
	wsbh 	$t9
	rotr 	$t4, 16
	rotr 	$t5, 16
	rotr 	$t6, 16
	rotr 	$t7, 16
	rotr 	$t8, 16
	rotr 	$t9, 16
#endif
	// Store first part of key data to ctx
	sw		$t0, 0($a0)
	sw		$t1, 4($a0)
	sw		$t2, 8($a0)
	sw		$t3, 12($a0)
	sw 		$t4, 16($a0)
	sw 		$t5, 20($a0)
	// Load second part of key data
	lw 		$t0, 24($a1)
	lw 		$t1, 28($a1)
	lw 		$t2, 0($a2)
	lw 		$t3, 4($a2)
	sw 		$t6, 24($a0)
	sw 		$t7, 28($a0)
	sw 		$t8, 32($a0)
	sw 		$t9, 36($a0)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	// Convert to Little Endian
	wsbh 	$t0
	wsbh 	$t1
	wsbh 	$t2
	wsbh 	$t3
	rotr 	$t0, 16
	rotr 	$t1, 16
	rotr 	$t2, 16
	rotr 	$t3, 16
#endif
	// Store second part of key data to ctx
	sw 		$zero, 48($a0)
	sw 		$zero, 52($a0)
	sw 		$t0, 40($a0)
	sw 		$t1, 44($a0)
	sw 		$t2, 56($a0)
	sw 		$t3, 60($a0)
	// Jump back
	jr 		$ra
END(chacha20_keysetup)

#define X0  $t0
#define X1  $t1
#define X2  $t2
#define X3  $t3
#define X4  $t4
#define X5  $t5
#define X6  $t6
#define X7  $t7
#define X8  $t8
#define X9  $t9
#define X10 $v0
#define X11 $v1
#define X12 $s4
#define X13 $s5
#define X14 $s6
#define X15 $at
#define T0  $s0
#define T1  $s1
#define T2  $s2
#define T3  $s3
#define T(n) T ## n
#define X(n) X ## n
#define __in_ctx_p $a0
#define AXR( A, B, C, D,  K, L, M, N,  V, W, Y, Z,  S) \
	addu X(A), X(K); \
	addu X(B), X(L); \
	addu X(C), X(M); \
	addu X(D), X(N); \
	xor  X(V), X(A); \
	xor  X(W), X(B); \
	xor  X(Y), X(C); \
	xor  X(Z), X(D); \
	rotl X(V), S;    \
	rotl X(W), S;    \
	rotl X(Y), S;    \
	rotl X(Z), S;

#define PTR_CHACHA20_STREAM(x) (CHACHA20_CTX_STREAM + (x*4)) ## (__in_ctx_p)
#define PTR_CHACHA20_STATE(x)  (CHACHA20_CTX_STATE  + (x*4)) ## (__in_ctx_p)

#define LOAD_ctx(R)        lw X(R), PTR_CHACHA20_STATE(R);
#define STORE_ctx(R)       sw X(R), PTR_CHACHA20_STATE(R);
#define STORE_stream(R)    sw X(R), PTR_CHACHA20_STREAM(R);
#define ADD_ctx(R) \
	lw I, PTR_CHACHA20_STATE(R); \
	addu X(R), I;
#define ADD_INCCNT_ctx(R) \
	ADD_ctx(R) 			 \
	addiu I, 1;			 \
	sw I, PTR_CHACHA20_STATE(R);
#define LOAD_ctx_TMP(R, TR)        lw T(TR), PTR_CHACHA20_STATE(R);
#define loop_cnt T(3)
.set noat
.set noreorder
.ent chacha20_generic_block
ENTRY(chacha20_generic_block)
	// store the used save registers.
	addiu 	$sp, -(7*4)
	// Load all chacha settings.
	LOAD_ctx(0)
	LOAD_ctx(1)
	LOAD_ctx(2)
	LOAD_ctx(3)
	LOAD_ctx(4)
	LOAD_ctx(5)
	LOAD_ctx(6)
	LOAD_ctx(7)
	// store the used save registers.
	sw  $s0, 0($sp)
	sw  $s1, 4($sp)
	sw  $s2, 8($sp)
	sw  $s3, 12($sp)
	sw  $s4, 16($sp)
	sw  $s5, 20($sp)
	sw  $s6, 24($sp)
	// Load all chacha settings.
	LOAD_ctx(8)
	LOAD_ctx(9)
	LOAD_ctx(10)
	LOAD_ctx(11)
	LOAD_ctx(12)
	LOAD_ctx(13)
	LOAD_ctx(14)
	LOAD_ctx(15)
	// set loop counter.
	li    loop_cnt, 18
chacha_rounds_loop:
	// do row shuffle
	AXR( 0, 1, 2, 3,  4, 5, 6, 7, 12,13,14,15, 16);
	AXR( 8, 9,10,11, 12,13,14,15,  4, 5, 6, 7, 12);
	AXR( 0, 1, 2, 3,  4, 5, 6, 7, 12,13,14,15,  8);
	AXR( 8, 9,10,11, 12,13,14,15,  4, 5, 6, 7,  7);
	AXR( 0, 1, 2, 3,  5, 6, 7, 4, 15,12,13,14, 16);
	AXR(10,11, 8, 9, 15,12,13,14,  5, 6, 7, 4, 12);
	AXR( 0, 1, 2, 3,  5, 6, 7, 4, 15,12,13,14,  8);
	AXR(10,11, 8, 9, 15,12,13,14,  5, 6, 7, 4,  7);
	// loop_cnt if T(0) != 0
	bnez 	loop_cnt, chacha_rounds_loop
	// decrease loop counter, make use of delay slot.
	addiu	loop_cnt, -2
	LOAD_ctx_TMP(0,0)
	LOAD_ctx_TMP(1,1)
	LOAD_ctx_TMP(2,2)
	LOAD_ctx_TMP(3,3)
	addu X(0), T(0)
	addu X(1), T(1)
	addu X(2), T(2)
	addu X(3), T(3)
	LOAD_ctx_TMP(4,0)
	LOAD_ctx_TMP(5,1)
	LOAD_ctx_TMP(6,2)
	LOAD_ctx_TMP(7,3)
	addu X(4), T(0)
	addu X(5), T(1)
	addu X(6), T(2)
	addu X(7), T(3)
	LOAD_ctx_TMP(8,0)
	LOAD_ctx_TMP(9,1)
	LOAD_ctx_TMP(10,2)
	LOAD_ctx_TMP(11,3)
	addu X(8), T(0)
	addu X(9), T(1)
	addu X(10), T(2)
	addu X(11), T(3)
	LOAD_ctx_TMP(12,0)
	LOAD_ctx_TMP(13,1)
	LOAD_ctx_TMP(14,2)
	LOAD_ctx_TMP(15,3)
	addu X(12), T(0)
	addiu T(0), 1
	addu X(13), T(1)
	addu X(14), T(2)
	addu X(15), T(3)
	sw T(0), 48(__in_ctx_p)
	// Convert to Litte endian and Save all to stream.
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	wsbh 	X(0)
	wsbh 	X(1)
	wsbh 	X(2)
	wsbh 	X(3)
	wsbh 	X(4)
	wsbh 	X(5)
	wsbh 	X(6)
	wsbh 	X(7)
	wsbh 	X(8)
	wsbh 	X(9)
	wsbh 	X(10)
	wsbh 	X(11)
	wsbh 	X(12)
	wsbh 	X(13)
	wsbh 	X(14)
	wsbh 	X(15)
	rotr 	X(0), 16
	rotr 	X(1), 16
	rotr 	X(2), 16
	rotr 	X(3), 16
	rotr 	X(4), 16
	rotr 	X(5), 16
	rotr 	X(6), 16
	rotr 	X(7), 16
	rotr 	X(8), 16
	rotr 	X(9), 16
	rotr 	X(10), 16
	rotr 	X(11), 16
	rotr 	X(12), 16
	rotr 	X(13), 16
	rotr 	X(14), 16
	rotr 	X(15), 16
#endif
	STORE_stream(0)
	STORE_stream(1)
	STORE_stream(2)
	STORE_stream(3)
	STORE_stream(4)
	STORE_stream(5)
	STORE_stream(6)
	STORE_stream(7)
	STORE_stream(8)
	STORE_stream(9)
	STORE_stream(10)
	STORE_stream(11)
	STORE_stream(12)
	STORE_stream(13)
	STORE_stream(14)
	STORE_stream(15)
	// restore the used save registers.
	lw  $s0, 0($sp)
	lw  $s1, 4($sp)
	lw  $s2, 8($sp)
	lw  $s3, 12($sp)
	lw  $s4, 16($sp)
	lw  $s5, 20($sp)
	lw  $s6, 24($sp)
	// Jump Back
	jr	$ra
	addiu 	$sp, (7*4)
END(chacha20_generic_block)
.set at
.set reorder


#define H0  $t0
#define H1  $t1
#define H2  $t2
#define H3  $t3
#define H4  $t4

#define R0  $t5
#define R1  $t6
#define R2  $t7
#define R3  $t8
#define R4  $t9

#define O0 $s0
#define O1 $s1
#define O2 $s2
#define O3 $s3
#define O4 $s4

#define S1 $s5
#define S2 $s6
#define S4 $s7
#define S3 $v0

#define SC  $gp
#define CA  $v1
#define AT  $at

#define R(n)  R ## n
#define S(n)  S ## n
#define H(n)  H ## n
#define O(n)  O ## n
#define D(n)  D ## n

#define __in_ctx_poly $a0
#define src        $a1
#define srclen     $a2
#define hibit      $a3

#define PTR_POLY1305_R(n) (POLY1305_CTX_R + (n*4)) ## ($a0)
#define PTR_POLY1305_H(n) (POLY1305_CTX_H + (n*4)) ## ($a0)
#define PTR_POLY1305_S(n) (POLY1305_CTX_S + (n*4)) ## ($a0)

#define LOAD_ctx_r(n)        lw R(n), PTR_POLY1305_R(n);
#define LOAD_ctx_s(n)        lw S(n), PTR_POLY1305_S(n);
#define LOAD_ctx_h(n)        lw H(n), PTR_POLY1305_H(n);
#define STORE_ctx_h(n)       sw H(n), PTR_POLY1305_H(n);
#define POLY1305_BLOCK_SIZE 16
#define GET_HILO_REG(RHI, RLO) \
	mflo RLO; \
	mfhi RHI;
#define AND_3FFFFFF(RT, RS) \
	ext RT, RS, 0, 26;
#define poly1305_frame_size 15 * 4

// MULTI_MUL_AND_ADD_PREV( R(2), R(1), R(0), S(4), S(3), H(1))
#define MULTI_MUL_AND_ADD_PREV( MUL1, MUL2, MUL3, MUL4, MUL5, PREV ) \
	mflo PREV; \
	mfhi SC;   \
	multu O(0), MUL1; \
	maddu O(1), MUL2; \
		addu AT,PREV,CA; \
	maddu O(2), MUL3; \
	maddu O(3), MUL4; \
		sltu PREV,AT,PREV; \
		srl  CA,AT,26; \
	maddu O(4), MUL5; \
		addu SC,PREV,SC; \
		AND_3FFFFFF( PREV, AT ); \
		ins CA,SC, 32-26, 26

// static unsigned int poly1305_generic_blocks(struct poly1305_ctx *ctx, const u8 *src, unsigned int srclen, u32 hibit)
// .abicalls
// .text
.set noat
.set reorder
// .set nomips16
// .set nomicromips
.ent poly1305_generic_blocks
//.type poly1305_generic_blocks, @function
ENTRY(poly1305_generic_blocks)
	.frame  $sp,poly1305_frame_size,$31
	// store the used save registers.
	addiu 	$sp, -poly1305_frame_size
	addiu srclen, -POLY1305_BLOCK_SIZE

	LOAD_ctx_r(0)
	LOAD_ctx_r(1)
	LOAD_ctx_r(2)
	LOAD_ctx_r(3)
	LOAD_ctx_r(4)

	// store the used save registers.
	sw  $s0, 0($sp)
	sw  $s1, 4($sp)
	sw  $s2, 8($sp)
	sw  $s3, 12($sp)
	sw  $s4, 16($sp)
	sw  $s5, 20($sp)
	sw  $s6, 24($sp)
	sw  $s7, 28($sp)
	sw  $gp, 32($sp)

	// S(1..4) = R(1..4) * 5
	sll S(4), R(4),2
	sll S(3), R(3),2
	sll S(2), R(2),2
	sll S(1), R(1),2
	addu S(4), R(4)
	addu S(3), R(3)
	addu S(2), R(2)
	addu S(1), R(1)


	LOAD_ctx_h(0)
	LOAD_ctx_h(1)
	LOAD_ctx_h(2)
	LOAD_ctx_h(3)
	LOAD_ctx_h(4)

poly1305_loop:

	/* h += m[i] */
	lw O(0), 0(src)
	lw AT,   4(src)
	lw SC,   8(src)
	lw CA  ,12(src)

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	wsbh 	O(0)
	wsbh 	AT
	wsbh 	SC
	wsbh 	CA
	rotr 	O(0), 16
	rotr 	AT, 16
	rotr 	SC, 16
	rotr 	CA, 16
#endif

	// h0 += t0 & 0x3ffffff
	srl     O(1), O(0), 26
	ext	O(0), O(0), 0, 26

	addiu src, POLY1305_BLOCK_SIZE
	addiu srclen, -POLY1305_BLOCK_SIZE

	// h1 += ((((uint64_t)t1 << 32) | t0) >> 26) & 0x3ffffff;
	srl	O(2), AT  , 20
	ins	O(1), AT  , 32-26, 26-(32-26)

	// h4 += (t3 >> 8) | (1 << 24);
	srl 	O(4), CA, 8

	// h2 += ((((uint64_t)t2 << 32) | t1) >> 20) & 0x3ffffff;
	srl	O(3), SC  , 14
	ins	O(2), SC  , 32-20, 26-(32-20)

	// h3 += ((((uint64_t)t3 << 32) | t2) >> 14) & 0x3ffffff;
	ins	O(3), CA, 32-14, 26-(32-14)

	OR	O(4), hibit

	addu	O(0), H(0)
	addu	O(1), H(1)
	addu	O(2), H(2)
	addu	O(3), H(3)
	addu	O(4), H(4)

poly1305_loop_mul:
	/* h *= r AND (partial) h %= p */

	// D0
	multu O(0), R(0)
	maddu O(1), S(4)
	maddu O(2), S(3)
	maddu O(3), S(2)
	maddu O(4), S(1)

	GET_HILO_REG (SC, CA)

	multu O(0), R(1)
	maddu O(1), R(0)
	AND_3FFFFFF( H(0), CA )
	srl CA,CA,26

	maddu O(2), S(4)
	maddu O(3), S(3)
	maddu O(4), S(2)

	ins CA,SC, 32-26, 26

	MULTI_MUL_AND_ADD_PREV( R(2), R(1), R(0), S(4), S(3), H(1))

	MULTI_MUL_AND_ADD_PREV( R(3), R(2), R(1), R(0), S(4), H(2))

	MULTI_MUL_AND_ADD_PREV( R(4), R(3), R(2), R(1), R(0), H(3))

	GET_HILO_REG (SC, H(4))


poly1305_loop_finish:
	addu AT,H(4),CA

	sltu 	H(4),AT,H(4)
	srl 	CA,AT, 26
	addu 	SC,H(4),SC
	AND_3FFFFFF( H(4), AT )
	ins		CA,SC, 32-26, 26

	// Multiply 5
	// H(0) = H(0) + (CA * 5) = H(0) + CA + (CA << 2)
	sll   SC, CA, 2
	addu  H(0), H(0), CA
	addu  H(0), SC

	// H(1) = H(1) + (H(0) >> 26)
	srl   SC, H(0), 26
	addu H(1), SC

	// H(0) = H(0) & 0x3FFFFFF
	AND_3FFFFFF( H(0), H(0) )

	// able to do a 16 byte block.
	bgezl srclen, poly1305_loop
	nop

	// restore the used save registers.
	lw  $s0, 0($sp)
	lw  $s1, 4($sp)
	lw  $s2, 8($sp)
	lw  $s3, 12($sp)
	lw  $s4, 16($sp)
	lw  $s5, 20($sp)
	lw  $s6, 24($sp)
	lw  $s7, 28($sp)
	lw  $gp, 32($sp)

	STORE_ctx_h(0)
	STORE_ctx_h(1)
	STORE_ctx_h(2)
	STORE_ctx_h(3)
	STORE_ctx_h(4)

	addiu 	$sp, poly1305_frame_size
	// return remaining bytes
	addiu	$v0, srclen, POLY1305_BLOCK_SIZE
	// Jump Back
	jr	$ra

END(poly1305_generic_blocks)
.set at
.set reorder




#define PT1  $t1
#define PT2  $t2
#define PT3  $t3

#define PR0  $t4
#define PR1  $t5
#define PR2  $t6
#define PR3  $t7
#define PR4  $t8

#define PS0 $t9
#define PS1 $t0
#define PS2 $t2
#define PS3 $t3


#define PR(n)  PR ## n
#define PS(n)  PS ## n
#define PT(n)  PT ## n

#define STORE_poly_s(n) sw PS(n), PTR_POLY1305_S(n)
#define STORE_poly_r(n) sw PR(n), PTR_POLY1305_R(n)
#define LOAD_key(RG,n)	lw RG, (n * 4) ## ($a1);

#define SRL_U64_LSB(RT, RS, SHIFT) \
		ext RT, RS, SHIFT   , 32-SHIFT;
#define SRL_U64_MSB_UPTO26BIT(RT, RS, SHIFT) \
		ins	RT, RS, 32-SHIFT, 26-(32-SHIFT);
#define AND_6BIT(RT, POS) \
		ins	RT, $zero, POS, 6;
//#define POLY1305_KEY_SIZE 32
// static void poly1305_init(struct poly1305_ctx *ctx, const u8 key[static POLY1305_KEY_SIZE])
.set noreorder
.ent poly1305_init
//.type poly1305_init, @function
ENTRY(poly1305_init)
	LOAD_key(PR(0), 0)
	LOAD_key(PT(1), 1)
	LOAD_key(PT(2), 2)
	LOAD_key(PT(3), 3)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	wsbh 	PR(0)
	wsbh 	PT(1)
	wsbh 	PT(2)
	wsbh 	PT(3)
	rotr 	PR(0), 16
	rotr 	PT(1), 16
	rotr 	PT(2), 16
	rotr 	PT(3), 16
#endif
	// ctx->r[x] = shift and ANDing
	SRL_U64_LSB( 			PR(1), PR(0),  26 )
	ext 					PR(0), PR(0), 0, 26
	SRL_U64_LSB( 			PR(2), PT(1),  20 )
	SRL_U64_LSB( 			PR(3), PT(2),  14 )
	ext						PR(4), PT(3), 8, 20

	sw		$zero, 36($a0)
	sw		$zero, 40($a0)
	sw		$zero, 44($a0)
	sw		$zero, 48($a0)

	SRL_U64_MSB_UPTO26BIT( 	PR(1), PT(1),  26 )
	SRL_U64_MSB_UPTO26BIT( 	PR(2), PT(2),  20 )
	SRL_U64_MSB_UPTO26BIT( 	PR(3), PT(3),  14 )

	sw		$zero, 52($a0)
	sw		$zero, 56($a0)
	sw		$zero, 60($a0)
	sw		$zero, 64($a0)
	sw		$zero, 68($a0)
	sw		$zero, 72($a0)

	AND_6BIT( 				PR(1), 28-26 )
	AND_6BIT( 				PR(2), 28-20 )
	AND_6BIT( 				PR(3), 28-14 )

	STORE_poly_r(0)
	STORE_poly_r(1)
	STORE_poly_r(2)
	STORE_poly_r(3)
	STORE_poly_r(4)

	LOAD_key(PS(0), 4)
	LOAD_key(PS(1), 5)
	LOAD_key(PS(2), 6)
	LOAD_key(PS(3), 7)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	wsbh 	PS(0)
	wsbh 	PS(1)
	wsbh 	PS(2)
	wsbh 	PS(3)
	rotr 	PS(0), 16
	rotr 	PS(1), 16
	rotr 	PS(2), 16
	rotr 	PS(3), 16
#endif
	STORE_poly_s(0)
	STORE_poly_s(1)
	STORE_poly_s(2)
	STORE_poly_s(3)

	// Jump Back
	jr	$ra
	nop
END(poly1305_init)
.set reorder
