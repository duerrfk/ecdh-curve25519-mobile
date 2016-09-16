/*
 * File:    avrnacl_8bitc/shared/fe25519.c
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Fri Aug 1 09:07:46 2014 +0200
 * Public Domain
 */

#ifdef __AVR__
  #include <avr/pgmspace.h>
#endif   

#include "avrnacl.h"
#include "bigint.h"
#include "fe25519.h"

/******************************************************************/
/*                Static constants and functions                  */
/******************************************************************/

/* m = 2^255-19 = 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed */
static const unsigned char ECCParam_p[32] = {0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};



static crypto_uint16 equal(crypto_uint16 a,crypto_uint16 b) /* 8-bit inputs */
{
  crypto_uint32 x = a ^ b; /* 0: yes; 1..255: no */
  x -= 1; /* 65535: yes; 0..254: no */
  x >>= 16; /* 1: yes; 0: no */
  return x;
}

/******************************************************************/
/*                Public constants and functions                  */
/******************************************************************/

void fe25519_add(fe25519 *r, const fe25519 *a, const fe25519 *b) 
{
  unsigned char carry=0;
  crypto_uint16 tmp;
  int i;

  carry = bigint_add(r->v,a->v,b->v, 32);
  tmp = ((carry << 1) | (r->v[31] >> 7)) * 19;
  for(i=0;i<31;i++)
  {
    tmp = (crypto_uint16) r->v[i] + tmp;
    r->v[i] = tmp & 0xff;
    tmp >>= 8;
  }
  r->v[i] = (r->v[i] & 0x7f) + tmp;
}

void fe25519_sub(fe25519 *r, const fe25519 *a, const fe25519 *b) 
{
  unsigned char borrow;
  crypto_uint16 tmp;
  int i;

  borrow = bigint_sub(r->v,a->v,b->v, 32);

  tmp = borrow * 38;
  for (i=0; i<32; i++) 
  {
    tmp = (crypto_uint16) r->v[i] - tmp;
    r->v[i] = tmp & 0xff;
    tmp >>= 15;
  }
  tmp *= 38;
  for (i=0; i<3; i++) 
  {
    tmp = (crypto_uint16) r->v[i] - tmp;
    r->v[i] = tmp & 0xff;
    tmp >>= 15;
  }
}

void fe25519_mul(fe25519 *r, const fe25519 *a, const fe25519 *b) 
{
  unsigned char t[64];
  crypto_uint16 UV=0;

  /* multiplication */
  bigint_mul32(t, a->v, b->v);
	
  /* reduction */
  int i;
  for (i=0; i<32; i++) 
  {
	  UV = (t[i+32] << 5) + (t[i+32] << 2) + (t[i+32] << 1) + (UV >> 8) + t[i];
  	r->v[i] = (UV & 0xFF);
  }
  UV >>= 8;
  UV *= 38;
  for (i=0; i<32; i++) 
  {
	  UV = UV + r->v[i];
  	r->v[i] = (UV & 0xFF);
    UV >>= 8;
  }
  UV *= 38;
  for (i=0; i<3; i++) /* XXX: 3 should be enough here, is 2 enough? */
  {
	  UV = UV + r->v[i];
  	r->v[i] = (UV & 0xFF);
    UV >>= 8;
  }

}

void fe25519_square(fe25519 *r, const fe25519 *x) 
{
  fe25519_mul(r,x,x);
}

void fe25519_setzero(fe25519 *r)
{
  int i;
  for(i=0;i<32;i++) 
    r->v[i]=0;
}

void fe25519_setone(fe25519 *r) 
{
  int i;
  r->v[0] = 1;
  for(i=1;i<32;i++) 
    r->v[i]=0;
}

unsigned char fe25519_getparity(const fe25519 *x)
{
  fe25519 t = *x;
  fe25519_freeze(&t);
  return t.v[0] & 1;
}

int fe25519_iszero(const fe25519 *x)
{
  int i;
  unsigned char r = 0;
  fe25519 t = *x;
  fe25519_freeze(&t);
  for(i=1;i<32;i++)
    r |= t.v[i];
  return equal(r,0);
}

int fe25519_iseq_vartime(const fe25519 *x, const fe25519 *y)
{
  fe25519 t1 = *x;
  fe25519 t2 = *y;
  fe25519_freeze(&t1);
  fe25519_freeze(&t2);
  int i;
  for(i=0;i<32;i++)
    if(t1.v[i] != t2.v[i]) return 0;
  return 1;
}

void fe25519_neg(fe25519 *r, const fe25519 *x) 
{
  fe25519 t;
  fe25519_setzero(&t);
  fe25519_sub(r, &t, x);
}

void fe25519_cmov(fe25519 *r, const fe25519 *x, unsigned char b)
{
  bigint_cmov(r->v,x->v,b,32);
}

void fe25519_unpack(fe25519 *r, const unsigned char x[32])
{
  int i;
  for(i=0;i<32;i++) r->v[i] = x[i];
  r->v[31] &= 127;
}

void fe25519_pack(unsigned char r[32], const fe25519 *x)
{
  int i;
  fe25519 y = *x;
  fe25519_freeze(&y);
  for(i=0;i<32;i++)
    r[i] = y.v[i];
}

/* reduction modulo 2^255-19 */
void fe25519_freeze(fe25519 *r)
{
  unsigned char c;
  fe25519 rt;
  c = bigint_sub(rt.v, r->v, ECCParam_p, 32);
  fe25519_cmov(r,&rt,1-c);
  c = bigint_sub(rt.v, r->v, ECCParam_p, 32);
  fe25519_cmov(r,&rt,1-c);
}

void fe25519_invert(fe25519 *r, const fe25519 *x)
{
	fe25519 z2;
	fe25519 z9;
	fe25519 z11;
	fe25519 z2_5_0;
	fe25519 z2_10_0;
	fe25519 z2_20_0;
	fe25519 z2_50_0;
	fe25519 z2_100_0;
	fe25519 t0;
	fe25519 t1;
	int i;

	/* 2 */ fe25519_square(&z2,x);
	/* 4 */ fe25519_square(&t1,&z2);
	/* 8 */ fe25519_square(&t0,&t1);
	/* 9 */ fe25519_mul(&z9,&t0,x);
	/* 11 */ fe25519_mul(&z11,&z9,&z2);
	/* 22 */ fe25519_square(&t0,&z11);
	/* 2^5 - 2^0 = 31 */ fe25519_mul(&z2_5_0,&t0,&z9);

	/* 2^6 - 2^1 */ fe25519_square(&t0,&z2_5_0);
	/* 2^7 - 2^2 */ fe25519_square(&t1,&t0);
	/* 2^8 - 2^3 */ fe25519_square(&t0,&t1);
	/* 2^9 - 2^4 */ fe25519_square(&t1,&t0);
	/* 2^10 - 2^5 */ fe25519_square(&t0,&t1);
	/* 2^10 - 2^0 */ fe25519_mul(&z2_10_0,&t0,&z2_5_0);

	/* 2^11 - 2^1 */ fe25519_square(&t0,&z2_10_0);
	/* 2^12 - 2^2 */ fe25519_square(&t1,&t0);
	/* 2^20 - 2^10 */ for (i = 2;i < 10;i += 2) { fe25519_square(&t0,&t1); fe25519_square(&t1,&t0); }
	/* 2^20 - 2^0 */ fe25519_mul(&z2_20_0,&t1,&z2_10_0);

	/* 2^21 - 2^1 */ fe25519_square(&t0,&z2_20_0);
	/* 2^22 - 2^2 */ fe25519_square(&t1,&t0);
	/* 2^40 - 2^20 */ for (i = 2;i < 20;i += 2) { fe25519_square(&t0,&t1); fe25519_square(&t1,&t0); }
	/* 2^40 - 2^0 */ fe25519_mul(&t0,&t1,&z2_20_0);

	/* 2^41 - 2^1 */ fe25519_square(&t1,&t0);
	/* 2^42 - 2^2 */ fe25519_square(&t0,&t1);
	/* 2^50 - 2^10 */ for (i = 2;i < 10;i += 2) { fe25519_square(&t1,&t0); fe25519_square(&t0,&t1); }
	/* 2^50 - 2^0 */ fe25519_mul(&z2_50_0,&t0,&z2_10_0);

	/* 2^51 - 2^1 */ fe25519_square(&t0,&z2_50_0);
	/* 2^52 - 2^2 */ fe25519_square(&t1,&t0);
	/* 2^100 - 2^50 */ for (i = 2;i < 50;i += 2) { fe25519_square(&t0,&t1); fe25519_square(&t1,&t0); }
	/* 2^100 - 2^0 */ fe25519_mul(&z2_100_0,&t1,&z2_50_0);

	/* 2^101 - 2^1 */ fe25519_square(&t1,&z2_100_0);
	/* 2^102 - 2^2 */ fe25519_square(&t0,&t1);
	/* 2^200 - 2^100 */ for (i = 2;i < 100;i += 2) { fe25519_square(&t1,&t0); fe25519_square(&t0,&t1); }
	/* 2^200 - 2^0 */ fe25519_mul(&t1,&t0,&z2_100_0);

	/* 2^201 - 2^1 */ fe25519_square(&t0,&t1);
	/* 2^202 - 2^2 */ fe25519_square(&t1,&t0);
	/* 2^250 - 2^50 */ for (i = 2;i < 50;i += 2) { fe25519_square(&t0,&t1); fe25519_square(&t1,&t0); }
	/* 2^250 - 2^0 */ fe25519_mul(&t0,&t1,&z2_50_0);

	/* 2^251 - 2^1 */ fe25519_square(&t1,&t0);
	/* 2^252 - 2^2 */ fe25519_square(&t0,&t1);
	/* 2^253 - 2^3 */ fe25519_square(&t1,&t0);
	/* 2^254 - 2^4 */ fe25519_square(&t0,&t1);
	/* 2^255 - 2^5 */ fe25519_square(&t1,&t0);
	/* 2^255 - 21 */ fe25519_mul(r,&t1,&z11);
}

void fe25519_pow2523(fe25519 *r, const fe25519 *x)
{
	fe25519 z2;
	fe25519 z9;
	fe25519 z11;
	fe25519 z2_5_0;
	fe25519 z2_10_0;
	fe25519 z2_20_0;
	fe25519 z2_50_0;
	fe25519 z2_100_0;
	fe25519 t;
	int i;

	/* 2 */ fe25519_square(&z2,x);
	/* 4 */ fe25519_square(&t,&z2);
	/* 8 */ fe25519_square(&t,&t);
	/* 9 */ fe25519_mul(&z9,&t,x);
	/* 11 */ fe25519_mul(&z11,&z9,&z2);
	/* 22 */ fe25519_square(&t,&z11);
	/* 2^5 - 2^0 = 31 */ fe25519_mul(&z2_5_0,&t,&z9);

	/* 2^6 - 2^1 */ fe25519_square(&t,&z2_5_0);
	/* 2^10 - 2^5 */ for (i = 1;i < 5;i++) { fe25519_square(&t,&t); }
	/* 2^10 - 2^0 */ fe25519_mul(&z2_10_0,&t,&z2_5_0);

	/* 2^11 - 2^1 */ fe25519_square(&t,&z2_10_0);
	/* 2^20 - 2^10 */ for (i = 1;i < 10;i++) { fe25519_square(&t,&t); }
	/* 2^20 - 2^0 */ fe25519_mul(&z2_20_0,&t,&z2_10_0);

	/* 2^21 - 2^1 */ fe25519_square(&t,&z2_20_0);
	/* 2^40 - 2^20 */ for (i = 1;i < 20;i++) { fe25519_square(&t,&t); }
	/* 2^40 - 2^0 */ fe25519_mul(&t,&t,&z2_20_0);

	/* 2^41 - 2^1 */ fe25519_square(&t,&t);
	/* 2^50 - 2^10 */ for (i = 1;i < 10;i++) { fe25519_square(&t,&t); }
	/* 2^50 - 2^0 */ fe25519_mul(&z2_50_0,&t,&z2_10_0);

	/* 2^51 - 2^1 */ fe25519_square(&t,&z2_50_0);
	/* 2^100 - 2^50 */ for (i = 1;i < 50;i++) { fe25519_square(&t,&t); }
	/* 2^100 - 2^0 */ fe25519_mul(&z2_100_0,&t,&z2_50_0);

	/* 2^101 - 2^1 */ fe25519_square(&t,&z2_100_0);
	/* 2^200 - 2^100 */ for (i = 1;i < 100;i++) { fe25519_square(&t,&t); }
	/* 2^200 - 2^0 */ fe25519_mul(&t,&t,&z2_100_0);

	/* 2^201 - 2^1 */ fe25519_square(&t,&t);
	/* 2^250 - 2^50 */ for (i = 1;i < 50;i++) { fe25519_square(&t,&t); }
	/* 2^250 - 2^0 */ fe25519_mul(&t,&t,&z2_50_0);

	/* 2^251 - 2^1 */ fe25519_square(&t,&t);
	/* 2^252 - 2^2 */ fe25519_square(&t,&t);
	/* 2^252 - 3 */ fe25519_mul(r,&t,x);
}
