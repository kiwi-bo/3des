/** 
 *  add lzp
 */

#ifndef _SHAHAI_DES_LOCAL_H_
#define _SHAHAI_DES_LOCAL_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "shahai_e_os2.h"

#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#ifndef DES_LONG
#define DES_LONG unsigned long
#endif

#define ITERATIONS 16
#define HALF_ITERATIONS 8

#define PARAMETER_ERROR  -3300  // ²ÎÊý´íÎó
#define OUT_IS_NULL      -3301  // Êä³ö²ÎÊý¿Õ¼äÎª¿Õ
#define DES_PASSWORD_ERROR   -3303  // DESÃØÔ¿´íÎó
#define DES_ENCRYPT_OK       0  // DESÃØÔ¿´íÎó
#define LEN_OF_KEY       24        // 3DESÃØÔ¿



#if (defined(OPENSSL_SYS_WIN32) && defined(_MSC_VER)) || defined(__ICC)
#define	ROTATE(a,n)	(_lrotr(a,n))
#elif defined(__GNUC__) && __GNUC__>=2 && !defined(__STRICT_ANSI__) && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM) && !defined(PEDANTIC)
# if defined(__i386) || defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
#  define ROTATE(a,n)	({ register unsigned int ret;	\
	asm ("rorl %1,%0"	\
	: "=r"(ret)	\
	: "I"(n),"0"(a)	\
	: "cc");	\
	ret;				\
			})
# endif
#endif

// # define ROTATE(a,n)	({ register unsigned int ret;	\
// 	asm ("rorl %1,%0"	\
// 	: "=r"(ret)	\
// 	: "I"(n),"0"(a)	\
// 	: "cc");	\
// 	ret;				\
// 	})



#define LOAD_DATA_tmp(a,b,c,d,e,f) LOAD_DATA(a,b,c,d,e,f,g)
#define LOAD_DATA(R,S,u,t,E0,E1,tmp) \
	u=R^s[S  ]; \
	t=R^s[S+1]

#define c2l(c,l)	(l =((DES_LONG)(*((c)++)))    , \
	l|=((DES_LONG)(*((c)++)))<< 8L, \
	l|=((DES_LONG)(*((c)++)))<<16L, \
	l|=((DES_LONG)(*((c)++)))<<24L)

#define PERM_OP(a,b,t,n,m) ((t)=((((a)>>(n))^(b))&(m)),\
	(b)^=(t),\
	(a)^=((t)<<(n)))

#define HPERM_OP(a,t,n,m) ((t)=((((a)<<(16-(n)))^(a))&(m)),\
	(a)=(a)^(t)^(t>>(16-(n))))

#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)     )&0xff), \
	*((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
	*((c)++)=(unsigned char)(((l)>>16L)&0xff), \
	*((c)++)=(unsigned char)(((l)>>24L)&0xff))

#define IP(l,r) \
	{ \
	register DES_LONG tt; \
	PERM_OP(r,l,tt, 4,0x0f0f0f0fL); \
	PERM_OP(l,r,tt,16,0x0000ffffL); \
	PERM_OP(r,l,tt, 2,0x33333333L); \
	PERM_OP(l,r,tt, 8,0x00ff00ffL); \
	PERM_OP(r,l,tt, 1,0x55555555L); \
	}

#define FP(l,r) \
	{ \
	register DES_LONG tt; \
	PERM_OP(l,r,tt, 1,0x55555555L); \
	PERM_OP(r,l,tt, 8,0x00ff00ffL); \
	PERM_OP(l,r,tt, 2,0x33333333L); \
	PERM_OP(r,l,tt,16,0x0000ffffL); \
	PERM_OP(l,r,tt, 4,0x0f0f0f0fL); \
	}

#define D_ENCRYPT(LL,R,S) {\
	LOAD_DATA_tmp(R,S,u,t,E0,E1); \
	t=ROTATE(t,4); \
	LL^=\
	DES_SPtrans[0][(u>> 2L)&0x3f]^ \
	DES_SPtrans[2][(u>>10L)&0x3f]^ \
	DES_SPtrans[4][(u>>18L)&0x3f]^ \
	DES_SPtrans[6][(u>>26L)&0x3f]^ \
	DES_SPtrans[1][(t>> 2L)&0x3f]^ \
	DES_SPtrans[3][(t>>10L)&0x3f]^ \
	DES_SPtrans[5][(t>>18L)&0x3f]^ \
	DES_SPtrans[7][(t>>26L)&0x3f]; }

typedef unsigned char DES_cblock[8];
typedef /* const */ unsigned char const_DES_cblock[8];
typedef struct DES_ks
{
	union
	{
		DES_cblock cblock;
		/* make sure things are correct size on machines with
		 * 8 byte longs */
		DES_LONG deslong[2];
	}ks[16];
} DES_key_schedule;

#define des_encrypt3(d,k1,k2,k3)\
	DES_encrypt3((d),&(k1),&(k2),&(k3))

void DES_set_key_unchecked(const_DES_cblock *key, DES_key_schedule *schedule);

void DES_encrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3);

void DES_ecb3_encrypt(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks1,DES_key_schedule *ks2, DES_key_schedule *ks3, int enc);

void DES_encrypt2(DES_LONG *data, DES_key_schedule *ks, int enc);
void DES_encrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3);

void DES_decrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3);

void DES_ecb3_encrypt(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks1,
					  DES_key_schedule *ks2, DES_key_schedule *ks3, int enc);


// add lzp

int get_key(const unsigned char *o_key, unsigned char *r_key);

int DES_Encrypt(unsigned char *p_in, unsigned char *primary_key, unsigned char *secondary_key, unsigned char *p_cipher);

int do_des_ecb3_encrypt(unsigned char *p_in, unsigned char *p_out, int *p_out_len, unsigned char *key_temp);

int do_des_ecb3_decode(const unsigned char *p_in, unsigned char *p_out, int *p_out_len, unsigned char *key_temp);

int do_main_des_encrypt(unsigned char *plaintext,unsigned char *km, unsigned char *ks, unsigned char *p_cipher/*, unsigned char *rmk, unsigned char *rsk*/);

int do_main_des_decode(unsigned char *cipher,unsigned char *km, unsigned char *ks, unsigned char *plain/*, unsigned char *rmk, unsigned char *rsk*/);

int cread_tesk_k(unsigned char *k_m, unsigned char *k_s);

int des_decode_k(const unsigned char *km, const unsigned char *ks, unsigned char *m_key, unsigned char *s_key);

#endif


