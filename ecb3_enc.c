#include "shahai_des_locl.h"
#include "shahai_spr.h"

void DES_encrypt2(DES_LONG *data, DES_key_schedule *ks, int enc)
{
	register DES_LONG l,r,t,u;

#ifndef DES_UNROLL
	register int i;
#endif
	register DES_LONG *s;

	r=data[0];
	l=data[1];

	/* Things have been modified so that the initial rotate is
	 * done outside the loop.  This required the
	 * DES_SPtrans values in sp.h to be rotated 1 bit to the right.
	 * One perl script later and things have a 5% speed up on a sparc2.
	 * Thanks to Richard Outerbridge <71755.204@CompuServe.COM>
	 * for pointing this out. */
	/* clear the top bits on machines with 8byte longs */
	r=ROTATE(r,29)&0xffffffffL;
	l=ROTATE(l,29)&0xffffffffL;

	s=ks->ks->deslong;

	if (enc)
	{
		for (i=0; i<32; i+=4)
		{
			D_ENCRYPT(l,r,i+0); /*  1 */
			D_ENCRYPT(r,l,i+2); /*  2 */
		}
	}
	else
	{
		for (i=30; i>0; i-=4)
		{
			D_ENCRYPT(l,r,i-0); /* 16 */
			D_ENCRYPT(r,l,i-2); /* 15 */
		}

	}
	/* rotate and clear the top bits on machines with 8byte longs */
	data[0]=ROTATE(l,3)&0xffffffffL;
	data[1]=ROTATE(r,3)&0xffffffffL;
	l=r=t=u=0;
}

void DES_encrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3)
{
	register DES_LONG l,r;

	l=data[0];
	r=data[1];
	IP(l,r);
	data[0]=l;
	data[1]=r;
	DES_encrypt2((DES_LONG *)data,ks1,DES_ENCRYPT);
	DES_encrypt2((DES_LONG *)data,ks2,DES_DECRYPT);
	DES_encrypt2((DES_LONG *)data,ks3,DES_ENCRYPT);
	l=data[0];
	r=data[1];
	FP(r,l);
	data[0]=l;
	data[1]=r;
}

void DES_decrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3)
{
	register DES_LONG l,r;

	l=data[0];
	r=data[1];
	IP(l,r);
	data[0]=l;
	data[1]=r;
	DES_encrypt2((DES_LONG *)data,ks3,DES_DECRYPT);
	DES_encrypt2((DES_LONG *)data,ks2,DES_ENCRYPT);
	DES_encrypt2((DES_LONG *)data,ks1,DES_DECRYPT);
	l=data[0];
	r=data[1];
	FP(r,l);
	data[0]=l;
	data[1]=r;
}

void DES_ecb3_encrypt(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks1,
					  DES_key_schedule *ks2, DES_key_schedule *ks3, int enc)
{
	register DES_LONG l0,l1;
	DES_LONG ll[2];
	const unsigned char *in = &(*input)[0];
	unsigned char *out = &(*output)[0];

	c2l(in,l0);
	c2l(in,l1);
	ll[0]=l0;
	ll[1]=l1;

	if (enc)
	{
		DES_encrypt3(ll,ks1,ks2,ks3);
	}
	else
	{
		DES_decrypt3(ll,ks1,ks2,ks3);
	}
	l0=ll[0];
	l1=ll[1];
	l2c(l0,out);
	l2c(l1,out);
}
