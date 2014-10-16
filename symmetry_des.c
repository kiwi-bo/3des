/**
 * symmetry_des.c --> symmetry_des.h��ʵ�ִ���
 *
 */

#include "shahai_des_locl.h"

char original_key[61] = 
{
	'1', '2' , '4', '5', '7', '5', '6', '7', '4', '8','1', '2' , '4', '5', '7', '5', '6', '7', '4', '8',
	'6', '8' , '4', '5', '7', '5', '6', '7', '4', '0','1', '4' , '4', '5', '7', '2', '6', '7', '1', '6',
	'1', '2' , '9', '9', '6', '5', '9', '7', '9', '8','1', '2' , '4', '1', '7', '5', '6', '7', '1', '5',
	'\0'
};

extern char original_key[61];
/** 
 * ��ԭʼ��Կoriginal_key[61]�õ���ʵ����Կ
 * o_key��ԭʼ��60λ��Կ;  r_key����ʵ��24λ��Կ
 */
int get_key(const unsigned char *o_key, unsigned char *r_key)
{
	// key = 60 λ(ԭʼ)��(tk =  key[5,25),  ttk = tk+tk[0,4)  ,  ttk����ʵ��Կ)
	// ������ԭ������ͻص�������Կ��
	unsigned char tk[21];
	unsigned char ttk[25];
	unsigned int i;
	for(i = 0; i < 20; i++)
	{
		tk[i] = *(o_key + i + 5);
	}
	tk[i] = '\0';

	memcpy(ttk, tk, 20);

	for (i = 0; i < 4; i++)
	{
		ttk[20 + i] = tk[i];
	}
	ttk[20 + i] = '\0';

	memcpy(r_key, ttk, 24);

	r_key[LEN_OF_KEY] = '\0';

	return -1;
}
/** 
 * plain_text:�����ܵ�����; main_key:xml���е�����Կ; secondary_key:xml���н���Ĵ���Կ
 *
 */
int DES_Encrypt(unsigned char *p_in, unsigned char *primary_key, unsigned char *secondary_key, unsigned char *p_cipher)
{
	return 0;
}

/** 
 * 3dec ecb ���ܺ���
 * p_in:��������; p_out:�������(����ʱ��һ�δ���һ��NULL,ʹ�õ��ú������P_out_len��ֵ,���ú�����������Ӧ��С�Ŀռ�);
 * key:��Կ
 *
 */
int do_des_ecb3_encrypt(unsigned char *p_in, unsigned char *p_out, int *p_out_len, unsigned char *key_temp)
{
	unsigned int do_continue = 1;

	unsigned char *data = p_in;
	unsigned char *temp_ch = NULL;
	unsigned int data_len, data_rest, len;
	unsigned char ch;
	unsigned char *src = NULL;  /* ���������� */
	unsigned char *dst = NULL;  /* ���ܺ������ */

	unsigned char tmp[8];
	unsigned char out[8];

	unsigned char *k = key_temp; /* ԭʼ��Կ */
	unsigned int key_len;
	unsigned char key[LEN_OF_KEY];     /* ��������Կ */
	unsigned char block_key[9];
	DES_key_schedule ks1, ks2, ks3;

	data_len = strlen(data);  /* ����������������ռ估����������� */
	data_rest = data_len % 8;
	len = data_len + (8 - data_rest); /* ���������ĳ��� */
	ch = 8 - data_rest;  /* ��Ҫ�������ĵ��ֽ��� */

/*	printf("data_len --> %d \n", data_len);*/

	if (NULL == p_out)
	{
		*p_out_len = len;
		return OUT_IS_NULL;
	}

	src = (unsigned char *)malloc(len);
	dst = p_out;

	key_len = strlen(k);  /* ���첹������Կ */
/*	printf("key_len = %d", key_len);*/
	if(key_len > LEN_OF_KEY)
		return DES_PASSWORD_ERROR;

	memcpy(key, k, key_len);
	memset(key + key_len, 0x00, LEN_OF_KEY - key_len); /* ��Կ����24 */

	if(NULL == src || NULL == dst)
		do_continue = 0;

	if(do_continue)
	{
		int count;
		int i;

		/* ���첹�����Ҫ������������� */
		memset(src, 0, len);  
		memcpy(src, data, data_len);
		memset(src + data_len, ch, 8 - data_rest);

		/* ��Կ�û� */
		memset(block_key, 0, sizeof(block_key));

		memcpy(block_key, key + 0, 8);
		DES_set_key_unchecked((const_DES_cblock *)block_key, &ks1);

		memcpy(block_key, key + 8, 8);
		DES_set_key_unchecked((const_DES_cblock *)block_key, &ks2);

		memcpy(block_key, key + 16, 8);
		DES_set_key_unchecked((const_DES_cblock *)block_key, &ks3);

		count = len / 8;
		for (i = 0; i < count; i++)
		{
			memset(tmp, 0, 8);
			memset(out, 0, 8);
			memcpy(tmp, src + 8 * i, 8);

			DES_ecb3_encrypt((const_DES_cblock *)tmp, (DES_cblock *)out, &ks1, &ks2, &ks3, DES_ENCRYPT);
			memcpy(dst + 8 * i, out, 8);   /* ������(���ܻ����)֮������ݿ���������ռ� */
		}

		dst[8 * i] = '\0'; // �ַ���������

// 		printf("\n after %d : \n",strlen(dst));
// 		
// 		for (i = 0; i < len; i++)
// 			printf("%02x", *(dst + i));
// 		printf("\n");
	}

	if(NULL != src)
	{
		free(src);
		src = NULL;
	}

	return DES_ENCRYPT_OK;
}




/** 
 * 3dec ecb �����ܺ���(���ɼ���Ҳ���Խ��� �ɲ���enc����)
 * p_in:��������; p_out:�������(����ʱ��һ�δ���һ��NULL,ʹ�õ��ú������P_out_len��ֵ,���ú�����������Ӧ��С�Ŀռ�);
 * key:��Կ
 *
 */
int do_des_ecb3_decode(unsigned char *p_in, unsigned char *p_out, int *p_out_len, unsigned char *key_temp)
{
	unsigned int do_continue = 1;
	unsigned char *data = p_in;
	unsigned char *temp_ch = NULL;
	unsigned int data_len;
	unsigned int data_rest;

	unsigned int count_fill; // ����֮�����ı������ַ�����

	unsigned char *dst = NULL;  /* ���ܺ������ */

	unsigned char tmp[8];
	unsigned char out[8];

	unsigned char *k = key_temp; /* ԭʼ��Կ */
	unsigned int key_len;
	unsigned char key[LEN_OF_KEY];     /* ��������Կ */
	unsigned char block_key[9];
	DES_key_schedule ks1, ks2, ks3;

	unsigned char *temp = NULL;

	data_len = strlen(data);  /* ����������������ռ估����������� */
	data_rest = data_len % 8;

	if(0 != data_rest)
		return -1;  // �������ݸ�������8��������

	if (NULL == p_out)
	{
		*p_out_len = data_len;
		return OUT_IS_NULL;
	}

	dst = p_out;

	key_len = strlen(k);  /* ���첹������Կ */

/*	printf("key_len   ---->    %d  \n", key_len);*/
	if(key_len > LEN_OF_KEY)
		return DES_PASSWORD_ERROR;
	memcpy(key, k, key_len);
	memset(key + key_len, 0x00, LEN_OF_KEY - key_len); /* ��Կ����24 */

	if(NULL == data || NULL == dst)
		do_continue = 0;

	if(do_continue)
	{
		int count;
		int i;

		/* ��Կ�û� */
		memset(block_key, 0, sizeof(block_key));

		memcpy(block_key, key + 0, 8);
		DES_set_key_unchecked((const_DES_cblock *)block_key, &ks1);

		temp = (unsigned char *)&ks1;
		printf("========\n");
		for(i = 0; i < sizeof(DES_key_schedule); i++)
			printf("%02x", *(temp + i));
		printf("\n========\n");

		memcpy(block_key, key + 8, 8);
		DES_set_key_unchecked((const_DES_cblock *)block_key, &ks2);

		memcpy(block_key, key + 16, 8);
		DES_set_key_unchecked((const_DES_cblock *)block_key, &ks3);

		count = data_len / 8;
		for (i = 0; i < count; i++)
		{
			memset(tmp, 0, 8);
			memset(out, 0, 8);
			memcpy(tmp, data + 8 * i, 8);

			DES_ecb3_encrypt((const_DES_cblock *)tmp, (DES_cblock *)out, &ks1, &ks2, &ks3, DES_DECRYPT);
			memcpy(dst + 8 * i, out, 8);   /* ������(���ܻ����)֮������ݿ���������ռ� */
		}

		dst[8 * i] = '\0'; // �ַ���������
	}

	count_fill = *(dst + data_len - 1);  // �õ�ԭʼ���ı����ĸ���

	dst[data_len - count_fill] = '\0';  // �����ַ���


	return DES_ENCRYPT_OK;
}

/** 
 * ���� ��������Կ
 */
int des_decode_k(unsigned char *km, unsigned char *ks)
{
	return 0;
}

/** 
 * km: ����Կ������;  ks:����Կ������
 * �Ƚ���xml���ġ� ���ҽ��������ݽ��н�base64������Ȼ���������̡�
 * 1��key = 60 λ(ԭʼ), (tk =  key[5,25),  ttk = tk+tk[0,4),  ttk����ʵ��Կ)  get_key()�����õ�ttk��
 * 2�����ʱ  "shahai_key_main"--> Km,  "shahai_key_sec"--> ks
 * 3��ʹ��ttk����ԭ������Կ��( ����Կʹ������Կ���л�ԭ).
 * 4���Ȼ�ԭ����Կ   byte [] rmk = 3des(ttk, km);
 * 5������Կ�� byte [] rsk=3des(rmk,ks)
 * 6���ͻ������ݼ���. (keymain, keysec �Ѿ���ȫ��ԭ������£�ִ�иò���)
 *    ���� plaintext .  ����Կrmk, ����Կ rsk
 *    һ�����   byte [] firstEnStr = 3des(rsk,plaintext)
 *    �������   byte [] secEnStr = 3des(rmk,firstEnStr);
 *
 */
int do_main_des_encrypt(char *plaintext,unsigned char *km, unsigned char *ks, unsigned char **p_cipher/*, unsigned char *rmk, unsigned char *rsk*/)
{
	unsigned int out_len;
	unsigned char *rmk = NULL;
	unsigned char *rsk = NULL;
	unsigned char *firstEnStr = NULL;
	unsigned char *secEnStr = NULL;
	int ret;

	int i;

	unsigned char *ttk = (unsigned char *)malloc(LEN_OF_KEY + 1);
	get_key(original_key, ttk);

	/*****  ��������Կ  *****/
	if(OUT_IS_NULL == do_des_ecb3_decode(km, NULL, &out_len, ttk))
	{
		rmk = (unsigned char *)malloc(out_len + 1);
	}
	// �ɹ����ܺ󷵻�DES_ENCRYPT_OK;���ҽ���֮ǰprimary_cipher_k���ĳ���24������֮��ҲӦ����24�ֽڵ�����
	if(DES_ENCRYPT_OK != do_des_ecb3_decode(km, rmk, &out_len, ttk) || 24 != strlen(rmk))
	{
		printf("rmk decode error\n");
		return DES_ENCRYPT_OK;
	}
	
	/*****  ���ܴ���Կ��Կ  *****/
	if(OUT_IS_NULL == do_des_ecb3_decode(ks, NULL, &out_len, rmk))
	{
		rsk = (unsigned char *)malloc(out_len + 1);
	}
	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_decode(ks, rsk, &out_len, rmk)) || 24 != strlen(rsk))
	{
		return ret;
	}

// 	printf("\nencrypt   ttk ==> %s \n", ttk);
// 	printf("24 != strlen(rmk) |%d| |%s| \n",strlen(rmk), rmk);
// 	printf("24 != strlen(rsk) |%d| |%s| \n",strlen(rsk), rsk);

	/******* ���ļ���,һ����� *******/
	if(OUT_IS_NULL == do_des_ecb3_encrypt(plaintext, NULL, &out_len, rsk))
	{
		firstEnStr = (unsigned char *)malloc(out_len + 1);
	}

	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_encrypt(plaintext, firstEnStr, &out_len, rsk)))
		return ret;

// 	printf("\n encrypt firstEnStr \n");
// 	for(i = 0; i < strlen(firstEnStr); i++)
// 		printf("%02x", *(firstEnStr + i));
// 	printf("\n");

	/******* ���ļ���,������� *******/
	if(OUT_IS_NULL == do_des_ecb3_encrypt(firstEnStr, NULL, &out_len, rmk))
	{
		secEnStr = (unsigned char *)malloc(out_len + 1);
	}

	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_encrypt(firstEnStr, secEnStr, &out_len, rmk)))
		return ret;

	*p_cipher = secEnStr;

	printf("\n encrypt secEnStr===================%d \n", strlen(secEnStr));
	for(i = 0; i < strlen(secEnStr); i++)
		printf("%02X", *(secEnStr + i));

	printf("\n ===================% \n", strlen(secEnStr));

	return 0;
}


int do_main_des_decode(unsigned char *cipher,unsigned char *km, unsigned char *ks, unsigned char **plain/*, unsigned char *rmk, unsigned char *rsk*/)
{
	unsigned int out_len;
	unsigned char *rmk = NULL;
	unsigned char *rsk = NULL;
	unsigned char *firstEnStr = NULL;
	unsigned char *plaintext = NULL;
	unsigned char *ttk = (unsigned char *)malloc(LEN_OF_KEY + 1);

	int ret;

	get_key(original_key, ttk);
	
// 	printf("\ncipher  decode    %d \n",strlen(cipher));
// 	for(i = 0; i < strlen(cipher); i++)
// 		printf("%02X", *(cipher + i));


	/*****  ��������Կ  *****/
	if(OUT_IS_NULL == do_des_ecb3_decode(km, NULL, &out_len, ttk))
	{
		rmk = (unsigned char *)malloc(out_len + 1);
	}

	// �ɹ����ܺ󷵻�DES_ENCRYPT_OK;���ҽ���֮ǰprimary_cipher_k���ĳ���24������֮��ҲӦ����24�ֽڵ�����
	if(DES_ENCRYPT_OK != do_des_ecb3_decode(km, rmk, &out_len, ttk) || 24 != strlen(rmk))
	{
		printf("rmk decode error\n");
		return DES_ENCRYPT_OK;
	}

	/*****  ���ܴ���Կ��Կ  *****/
	if(OUT_IS_NULL == do_des_ecb3_decode(ks, NULL, &out_len, rmk))
	{
		rsk = (unsigned char *)malloc(out_len + 1);
	}
	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_decode(ks, rsk, &out_len, rmk)) || 24 != strlen(rsk))
		return ret;

// 	printf("\nttk ==> %s \n", ttk);
// 	printf("24 != strlen(rmk) |%d| |%s| \n",strlen(rmk), rmk);
// 	printf("24 != strlen(rsk) |%d| |%s| \n",strlen(rsk), rsk);

	/******* ���Ľ���,һ����� *******/
	if(OUT_IS_NULL == do_des_ecb3_decode(cipher, NULL, &out_len, rmk))
	{
		firstEnStr = (unsigned char *)malloc(out_len + 1);
	}

	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_decode(cipher, firstEnStr, &out_len, rmk)))
		return ret;

// 	printf("\n decode firstEnStr \n");
// 	for(i = 0; i < strlen(firstEnStr); i++)
// 		printf("%02x", *(firstEnStr + i));
// 	printf("\n");


	/******* ���Ľ���,������� *******/
	if(OUT_IS_NULL == do_des_ecb3_decode(firstEnStr, NULL, &out_len, rsk))
	{
		plaintext = (unsigned char *)malloc(out_len + 1);
	}

	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_decode(firstEnStr, plaintext, &out_len, rsk)))
		return ret;

// 	printf("\n decode  plaintext \n");
// 	for(i = 0; i < strlen(plaintext); i++)
// 		printf("%02X", *(plaintext + i));
// 	printf("\n");
// 
// 	printf("%s %d \n", plaintext, strlen(plaintext));

	*plain = plaintext;

	return 0;
}


/** 
 * �Ƚ���xml���ġ� ���ҽ��������ݽ��н�base64������Ȼ���������̡�
 * 1��key = 60 λ(ԭʼ), (tk =  key[5,25),  ttk = tk+tk[0,4),  ttk����ʵ��Կ)  get_key()�����õ�ttk��
 * 2�����ʱ  "shahai_key_main"--> Km,  "shahai_key_sec"--> ks
 * 3��ʹ��ttk����ԭ������Կ��( ����Կʹ������Կ���л�ԭ).
 * 4���Ȼ�ԭ����Կ   byte [] rmk = 3des(ttk, km);
 * 5������Կ�� byte [] rsk=3des(rmk,ks)
 */
int cread_tesk_k(unsigned char **k_m, unsigned char **k_s)
{
	unsigned char *tkm = "123456788765432112345678";
	unsigned char *tks = "876543211234567887654321";

	unsigned char *km = NULL;
	unsigned char *ks = NULL;

	int out_len, ret;

	unsigned char *ttk = (unsigned char *)malloc(LEN_OF_KEY + 1);
	get_key(original_key, ttk);
	/*printf("%d ==== \n", strlen(tks));*/

	/******* ��������Կ *******/
	if(OUT_IS_NULL == do_des_ecb3_encrypt(tkm, NULL, &out_len, ttk))
	{
		km = (unsigned char *)malloc(out_len + 1);
	}
	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_encrypt(tkm, km, &out_len, ttk)))
		return ret;

	/******* ���ܴ���Կ *******/
	if(OUT_IS_NULL == do_des_ecb3_encrypt(tks, NULL, &out_len, tkm))
	{
		ks = (unsigned char *)malloc(out_len + 1);
	}

	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_encrypt(tks, ks, &out_len, tkm)))
		return ret;

	*k_m = km;
	*k_s = ks;

	return 0;
}

/** 
 * DES_ecb3_encrypt����
 * 
 * ����ʹ��ʱ��Ҫע��des�㷨�ļ���ģʽ����Կ���ȡ����뷽ʽ��
 * ���������3des��ECB��ʽ��24λ��Կ�������Ҳ�0�������ݳ�����8�ֽ��з֣����ܱ�8������ĩβ���֣����ݳ��Ȳ���8�ֽڵĲ���
 * 
 * des������ԿҲ��8λ������ģ���������Կ�û�ʱֻȡ8λ
 *
 */
