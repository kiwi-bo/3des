#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/des.h>

#define LEN_OF_KEY 24


int test_len(unsigned char *tmp)
{

	printf("test_len -- > %d\n", strlen(tmp));
	return 0;
}


/** 
 * man��һ�²鵽openssl�ṩDES_ecb3_encrypt�������������⣡
 * ��ʾ��openssl��֧�ֺܶ�����㷨Ŷ���磺AES/DES/MD5/RSA...��
 * 
 * ����ʹ��ʱ��Ҫע��des�㷨�ļ���ģʽ����Կ���ȡ����뷽ʽ��
 * ���������3des��ECB��ʽ��24λ��Կ�������Ҳ�0�������ݳ�����8�ֽ��з֣����ܱ�8������ĩβ���֣����ݳ��Ȳ���8�ֽڵĲ���
 * 
 * des������ԿҲ��8λ������ģ���������Կ�û�ʱֻȡ8λ
 *
 */
int main_test(int argc, char **argv)
{
	int do_continue = 1;
	char *data = "1234";    /* ���� */

	

	char *temp_ch = NULL;
	int data_len;
	int data_rest;
	unsigned char ch;
	unsigned char *src = NULL;  /* ���������� */
	unsigned char *dst = NULL;  /* ���ܺ������ */

	int len;
	unsigned char tmp[8];
	unsigned char in[8];
	unsigned char out[8];

	char *k = "123456789012345678901234";  /* ԭʼ��Կ */ 
	int key_len;
	unsigned char key[LEN_OF_KEY];     /* ��������Կ */
	unsigned char block_key[9];
	DES_key_schedule ks, ks2, ks3;

	key_len = strlen(k);  /* ���첹������Կ */
	test_len(data);
	memcpy(key, k, key_len);
	memset(key + key_len, 0x00, LEN_OF_KEY - key_len); /* ��Կ����24 */

	data_len = strlen(data);  /* ����������������ռ估����������� */
	data_rest = data_len % 8;
	len = data_len + (8 - data_rest); /* ���������ĳ��� */
	ch = 8 - data_rest;  /* ��Ҫ�������ĵ��ֽ��� */

	src = (unsigned char *)malloc(len);
	dst = (unsigned char *)malloc(len);
	
	if(NULL == src || NULL == dst)
		do_continue = 0;

	if(do_continue)
	{
		int count;
		int i;

		/* ���첹���ļ������� */
		memset(src, 0, len);  
		memcpy(src, data, data_len);
		printf("%s \n", src);
		memset(src + data_len, ch, 8 - data_rest);
		printf("%s \n", src);


		/* ��Կ�û� */
		memset(block_key, 0, sizeof(block_key));

		memcpy(block_key, key + 0, 8);
		DES_set_key_unchecked((const_DES_cblock *)block_key, &ks);

		memcpy(block_key, key + 8, 8);
		DES_set_key_unchecked((const_DES_cblock *)block_key, &ks2);

		memcpy(block_key, key + 16, 8);
		DES_set_key_unchecked((const_DES_cblock *)block_key, &ks3);


		printf("before encrypt: \n");
		for (i = 0; i < len; i++)
			printf("%02x", *(src + i));

		printf("\n");

		count = len / 8;
		for (i = 0; i < count; i++)
		{
			int index;
			memset(tmp, 0, 8);
			memset(in, 0, 8);
			memset(out, 0, 8);
			memcpy(tmp, src + 8 * i, 8);

			/* ���� */ 
			DES_ecb3_encrypt((const_DES_cblock *)tmp, (DES_cblock *)in, &ks, &ks2, &ks3, DES_ENCRYPT);

			for (index = 0; index < len; index++)
				printf("%02x", *(in + index));

			/* ���� */
			DES_ecb3_encrypt((const_DES_cblock *)in, (DES_cblock *)out, &ks, &ks2, &ks3, DES_DECRYPT);
		
			memcpy(dst + 8 * i, out, 8);   /* �����ܵ����ݿ��������ܺ������ */
		}
		printf("\nafter decrypt : \n");


		for (i = 0; i < len; i++)
			printf("%02x", *(dst + i));

		memcpy(dst, dst, data_len);

		printf("===========> %s \n", dst);

		printf("\n");
	}

	if(NULL != src)
	{
		free(src);
		src = NULL;
	}

	if(NULL != dst)
	{
		free(dst);
		dst = NULL;
	}

	getchar();

	return 0;
}