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
 * man了一下查到openssl提供DES_ecb3_encrypt方法，正合我意！
 * 提示：openssl库支持很多加密算法哦，如：AES/DES/MD5/RSA...，
 * 
 * 具体使用时需要注意des算法的加密模式、密钥长度、补齐方式，
 * 我这里采用3des的ECB方式、24位密钥（不足右补0）、内容长度以8字节切分，不能被8整除的末尾部分，根据长度不足8字节的部分
 * 
 * des加密密钥也是8位来处理的，所以在密钥置换时只取8位
 *
 */
int main_test(int argc, char **argv)
{
	int do_continue = 1;
	char *data = "1234";    /* 明文 */

	

	char *temp_ch = NULL;
	int data_len;
	int data_rest;
	unsigned char ch;
	unsigned char *src = NULL;  /* 补齐后的明文 */
	unsigned char *dst = NULL;  /* 解密后的明文 */

	int len;
	unsigned char tmp[8];
	unsigned char in[8];
	unsigned char out[8];

	char *k = "123456789012345678901234";  /* 原始密钥 */ 
	int key_len;
	unsigned char key[LEN_OF_KEY];     /* 补齐后的密钥 */
	unsigned char block_key[9];
	DES_key_schedule ks, ks2, ks3;

	key_len = strlen(k);  /* 构造补齐后的密钥 */
	test_len(data);
	memcpy(key, k, key_len);
	memset(key + key_len, 0x00, LEN_OF_KEY - key_len); /* 秘钥长度24 */

	data_len = strlen(data);  /* 分析补齐明文所需空间及补齐填充数据 */
	data_rest = data_len % 8;
	len = data_len + (8 - data_rest); /* 补齐后的明文长度 */
	ch = 8 - data_rest;  /* 需要补齐明文的字节数 */

	src = (unsigned char *)malloc(len);
	dst = (unsigned char *)malloc(len);
	
	if(NULL == src || NULL == dst)
		do_continue = 0;

	if(do_continue)
	{
		int count;
		int i;

		/* 构造补齐后的加密内容 */
		memset(src, 0, len);  
		memcpy(src, data, data_len);
		printf("%s \n", src);
		memset(src + data_len, ch, 8 - data_rest);
		printf("%s \n", src);


		/* 密钥置换 */
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

			/* 加密 */ 
			DES_ecb3_encrypt((const_DES_cblock *)tmp, (DES_cblock *)in, &ks, &ks2, &ks3, DES_ENCRYPT);

			for (index = 0; index < len; index++)
				printf("%02x", *(in + index));

			/* 解密 */
			DES_ecb3_encrypt((const_DES_cblock *)in, (DES_cblock *)out, &ks, &ks2, &ks3, DES_DECRYPT);
		
			memcpy(dst + 8 * i, out, 8);   /* 将解密的内容拷贝到解密后的明文 */
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