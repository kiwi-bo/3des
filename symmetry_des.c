/**
 * symmetry_des.c --> symmetry_des.h的实现代码
 *
 */

#include "shahai_des_locl.h"



char original_key[61] = 
{//123456789012345678901234567890123456789012345678901234567890
	'1', '2' , '3', '4', '5', '6', '7', '8', '9', '0','1', '2' , '3', '4', '5', '6', '7', '8', '9', '0',
	'1', '2' , '3', '4', '5', '6', '7', '8', '9', '0','1', '2' , '3', '4', '5', '6', '7', '8', '9', '0',
	'1', '2' , '3', '4', '5', '6', '7', '8', '9', '0','1', '2' , '3', '4', '5', '6', '7', '8', '9', '0',
	'\0'
};
/*extern char original_key[60];*/

/** 
 * 用原始秘钥original_key[60]得到真实的秘钥
 * o_key：原始的60位秘钥(可以在调用时重新传入一个60位字符数组,作为原始秘钥);  r_key：得到真实的24位秘钥
 *
 */
int get_key(const unsigned char *o_key, unsigned char *r_key)
{
	// key = 60 位(原始)，(tk =  key[5,25),  ttk = tk+tk[0,4)  ,  ttk是真实密钥)
	// 用来还原服务端送回的两个密钥。
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
 * plain_text:待加密的明文; main_key:xml包中的主秘钥; secondary_key:xml包中解码的次秘钥
 *
 */
int DES_Encrypt(unsigned char *p_in, unsigned char *primary_key, unsigned char *secondary_key, unsigned char *p_cipher)
{
	return 0;
}

/** 
 * 3dec ecb 加密函数
 * p_in:输入数据; p_out:输出数据(调用时第一次传入一个NULL,使得调用函数获得P_out_len的值,调用函数再申请相应大小的空间);
 * key:秘钥
 *
 */
int do_des_ecb3_encrypt(unsigned char *p_in, unsigned char *p_out, int *p_out_len, unsigned char *key_temp)
{
	unsigned int do_continue = 1;

	unsigned char *data = p_in;
	unsigned char *temp_ch = NULL;
	unsigned int data_len, data_rest, len;
	unsigned char ch;
	unsigned char *src = NULL;  /* 补齐后的明文 */
	unsigned char *dst = NULL;  /* 解密后的明文 */

	unsigned char tmp[8];
	unsigned char out[8];

	unsigned char *k = key_temp; /* 原始密钥 */
	unsigned int key_len;
	unsigned char key[LEN_OF_KEY];     /* 补齐后的密钥 */
	unsigned char block_key[9];
	DES_key_schedule ks1, ks2, ks3;

	data_len = strlen(data);  /* 分析补齐明文所需空间及补齐填充数据 */
	data_rest = data_len % 8;
	len = data_len + (8 - data_rest); /* 补齐后的明文长度 */
	ch = 8 - data_rest;  /* 需要补齐明文的字节数 */

/*	printf("data_len --> %d \n", data_len);*/

	if (NULL == p_out)
	{
		*p_out_len = len;
		return OUT_IS_NULL;
	}

	src = (unsigned char *)malloc(len);
	dst = p_out;

	key_len = strlen(k);  /* 构造补齐后的密钥 */
/*	printf("key_len = %d", key_len);*/
	if(key_len > LEN_OF_KEY)
		return DES_PASSWORD_ERROR;

	memcpy(key, k, key_len);
	memset(key + key_len, 0x00, LEN_OF_KEY - key_len); /* 秘钥长度24 */

	if(NULL == src || NULL == dst)
		do_continue = 0;

	if(do_continue)
	{
		int count;
		int i;

		/* 构造补齐后需要处理的数据内容 */
		memset(src, 0, len);  
		memcpy(src, data, data_len);
		memset(src + data_len, ch, 8 - data_rest);

		/* 密钥置换 */
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
			memcpy(dst + 8 * i, out, 8);   /* 将处理(加密或解密)之后的内容拷贝到输出空间 */
		}

		dst[8 * i] = '\0'; // 字符串结束符

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
 * 3dec ecb 解密密函数(即可加密也可以解密 由参数enc决定)
 * p_in:输入数据; p_out:输出数据(调用时第一次传入一个NULL,使得调用函数获得P_out_len的值,调用函数再申请相应大小的空间);
 * key:秘钥
 *
 */
int do_des_ecb3_decode(const unsigned char *p_in, unsigned char *p_out, int *p_out_len, unsigned char *key_temp)
{
	unsigned int do_continue = 1;
	const unsigned char *data = p_in;
	unsigned char *temp_ch = NULL;
	unsigned int data_len;
	unsigned int data_rest;

	unsigned int count_fill; // 解密之后明文被填充的字符个数

	unsigned char *dst = NULL;  /* 解密后的明文 */

	unsigned char tmp[8];
	unsigned char out[8];

	unsigned char *k = key_temp; /* 原始密钥 */
	unsigned int key_len;
	unsigned char key[LEN_OF_KEY];     /* 补齐后的密钥 */
	unsigned char block_key[9];
	DES_key_schedule ks1, ks2, ks3;

	unsigned char *temp = NULL;

	data_len = strlen(data);  /* 分析补齐明文所需空间及补齐填充数据 */
	data_rest = data_len % 8;

	if(0 != data_rest)
		return -1;  // 密文数据个数不是8的整倍数

	if (NULL == p_out)
	{
		*p_out_len = data_len;
		return OUT_IS_NULL;
	}

	dst = p_out;

	key_len = strlen(k);  /* 构造补齐后的密钥 */

/*	printf("key_len   ---->    %d  \n", key_len);*/
	if(key_len > LEN_OF_KEY)
		return DES_PASSWORD_ERROR;
	memcpy(key, k, key_len);
	memset(key + key_len, 0x00, LEN_OF_KEY - key_len); /* 秘钥长度24 */

	if(NULL == data || NULL == dst)
		do_continue = 0;

	if(do_continue)
	{
		int count;
		int i;

		/* 密钥置换 */
		memset(block_key, 0, sizeof(block_key));

		memcpy(block_key, key + 0, 8);
		DES_set_key_unchecked((const_DES_cblock *)block_key, &ks1);

		temp = (unsigned char *)&ks1;

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
			memcpy(dst + 8 * i, out, 8);   /* 将处理(加密或解密)之后的内容拷贝到输出空间 */
		}

		dst[8 * i] = '\0'; // 字符串结束符
	}

	count_fill = *(dst + data_len - 1);  // 得到原始明文被填充的个数

	dst[data_len - count_fill] = '\0';  // 结束字符串


	return DES_ENCRYPT_OK;
}

/** 
 * 解密 主、次秘钥
 * km:主密钥(服务器传来的,已经做过base64解码);   km:次密钥(服务器传来的,已经做过base64解码)
 * m_key:按照加密规则反解密出来的主密钥;    s_key:解密出来的次秘钥
 *
 */
int des_decode_k(const unsigned char *km, const unsigned char *ks, unsigned char *m_key, unsigned char *s_key)
{
	unsigned int out_len;
	unsigned char *rmk = NULL;
	unsigned char *rsk = NULL;
	int ret;

	unsigned char *ttk = (unsigned char *)malloc(LEN_OF_KEY + 1);
	get_key(original_key, ttk);

	/*****  解密主密钥  *****/
	if(OUT_IS_NULL == do_des_ecb3_decode(km, NULL, &out_len, ttk))
	{
		rmk = (unsigned char *)malloc(out_len + 1);
	}


	// 成功解密后返回DES_ENCRYPT_OK;并且解密之前primary_cipher_k密文长度24，解密之后也应该是24字节的明文
	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_decode(km, rmk, &out_len, ttk)) || 24 != strlen(rmk))
	{
		return ret;
	}

	/*****  解密次秘钥密钥  *****/
	if(OUT_IS_NULL == do_des_ecb3_decode(ks, NULL, &out_len, rmk))
	{
		rsk = (unsigned char *)malloc(out_len + 1);
	}
	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_decode(ks, rsk, &out_len, rmk)) || 24 != strlen(rsk))
	{
		return ret;
	}


	//memset(m_key, 0, strlen(m_key));
	memcpy(m_key, rmk, strlen(rmk));

	//memset(s_key, 0, strlen(s_key));
	memcpy(s_key, rsk, strlen(rsk));



	if (NULL != ttk)
	{
		free(ttk);
		ttk = NULL;
	}

	if (NULL != rmk)
	{
		free(rmk);
		rmk = NULL;
	}

	if (NULL != rsk)
	{
		free(rsk);
		rsk = NULL;
	}

	return 0;
}

/** 
 * 
 * 先解析xml报文。 并且将各个数据进行解base64操作。然后按下面流程。
 * 1、key = 60 位(原始), (tk =  key[5,25),  ttk = tk+tk[0,4),  ttk是真实密钥)  get_key()函数得到ttk；
 * 2、设此时  "shahai_key_main"--> Km,  "shahai_key_sec"--> ks
 * 3、使用ttk来还原两个密钥。( 次密钥使用主密钥进行还原).
 * 4、先还原主密钥   byte [] rmk = 3des(ttk, km);
 * 5、次密钥： byte [] rsk=3des(rmk,ks)
 * 6、客户端数据加密. (keymain, keysec 已经完全还原的情况下，执行该操作)
 *    明文 plaintext .  主密钥rmk, 次密钥 rsk
 *    一层加密   byte [] firstEnStr = 3des(rsk,plaintext)
 *    二层加密   byte [] secEnStr = 3des(rmk,firstEnStr);
 * 输入:  plaintext:明文数据;  km: 主密钥(被加密的主密钥密文);  ks:次秘钥(被加密的次密钥密文)
 * 输出:  p_cipher：明文加密之后的密文数据
 * demo:(调用要求)
 * unsigned char *cipher = NULL;
 * cipher = (unsigned char *)malloc(strlen(data) + 16);
 * memset(cipher, 0, strlen(data) + 16);  //  两次加密最多密文最多比明文多16个字节;必须要做否则，可能造成错误
 * do_main_des_encrypt(data, km, ks, cipher);
 *
 */
int do_main_des_encrypt(unsigned char *plaintext,unsigned char *km, unsigned char *ks, unsigned char *p_cipher)
{
	unsigned int out_len;
	unsigned char *rmk = NULL;
	unsigned char *rsk = NULL;
	unsigned char *firstEnStr = NULL;
	unsigned char *secEnStr = NULL;
	int ret;

	rmk = km;
	rsk = ks;

// 	unsigned char *ttk = (unsigned char *)malloc(LEN_OF_KEY + 1);
// 	get_key(original_key, ttk);
// 
// 	/*****  解密主密钥  *****/
// 	if(OUT_IS_NULL == do_des_ecb3_decode(km, NULL, &out_len, ttk))
// 	{
// 		rmk = (unsigned char *)malloc(out_len + 1);
// 	}
// 	// 成功解密后返回DES_ENCRYPT_OK;并且解密之前primary_cipher_k密文长度24，解密之后也应该是24字节的明文
// 	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_decode(km, rmk, &out_len, ttk)) || 24 != strlen(rmk))
// 	{
// 		return ret;
// 	}
// 	
// 	/*****  解密次秘钥密钥  *****/
// 	if(OUT_IS_NULL == do_des_ecb3_decode(ks, NULL, &out_len, rmk))
// 	{
// 		rsk = (unsigned char *)malloc(out_len + 1);
// 	}
// 	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_decode(ks, rsk, &out_len, rmk)) || 24 != strlen(rsk))
// 	{
// 		return ret;
// 	}

// 	printf("\nencrypt   ttk ==> %s \n", ttk);
// 	printf("24 != strlen(rmk) |%d| |%s| \n",strlen(rmk), rmk);
// 	printf("24 != strlen(rsk) |%d| |%s| \n",strlen(rsk), rsk);

	/******* 明文加密,一层加密 *******/
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

	/******* 明文加密,二层加密 *******/
	if(OUT_IS_NULL == do_des_ecb3_encrypt(firstEnStr, NULL, &out_len, rmk))
	{
		secEnStr = (unsigned char *)malloc(out_len + 1);
	}

	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_encrypt(firstEnStr, secEnStr, &out_len, rmk)))
		return ret;

	printf("sizeof(p_cipher)  == %d \n", strlen(p_cipher));
	memset(p_cipher, 0, sizeof(p_cipher));
	memcpy(p_cipher, secEnStr, strlen(secEnStr));



// 	printf("\n encrypt secEnStr===================%d \n", strlen(secEnStr));
// 	for(i = 0; i < strlen(secEnStr); i++)
// 		printf("%02X", *(secEnStr + i));
// 
// 	printf("\n %d \n", strlen(secEnStr));

// 	free(ttk);
// 	free(rmk);
	free(firstEnStr);
	free(secEnStr);

	return 0;
}

/** 
 * cipher:密文; km:主密钥(被加密之后的); ks:次秘钥(被加密之后的); plain:输出明文
 * unsigned char *out_plain = NULL;
 * out_plain = (unsigned char *)malloc(strlen(cipher));   
 * 由于明文加密之前进行了补齐操作，所以密文长度大于明文长度;因此，解密得到的实际明文长度小于输入密文长度
 */
int do_main_des_decode(unsigned char *cipher,unsigned char *km, unsigned char *ks, unsigned char *plain/*, unsigned char *rmk, unsigned char *rsk*/)
{
	unsigned int out_len;
	unsigned char *rmk = NULL;
	unsigned char *rsk = NULL;
	unsigned char *firstEnStr = NULL;
	unsigned char *plaintext = NULL;
	unsigned char *ttk = (unsigned char *)malloc(LEN_OF_KEY + 1);


	int ret;
	rmk = km;
	rsk = ks;


/*	get_key(original_key, ttk);*/
	
// 	printf("\ncipher  decode    %d \n",strlen(cipher));
// 	for(i = 0; i < strlen(cipher); i++)
// 		printf("%02X", *(cipher + i));


// 	/*****  解密主密钥  *****/
// 	if(OUT_IS_NULL == do_des_ecb3_decode(km, NULL, &out_len, ttk))
// 	{
// 		rmk = (unsigned char *)malloc(out_len + 1);
// 	}
// 	// 成功解密后返回DES_ENCRYPT_OK;并且解密之前primary_cipher_k密文长度24，解密之后也应该是24字节的明文
// 	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_decode(km, rmk, &out_len, ttk)) || 24 != strlen(rmk))
// 	{
// /*		printf("rmk decode error\n");*/
// 		return ret;
// 	}
// 
// 	/*****  解密次秘钥密钥  *****/
// 	if(OUT_IS_NULL == do_des_ecb3_decode(ks, NULL, &out_len, rmk))
// 	{
// 		rsk = (unsigned char *)malloc(out_len + 1);
// 	}
// 	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_decode(ks, rsk, &out_len, rmk)) || 24 != strlen(rsk))
// 		return ret;

// 	printf("\nttk ==> %s \n", ttk);
// 	printf("24 != strlen(rmk) |%d| |%s| \n",strlen(rmk), rmk);
// 	printf("24 != strlen(rsk) |%d| |%s| \n",strlen(rsk), rsk);

	/******* 密文解密,一层解密 *******/
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


	/******* 密文解密,二层解密 *******/
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

	memset(plain, 0, strlen(plain));
	memcpy(plain, plaintext, strlen(plaintext));

	free(ttk);
// 	free(rmk);
// 	free(rsk);
	free(firstEnStr);
	free(plaintext);

	return 0;
}


/** 
 * 先解析xml报文。 并且将各个数据进行解base64操作。然后按下面流程。
 * 1、key = 60 位(原始), (tk =  key[5,25),  ttk = tk+tk[0,4),  ttk是真实密钥)  get_key()函数得到ttk；
 * 2、设此时  "shahai_key_main"--> Km,  "shahai_key_sec"--> ks
 * 3、使用ttk来还原两个密钥。( 次密钥使用主密钥进行还原).
 * 4、先还原主密钥   byte [] rmk = 3des(ttk, km);
 * 5、次密钥： byte [] rsk=3des(rmk,ks)
 */

/**
 * 测试用代码,按照规则创建两个测试用 主次秘钥
 *
 */
int cread_tesk_k(unsigned char *k_m, unsigned char *k_s)
{
	unsigned char *tkm = "123456788765432112345678";
	unsigned char *tks = "876543211234567887654321";

	unsigned char *km = NULL;
	unsigned char *ks = NULL;

	int out_len, ret;

	unsigned char *ttk = (unsigned char *)malloc(LEN_OF_KEY + 1);
	get_key(original_key, ttk);
	/*printf("%d ==== \n", strlen(tks));*/

	/******* 加密主密钥 *******/
	if(OUT_IS_NULL == do_des_ecb3_encrypt(tkm, NULL, &out_len, ttk))
	{
		km = (unsigned char *)malloc(out_len + 1);
	}
	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_encrypt(tkm, km, &out_len, ttk)))
		return ret;

	/******* 加密次密钥 *******/
	if(OUT_IS_NULL == do_des_ecb3_encrypt(tks, NULL, &out_len, tkm))
	{
		ks = (unsigned char *)malloc(out_len + 1);
	}

	if(DES_ENCRYPT_OK != (ret = do_des_ecb3_encrypt(tks, ks, &out_len, tkm)))
		return ret;

	printf("%d | %d \n", strlen(km), strlen(ks));
	memcpy(k_m, km, strlen(km));
	memcpy(k_s, ks, strlen(ks));

	
	
	free(ttk);
	free(km);
	free(ks);

	return 0;
}

/** 
 * DES_ecb3_encrypt方法
 * 
 * 具体使用时需要注意des算法的加密模式、密钥长度、补齐方式，
 * 我这里采用3des的ECB方式、24位密钥（不足右补0）、内容长度以8字节切分，不能被8整除的末尾部分，根据长度不足8字节的部分
 * 
 * des加密密钥也是8位来处理的，所以在密钥置换时只取8位
 *
 */
