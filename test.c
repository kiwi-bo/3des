#include "shahai_des_locl.h"

extern char original_key[61];

int main(int argc, char **argv)
{
	/* 太长有问题 */
	unsigned char *data = "=-][';/.09!@#$%^&*()12s<>?qwqw";    /* 明文 */

	// 	unsigned char *km = "123456788765432123456789";
	// 	unsigned char *ks = "193748294672926397303733";
	unsigned char *cipher = NULL;

	unsigned char *km = NULL;
	unsigned char *ks = NULL;

	int i;

	unsigned char *ttk = (unsigned char *)malloc(LEN_OF_KEY + 1);
	unsigned char *out_ch = NULL;
	unsigned char *out_plain = NULL;

	get_key(original_key, ttk);

	cread_tesk_k(&km, &ks);

	printf("strlen(km), strlen(ks)  --> %d  %d \n", strlen(km), strlen(ks));

	do_main_des_encrypt(data, km, ks, &cipher);



	do_main_des_decode(cipher, km, ks, &out_plain);

	printf("strcmp  --> %d \n", strcmp(out_plain, data));

	printf("do_main_des_decode %s \n", out_plain);


	getchar();
	return 0;

}