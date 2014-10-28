#include "shahai_des_locl.h"

int main(int argc, char **argv)
{
	unsigned char *data = "12345qwertasdfg12345";    /* 明文 */

	// 	unsigned char *km = "123456788765432123456789";
	// 	unsigned char *ks = "193748294672926397303733";
	unsigned char *cipher = NULL;

	unsigned char km[LEN_OF_KEY + 8 + 1] = {0};
	unsigned char ks[LEN_OF_KEY + 8 + 1] = {0};


	unsigned char *out_ch = NULL;
	unsigned char *out_plain = NULL;

	unsigned char k_m[LEN_OF_KEY + 1] = {0};
	unsigned char k_s[LEN_OF_KEY + 1] = {0};

	int index;

	extern char original_key[60];
	unsigned char *ttk = (unsigned char *)malloc(LEN_OF_KEY + 1);
	get_key(original_key, ttk);

	cread_tesk_k(km, ks);

	des_decode_k(km, ks, k_m, k_s);
// 	printf("\nk_m = %s \n", k_m);
// 	printf("\nk_s = %s \n", k_s);


	

	for (index = 0; index < 100; index++)
	{

		cipher = (unsigned char *)malloc(strlen(data) + 16);
		memset(cipher, 0, strlen(data) + 16);  // 必须要做否则，可能造成错误
		// do_main_des_encrypt(data, km, ks, cipher);
		do_main_des_encrypt(data, k_m, k_s, cipher);


		printf("strlen(cipher)  ==>  %d\n", strlen(cipher));

		out_plain = (unsigned char *)malloc(strlen(cipher));

		memset(out_plain, 0, strlen(cipher));  // 必须要做否则，可能造成错误

		// do_main_des_decode(cipher, km, ks, out_plain);
		do_main_des_decode(cipher, k_m, k_s, out_plain);


		if(0 != strcmp(out_plain, data))
			printf("error ===== error\n");

		printf("do_main_des_decode %s| %d \n", out_plain, strlen(out_plain));


		if(NULL == cipher)
		{
			free(cipher);
			cipher = NULL;
		}
		if (NULL == out_plain)
		{
			free(out_plain);
			out_plain = NULL;
		}


	}

	free(ttk);

	getchar();

	return 0;

}

