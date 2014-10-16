#include "shahai_des_locl.h"

int main(int argc, char **argv)
{
	unsigned char *data = "12345qwertasdfg12345";    /* 明文 */

	// 	unsigned char *km = "123456788765432123456789";
	// 	unsigned char *ks = "193748294672926397303733";
	unsigned char *cipher = NULL;

	unsigned char *km = NULL;
	unsigned char *ks = NULL;


	unsigned char *out_ch = NULL;
	unsigned char *out_plain = NULL;

	int index;

	extern char original_key[60];
	unsigned char *ttk = (unsigned char *)malloc(LEN_OF_KEY + 1);
	get_key(original_key, ttk);

	cread_tesk_k(&km, &ks);

	

	for (index = 0; index < 10000; index++)
	{

		cipher = (unsigned char *)malloc(strlen(data) + 16);
		memset(cipher, 0, strlen(data) + 16);  // 必须要做否则，可能造成错误
		do_main_des_encrypt(data, km, ks, cipher);

		printf("strlen(cipher)  ==>  %d\n", strlen(cipher));

		out_plain = (unsigned char *)malloc(strlen(cipher));

		memset(out_plain, 0, strlen(cipher));  // 必须要做否则，可能造成错误

		do_main_des_decode(cipher, km, ks, out_plain);


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

