#include "/home/laji/keshe2/keshe/yuanma/Client/AES/aes-gcm.h"

extern char* StrSHA256(const char* str, long long length, char* sha256){
    /*
    计算字符串SHA-256
    参数说明：
    str         字符串指针
    length      字符串长度
    sha256         用于保存SHA-256的字符串指针
    返回值为参数sha256
    */
    char *pp, *ppend;
    long l, i, W[64], T1, T2, A, B, C, D, E, F, G, H, H0, H1, H2, H3, H4, H5, H6, H7;
    H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
    H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;
    long K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    l = length + ((length % 64 >= 56) ? (128 - length % 64) : (64 - length % 64));
    if (!(pp = (char*)malloc((unsigned long)l))) return 0;
    for (i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++);
    for (pp[i + 3 - 2 * (i % 4)] = 128, i++; i < l; pp[i + 3 - 2 * (i % 4)] = 0, i++);
    *((long*)(pp + l - 4)) = length << 3;
    *((long*)(pp + l - 8)) = length >> 29;
    for (ppend = pp + l; pp < ppend; pp += 64){
        for (i = 0; i < 16; W[i] = ((long*)pp)[i], i++);
        for (i = 16; i < 64; W[i] = (SHA256_O1(W[i - 2]) + W[i - 7] + SHA256_O0(W[i - 15]) + W[i - 16]), i++);
        A = H0, B = H1, C = H2, D = H3, E = H4, F = H5, G = H6, H = H7;
        for (i = 0; i < 64; i++){
            T1 = H + SHA256_E1(E) + SHA256_Ch(E, F, G) + K[i] + W[i];
            T2 = SHA256_E0(A) + SHA256_Maj(A, B, C);
            H = G, G = F, F = E, E = D + T1, D = C, C = B, B = A, A = T1 + T2;
        }
        H0 += A, H1 += B, H2 += C, H3 += D, H4 += E, H5 += F, H6 += G, H7 += H;
    }
    free(pp - l);
    sprintf(sha256, "%08X%08X%08X%08X%08X%08X%08X%08X", H0, H1, H2, H3, H4, H5, H6, H7);
    return sha256;
}

void get_key(char * secret_key, char * init_iv , int S2)
{
    int read_len;
    char text[256] = {'0'};
    char temp[8]={0};
    char data[40] = {""};
    printf("The exchange key word is %d\n",S2);
    unsigned char digest[16]; //存放结果
    unsigned char decrypt[16]={0};
    sprintf(text,"%d",S2);
    StrSHA256(text, strlen(text), secret_key);
    MD5_CTX md5c;
    MD5Init(&md5c); //初始化
    read_len = strlen(text);
    MD5Update(&md5c,(unsigned char *)text,read_len);
    MD5Final(&md5c,decrypt);
    strcpy((char *)init_iv,"");
    for(int i=0;i<16;i++)
    {
        sprintf(temp,"%02x",decrypt[i]);
        strcat((char *)init_iv,temp);
    }
}


int aes_gcm_encrypt(unsigned char* output, const unsigned char* input, int input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len){

    int ret = 0;                // our return value
    gcm_context ctx;            // includes the AES context structure

    size_t tag_len = 0;
    unsigned char * tag_buf = NULL;

    gcm_setkey( &ctx, key, (const uint)key_len );

    ret = gcm_crypt_and_tag( &ctx, ENCRYPT, iv, iv_len, NULL, 0,
                             input, output, input_length, tag_buf, tag_len);

    gcm_zero_ctx( &ctx );

    return( ret );
}

int aes_gcm_decrypt(unsigned char* output, const unsigned char* input, int input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len){

    int ret = 0;                // our return value
    gcm_context ctx;            // includes the AES context structure

    size_t tag_len = 0;
    unsigned char * tag_buf = NULL;

    gcm_setkey( &ctx, key, (const uint)key_len );

    ret = gcm_crypt_and_tag( &ctx, DECRYPT, iv, iv_len, NULL, 0,
                             input, output, input_length, tag_buf, tag_len);

    gcm_zero_ctx( &ctx );

    return( ret );

}
