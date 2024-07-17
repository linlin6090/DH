#ifndef AES_HEADER
#define AES_HEADER

/******************************************************************************/
#define AES_DECRYPTION  0       // whether AES decryption is supported
/******************************************************************************/

#include <string.h>

#define ENCRYPT         1       // 选择加密还是解密
#define DECRYPT         0       
#if defined(_MSC_VER)
    #include <basetsd.h>
    typedef UINT32 uint32_t;
#else
    #include <inttypes.h>
#endif

typedef unsigned char uchar;  
typedef unsigned int uint;
void aes_init_keygen_tables( void );


/******************************************************************************
 *  AES_CONTEXT : 加密内容/保存调用间数据
 ******************************************************************************/
typedef struct {
    int mode;           // 1 for Encryption, 0 for Decryption
    int rounds;         // 基于密钥大小的轮数
    uint32_t *rk;       // 指向当前轮密钥的指针
    uint32_t buf[68];   // 密钥扩展缓冲区
} aes_context;


/******************************************************************************
 *  AES_SETKEY : 扩展密钥以进行加密或解密
 ******************************************************************************/
int aes_setkey( aes_context *ctx,       // 指向内容的指针
                int mode,               // 1 or 0 for Encrypt/Decrypt
                const uchar *key,       // AES的输入密钥
                uint keysize );         // 字节长度
                                        // 成功则返回0

/******************************************************************************
 *  AES_CIPHER : 调用以加密或解密一个128位数据块
 ******************************************************************************/
int aes_cipher( aes_context *ctx,       // 指向内容的指针
                const uchar input[16],  // 输入加密或解密的128位数据块
                uchar output[16] );     // 输出加密或解密的128位数据块
                                        // 成功返回0
#endif /* AES_HEADER */
