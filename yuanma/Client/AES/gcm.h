#ifndef GCM_HEADER
#define GCM_HEADER

#define GCM_AUTH_FAILURE    0x55555555  // authentication failure

#include "aes.h"                        // gcm_context includes aes_context

#if defined(_MSC_VER)
    #include <basetsd.h>
    typedef unsigned int size_t;// use the right type for length declarations
    typedef UINT32 uint32_t;
    typedef UINT64 uint64_t;
#else
    #include <stdint.h>
#endif


/******************************************************************************
 *  GCM_CONTEXT : GCM 的内容密钥等
 ******************************************************************************/
typedef struct {
    int mode;               // 加密或者解密
    uint64_t len;           // 已经处理的密码数据长度
    uint64_t add_len;       // 数据的总长度
    uint64_t HL[16];        // 预先计算的低半表
    uint64_t HH[16];        // 预先计算的高半表
    uchar base_ectr[16];    // 身份认证标签
    uchar y[16];            // 当前输入向量或者计数器的值
    uchar buf[16];          // 工作缓冲区
    aes_context aes_ctx;    
} gcm_context;


/******************************************************************************
 *  GCM_CONTEXT : 在使用GCM前必须要初始化
 ******************************************************************************/
int gcm_initialize( void );


/******************************************************************************
 *  GCM_SETKEY : 设置GCM和AES的密钥
 ******************************************************************************/
int gcm_setkey( gcm_context *ctx,   // 调用提供的ptr
                const uchar *key,   // 指向加密密钥的指针
                const uint keysize  // byte长度
); // 成功则返回0


/******************************************************************************
 *
 *  GCM_CRYPT_AND_TAG
 *
 *  对用户提供的数据进行加密或者解密，生成指定长度的身份认证标志
 *  用户用此函数与可选的数据关联，生成身份验证标记
 *  或者调用解密函数，解密数据并根据提供的身份验证标签进行解密和身份验证
 ******************************************************************************/

int gcm_crypt_and_tag(
        gcm_context *ctx,       // 已设置密钥的gcm上下文
        int mode,               // 方向：GCM加密或GCM解密
        const uchar *iv,        // 指向12字节初始化向量的指针
        size_t iv_len,          // 向量的byte长度
        const uchar *add,       // 指向未加密附加数据的指针
        size_t add_len,         // 附加AEAD数据的字节长度
        const uchar *input,     // 指向密码数据源的指针
        uchar *output,          // 指向密码数据目标的指针
        size_t length,          // 密码数据的字节长度
        uchar *tag,             // 指向要生成的标记的指针
        size_t tag_len );       // 要生成的标记的字节长度


/******************************************************************************
 *
 *  GCM_AUTH_DECRYPT
 *
 *  使用可选的关联数据解密用户提供的数据缓冲区
 *  根据验证的标签验证用户的身份，验证数据是否被修改
 *
 ******************************************************************************/

int gcm_auth_decrypt(
        gcm_context *ctx,       // 已设置密钥的gcm上下文
        const uchar *iv,        // 指向12字节初始化向量的指针
        size_t iv_len,          // 指向12字节初始化向量的指针
        const uchar *add,       // 指向未加密附加数据的指针
        size_t add_len,         // 附加AEAD数据的字节长度
        const uchar *input,     // 指向密码数据源的指针
        uchar *output,          // 指向密码数据目标的指针
        size_t length,          //  密码数据的字节长度
        const uchar *tag,       // 指向要验证的标记的指针
        size_t tag_len );       // 标记的字节长度<=16


/******************************************************************************
 *
 *  GCM_START
 *给定用户提供的GCM上下文，这将初始化它，设置加密模式，并预处理初始化向量和其他AEAD数据。
 *
 ******************************************************************************/
int gcm_start( gcm_context *ctx,    //指向用户提供的GCM上下文的指针
               int mode,            // ENCRYPT (1) or DECRYPT (0)
               const uchar *iv,     // 指向初始化向量的指针
               size_t iv_len,       // 初始化向量的长度
               const uchar *add,    //指向其他附加AEAD数据的指针（如果没有，则为NULL）
               size_t add_len );    //附加AEAD数据的长度（字节）


/******************************************************************************
 *
 *  GCM_UPDATE
 *
 *这被调用一次或多次以处理大容量明文或密文数据，输入并输出
 *
 ******************************************************************************/
int gcm_update( gcm_context *ctx,       // 指向用户提供的GCM上下文的指针
                size_t length,          // 要处理的数据长度（字节）
                const uchar *input,     // 指向源数据的指针
                uchar *output );        // 指向目标数据的指针


/******************************************************************************
 *
 *  GCM_FINISH
 *在所有对GCM\U UPDATE的调用完成GCM后，将调用该命令一次。
 *它执行最后的GHASH以生成最终的身份验证标记。
 *
 ******************************************************************************/

int gcm_finish( gcm_context *ctx,   // 指向目标数据的指针
                uchar *tag,       
                size_t tag_len );   // 接收的标记的长度（字节）


/******************************************************************************
 *
 *  GCM_ZERO_CTX
 *  GCM上下文包含GCM上下文和AES上下文。
 *  包括密钥和安全敏感的密钥相关材料，因此使用后必须归零
 *  此函数可执行此操作。
 *
 ******************************************************************************/

void gcm_zero_ctx( gcm_context *ctx );


#endif /* GCM_HEADER */
