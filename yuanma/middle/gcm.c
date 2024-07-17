#include "gcm.h"
#include "aes.h"

static const uint64_t last4[16] = {
        0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
        0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0  };

#define GET_UINT32_BE(n,b,i) {                      \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )         \
        | ( (uint32_t) (b)[(i) + 1] << 16 )         \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )         \
        | ( (uint32_t) (b)[(i) + 3]       ); }

#define PUT_UINT32_BE(n,b,i) {                      \
    (b)[(i)    ] = (uchar) ( (n) >> 24 );   \
    (b)[(i) + 1] = (uchar) ( (n) >> 16 );   \
    (b)[(i) + 2] = (uchar) ( (n) >>  8 );   \
    (b)[(i) + 3] = (uchar) ( (n)       ); }


/******************************************************************************
*GCM初始化
*必须调用一次才能初始化GCM库。
*调用AES keygen表生成器
 ******************************************************************************/
int gcm_initialize( void )
{
    aes_init_keygen_tables();
    return( 0 );
}


/******************************************************************************
*GCM
*对128位输入向量“x”执行GHASH操作
*使用我们的预计算表将128位输出向量转换为“x”乘以H。
*“x”和“output”被视为GCM的GF（2^128）Galois字段的元素。
 ******************************************************************************/
static void gcm_mult( gcm_context *ctx,     // 建立已经指向内容的指针
                      const uchar x[16],    // 128位输入向量的指针
                      uchar output[16] )    // 128位输出向量的指针
{
    int i;
    uchar lo, hi, rem;
    uint64_t zh, zl;

    lo = (uchar)( x[15] & 0x0f );
    hi = (uchar)( x[15] >> 4 );
    zh = ctx->HH[lo];
    zl = ctx->HL[lo];

    for( i = 15; i >= 0; i-- ) {
        lo = (uchar) ( x[i] & 0x0f );
        hi = (uchar) ( x[i] >> 4 );

        if( i != 15 ) {
            rem = (uchar) ( zl & 0x0f );
            zl = ( zh << 60 ) | ( zl >> 4 );
            zh = ( zh >> 4 );
            zh ^= (uint64_t) last4[rem] << 48;
            zh ^= ctx->HH[lo];
            zl ^= ctx->HL[lo];
        }
        rem = (uchar) ( zl & 0x0f );
        zl = ( zh << 60 ) | ( zl >> 4 );
        zh = ( zh >> 4 );
        zh ^= (uint64_t) last4[rem] << 48;
        zh ^= ctx->HH[hi];
        zl ^= ctx->HL[hi];
    }
    PUT_UINT32_BE( zh >> 32, output, 0 );
    PUT_UINT32_BE( zh, output, 4 );
    PUT_UINT32_BE( zl >> 32, output, 8 );
    PUT_UINT32_BE( zl, output, 12 );
}


/******************************************************************************
 *
 *  GCM_SETKEY
 * 调用此函数可设置AES-GCM密钥。它初始化AES密钥
 * 并填充gcm上下文预先计算的HTables。
 ******************************************************************************/
int gcm_setkey( gcm_context *ctx,   // 已经指向内容的指针
                const uchar *key,   // 指向AES加密密钥的指针
                const uint keysize) //字节长度
{
    int ret, i, j;
    uint64_t hi, lo;
    uint64_t vl, vh;
    unsigned char h[16];

    memset( ctx, 0, sizeof(gcm_context) );  // 将内容设置为0
    memset( h, 0, 16 );                     // 初始化要加密的块

    // 加密空的128位块以生成基于密钥的值
    if(( ret = aes_setkey( &ctx->aes_ctx, ENCRYPT, key, keysize )) != 0 )
        return( ret );
    if(( ret = aes_cipher( &ctx->aes_ctx, h, h )) != 0 )
        return( ret );

    GET_UINT32_BE( hi, h,  0  );   
    GET_UINT32_BE( lo, h,  4  );
    vh = (uint64_t) hi << 32 | lo;

    GET_UINT32_BE( hi, h,  8  );
    GET_UINT32_BE( lo, h,  12 );
    vl = (uint64_t) hi << 32 | lo;

    ctx->HL[8] = vl;                // 8 = 1000 corresponds to 1 in GF(2^128)
    ctx->HH[8] = vh;
    ctx->HH[0] = 0;                 // 0 corresponds to 0 in GF(2^128)
    ctx->HL[0] = 0;

    for( i = 4; i > 0; i >>= 1 ) {
        uint32_t T = (uint32_t) ( vl & 1 ) * 0xe1000000U;
        vl  = ( vh << 63 ) | ( vl >> 1 );
        vh  = ( vh >> 1 ) ^ ( (uint64_t) T << 32);
        ctx->HL[i] = vl;
        ctx->HH[i] = vh;
    }
    for (i = 2; i < 16; i <<= 1 ) {
        uint64_t *HiL = ctx->HL + i, *HiH = ctx->HH + i;
        vh = *HiH;
        vl = *HiL;
        for( j = 1; j < i; j++ ) {
            HiH[j] = vh ^ ctx->HH[j];
            HiL[j] = vl ^ ctx->HL[j];
        }
    }
    return( 0 );
}


/******************************************************************************
 *
 *GCM处理分为四个阶段：设置密钥、开始、更新和完成。
 *
 *设置密钥：
 *开始：设置加密/解密模式。
 *接受初始化向量和其他数据。
 *更新：加密或解密明文或密文。
 *完成：执行最后一次GHASH以生成身份验证标记。
 *GCM启动
 *给定用户提供的GCM上下文，这将初始化它，设置加密模式，并预处理初始化向量和其他AEAD数据。
 *
 ******************************************************************************/
int gcm_start( gcm_context *ctx,    // 指向用户提供的GCM上下文的指针
               int mode,            // 加密或者解密的模式
               const uchar *iv,     // 指向初始化向量的指针
               size_t iv_len,       // 初始化向量的byte长度
               const uchar *add,    // 附加AEAD数据的ptr（如果无，则为空）
               size_t add_len )     // 附加AEAD数据的长度
{
    int ret;            // 如果AES加密失败，则返回错误
    uchar work_buf[16]; 
    const uchar *p;     // 通用数组指针
    size_t use_len;     // 要处理的字节计数，最多16个字节
    size_t i;           // 局部循环迭代器

    // 为下一个新流程将工作缓冲区归零
    memset( ctx->y,   0x00, sizeof(ctx->y  ) );
    memset( ctx->buf, 0x00, sizeof(ctx->buf) );
    ctx->len = 0;
    ctx->add_len = 0;

    ctx->mode = mode;               // 设置加密或者解密的模式
    ctx->aes_ctx.mode = ENCRYPT;    // 在加密模式下调用AES加密

    if( iv_len == 12 ) {                // 使用一个12字节、96位的IV将IV从1（而非0）复制到“y”buffstart“counting”的顶部
        memcpy( ctx->y, iv, iv_len );   
        ctx->y[15] = 1;                 
    }
    else    
    {
        memset( work_buf, 0x00, 16 );               // 清除工作缓冲区
        PUT_UINT32_BE( iv_len * 8, work_buf, 12 );  // 将向量输入到缓冲区中

        p = iv;
        while( iv_len > 0 ) {
            use_len = ( iv_len < 16 ) ? iv_len : 16;
            for( i = 0; i < use_len; i++ ) ctx->y[i] ^= p[i];
            gcm_mult( ctx, ctx->y, ctx->y );
            iv_len -= use_len;
            p += use_len;
        }
        for( i = 0; i < 16; i++ ) ctx->y[i] ^= work_buf[i];
        gcm_mult( ctx, ctx->y, ctx->y );
    }
    if( ( ret = aes_cipher( &ctx->aes_ctx, ctx->y, ctx->base_ectr ) ) != 0 )
        return( ret );

    ctx->add_len = add_len;
    p = add;
    while( add_len > 0 ) {
        use_len = ( add_len < 16 ) ? add_len : 16;
        for( i = 0; i < use_len; i++ ) ctx->buf[i] ^= p[i];
        gcm_mult( ctx, ctx->buf, ctx->buf );
        add_len -= use_len;
        p += use_len;
    }
    return( 0 );
}

/******************************************************************************
 *
 *  GCM_UPDATE
 *这被调用一次或多次以处理大容量明文或密文数据。
 *我们给它一些字节数的输入，它返回相同的数字
 *输出字节数
 *部分块长度<128位。）
 ******************************************************************************/
int gcm_update( gcm_context *ctx,       // 指向用户提供的GCM上下文的指针
                size_t length,          // 要处理的数据长度（字节）
                const uchar *input,     // 指向源数据的指针
                uchar *output )         // 指向目标数据的指针
{
    int ret;            // 如果AES加密失败，则返回错误
    uchar ectr[16];     // 异或运算的计数器模式密码输出
    size_t use_len;     // 要处理的字节计数，最多16个字节
    size_t i;           // 局部循环迭代器

    ctx->len += length; // 缓冲GCM上下文的运行长度计数

    while( length > 0 ) {
        // 将要处理的长度限制为16字节
        use_len = ( length < 16 ) ? length : 16;

        // 递增上下文的128位IV | |计数器“y”向量
        for( i = 16; i > 12; i-- ) if( ++ctx->y[i - 1] != 0 ) break;

        // 在已建立的密钥下加密上下文的“y”向量
        if( ( ret = aes_cipher( &ctx->aes_ctx, ctx->y, ectr ) ) != 0 )
            return( ret );

        // 加密或解密输出的输入
        if( ctx->mode == ENCRYPT )
        {
            for( i = 0; i < use_len; i++ ) {
                // 将密码的输出向量（ectr）与输入进行异或运算
                output[i] = (uchar) ( ectr[i] ^ input[i] );
                ctx->buf[i] ^= output[i];
            }
        }
        else
        {
            for( i = 0; i < use_len; i++ ) {
                ctx->buf[i] ^= input[i];
                //将密码的输出向量（ectr）与输入进行异或运算
                output[i] = (uchar) ( ectr[i] ^ input[i] );
            }
        }
        gcm_mult( ctx, ctx->buf, ctx->buf );    // 执行GHASH操作

        length -= use_len;  // 删除要处理的剩余字节计数
        input  += use_len;  // 向前移动输入指针
        output += use_len;  // 向前移动输出指针
    }
    return( 0 );
}

/******************************************************************************
 *
 *  GCM_FINISH
 *在所有对GCM\U UPDATE的调用完成GCM后，将调用该命令一次。
 *它执行最后的GHASH以生成最终的身份验证标记。
 *
 ******************************************************************************/
int gcm_finish( gcm_context *ctx,   // 指向用户提供的GCM上下文的指针
                uchar *tag,         // 指向接收标记的缓冲区的指针
                size_t tag_len )    // 接收buf的标记的长度（字节）
{
    uchar work_buf[16];
    uint64_t orig_len     = ctx->len * 8;
    uint64_t orig_add_len = ctx->add_len * 8;
    size_t i;

    if( tag_len != 0 ) memcpy( tag, ctx->base_ectr, tag_len );

    if( orig_len || orig_add_len ) {
        memset( work_buf, 0x00, 16 );

        PUT_UINT32_BE( ( orig_add_len >> 32 ), work_buf, 0  );
        PUT_UINT32_BE( ( orig_add_len       ), work_buf, 4  );
        PUT_UINT32_BE( ( orig_len     >> 32 ), work_buf, 8  );
        PUT_UINT32_BE( ( orig_len           ), work_buf, 12 );

        for( i = 0; i < 16; i++ ) ctx->buf[i] ^= work_buf[i];
        gcm_mult( ctx, ctx->buf, ctx->buf );
        for( i = 0; i < tag_len; i++ ) tag[i] ^= ctx->buf[i];
    }
    return( 0 );
}


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
        size_t tag_len )        // 要生成的标记的字节长度
{ 
    gcm_start  ( ctx, mode, iv, iv_len, add, add_len );
    gcm_update ( ctx, length, input, output );
    gcm_finish ( ctx, tag, tag_len );
    return( 0 );
}


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
        size_t add_len,         // b附加AEAD数据的字节长度
        const uchar *input,     // 指向密码数据源的指针
        uchar *output,          // 指向密码数据目标的指针
        size_t length,          // 密码数据的字节长度
        const uchar *tag,       // 指向要验证的标记的指针
        size_t tag_len )        // 标记的字节长度<=16
{
    uchar check_tag[16];        // 通过解密生成并返回的标记
    int diff;                   // 用于检测身份验证错误的OR标志
    size_t i;                   // 我们的本地迭代器
    gcm_crypt_and_tag(  ctx, DECRYPT, iv, iv_len, add, add_len,
                        input, output, length, check_tag, tag_len );
    for( diff = 0, i = 0; i < tag_len; i++ )
        diff |= tag[i] ^ check_tag[i];

    if( diff != 0 ) {                   // 查看身份认证标签是否改变
        memset( output, 0, length );    
        return( GCM_AUTH_FAILURE );     // 如果发现修改，返回解密失败
    }
    return( 0 );
}

/******************************************************************************
 *
 *  GCM_ZERO_CTX
 *  GCM上下文包含GCM上下文和AES上下文。
 *  包括密钥和安全敏感的密钥相关材料，因此使用后必须归零
 *  此函数可执行此操作。
 *
 ******************************************************************************/
void gcm_zero_ctx( gcm_context *ctx )
{
    //数据缓冲区内容归零
    memset( ctx, 0, sizeof( gcm_context ) );
}