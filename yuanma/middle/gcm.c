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
*GCM��ʼ��
*�������һ�β��ܳ�ʼ��GCM�⡣
*����AES keygen��������
 ******************************************************************************/
int gcm_initialize( void )
{
    aes_init_keygen_tables();
    return( 0 );
}


/******************************************************************************
*GCM
*��128λ����������x��ִ��GHASH����
*ʹ�����ǵ�Ԥ�����128λ�������ת��Ϊ��x������H��
*��x���͡�output������ΪGCM��GF��2^128��Galois�ֶε�Ԫ�ء�
 ******************************************************************************/
static void gcm_mult( gcm_context *ctx,     // �����Ѿ�ָ�����ݵ�ָ��
                      const uchar x[16],    // 128λ����������ָ��
                      uchar output[16] )    // 128λ���������ָ��
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
 * ���ô˺���������AES-GCM��Կ������ʼ��AES��Կ
 * �����gcm������Ԥ�ȼ����HTables��
 ******************************************************************************/
int gcm_setkey( gcm_context *ctx,   // �Ѿ�ָ�����ݵ�ָ��
                const uchar *key,   // ָ��AES������Կ��ָ��
                const uint keysize) //�ֽڳ���
{
    int ret, i, j;
    uint64_t hi, lo;
    uint64_t vl, vh;
    unsigned char h[16];

    memset( ctx, 0, sizeof(gcm_context) );  // ����������Ϊ0
    memset( h, 0, 16 );                     // ��ʼ��Ҫ���ܵĿ�

    // ���ܿյ�128λ�������ɻ�����Կ��ֵ
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
 *GCM�����Ϊ�ĸ��׶Σ�������Կ����ʼ�����º���ɡ�
 *
 *������Կ��
 *��ʼ�����ü���/����ģʽ��
 *���ܳ�ʼ���������������ݡ�
 *���£����ܻ�������Ļ����ġ�
 *��ɣ�ִ�����һ��GHASH�����������֤��ǡ�
 *GCM����
 *�����û��ṩ��GCM�����ģ��⽫��ʼ���������ü���ģʽ����Ԥ�����ʼ������������AEAD���ݡ�
 *
 ******************************************************************************/
int gcm_start( gcm_context *ctx,    // ָ���û��ṩ��GCM�����ĵ�ָ��
               int mode,            // ���ܻ��߽��ܵ�ģʽ
               const uchar *iv,     // ָ���ʼ��������ָ��
               size_t iv_len,       // ��ʼ��������byte����
               const uchar *add,    // ����AEAD���ݵ�ptr������ޣ���Ϊ�գ�
               size_t add_len )     // ����AEAD���ݵĳ���
{
    int ret;            // ���AES����ʧ�ܣ��򷵻ش���
    uchar work_buf[16]; 
    const uchar *p;     // ͨ������ָ��
    size_t use_len;     // Ҫ������ֽڼ��������16���ֽ�
    size_t i;           // �ֲ�ѭ��������

    // Ϊ��һ�������̽���������������
    memset( ctx->y,   0x00, sizeof(ctx->y  ) );
    memset( ctx->buf, 0x00, sizeof(ctx->buf) );
    ctx->len = 0;
    ctx->add_len = 0;

    ctx->mode = mode;               // ���ü��ܻ��߽��ܵ�ģʽ
    ctx->aes_ctx.mode = ENCRYPT;    // �ڼ���ģʽ�µ���AES����

    if( iv_len == 12 ) {                // ʹ��һ��12�ֽڡ�96λ��IV��IV��1������0�����Ƶ���y��buffstart��counting���Ķ���
        memcpy( ctx->y, iv, iv_len );   
        ctx->y[15] = 1;                 
    }
    else    
    {
        memset( work_buf, 0x00, 16 );               // �������������
        PUT_UINT32_BE( iv_len * 8, work_buf, 12 );  // ���������뵽��������

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
 *�ⱻ����һ�λ����Դ�����������Ļ��������ݡ�
 *���Ǹ���һЩ�ֽ��������룬��������ͬ������
 *����ֽ���
 *���ֿ鳤��<128λ����
 ******************************************************************************/
int gcm_update( gcm_context *ctx,       // ָ���û��ṩ��GCM�����ĵ�ָ��
                size_t length,          // Ҫ��������ݳ��ȣ��ֽڣ�
                const uchar *input,     // ָ��Դ���ݵ�ָ��
                uchar *output )         // ָ��Ŀ�����ݵ�ָ��
{
    int ret;            // ���AES����ʧ�ܣ��򷵻ش���
    uchar ectr[16];     // �������ļ�����ģʽ�������
    size_t use_len;     // Ҫ������ֽڼ��������16���ֽ�
    size_t i;           // �ֲ�ѭ��������

    ctx->len += length; // ����GCM�����ĵ����г��ȼ���

    while( length > 0 ) {
        // ��Ҫ����ĳ�������Ϊ16�ֽ�
        use_len = ( length < 16 ) ? length : 16;

        // ���������ĵ�128λIV | |��������y������
        for( i = 16; i > 12; i-- ) if( ++ctx->y[i - 1] != 0 ) break;

        // ���ѽ�������Կ�¼��������ĵġ�y������
        if( ( ret = aes_cipher( &ctx->aes_ctx, ctx->y, ectr ) ) != 0 )
            return( ret );

        // ���ܻ�������������
        if( ctx->mode == ENCRYPT )
        {
            for( i = 0; i < use_len; i++ ) {
                // ����������������ectr������������������
                output[i] = (uchar) ( ectr[i] ^ input[i] );
                ctx->buf[i] ^= output[i];
            }
        }
        else
        {
            for( i = 0; i < use_len; i++ ) {
                ctx->buf[i] ^= input[i];
                //����������������ectr������������������
                output[i] = (uchar) ( ectr[i] ^ input[i] );
            }
        }
        gcm_mult( ctx, ctx->buf, ctx->buf );    // ִ��GHASH����

        length -= use_len;  // ɾ��Ҫ�����ʣ���ֽڼ���
        input  += use_len;  // ��ǰ�ƶ�����ָ��
        output += use_len;  // ��ǰ�ƶ����ָ��
    }
    return( 0 );
}

/******************************************************************************
 *
 *  GCM_FINISH
 *�����ж�GCM\U UPDATE�ĵ������GCM�󣬽����ø�����һ�Ρ�
 *��ִ������GHASH���������յ������֤��ǡ�
 *
 ******************************************************************************/
int gcm_finish( gcm_context *ctx,   // ָ���û��ṩ��GCM�����ĵ�ָ��
                uchar *tag,         // ָ����ձ�ǵĻ�������ָ��
                size_t tag_len )    // ����buf�ı�ǵĳ��ȣ��ֽڣ�
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
 *  ���û��ṩ�����ݽ��м��ܻ��߽��ܣ�����ָ�����ȵ������֤��־
 *  �û��ô˺������ѡ�����ݹ��������������֤���
 *  ���ߵ��ý��ܺ������������ݲ������ṩ�������֤��ǩ���н��ܺ������֤
 ******************************************************************************/
int gcm_crypt_and_tag(
        gcm_context *ctx,       // ��������Կ��gcm������
        int mode,               // ����GCM���ܻ�GCM����
        const uchar *iv,        // ָ��12�ֽڳ�ʼ��������ָ��
        size_t iv_len,          // ������byte����
        const uchar *add,       // ָ��δ���ܸ������ݵ�ָ��
        size_t add_len,         // ����AEAD���ݵ��ֽڳ���
        const uchar *input,     // ָ����������Դ��ָ��
        uchar *output,          // ָ����������Ŀ���ָ��
        size_t length,          // �������ݵ��ֽڳ���
        uchar *tag,             // ָ��Ҫ���ɵı�ǵ�ָ��
        size_t tag_len )        // Ҫ���ɵı�ǵ��ֽڳ���
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
 *  ʹ�ÿ�ѡ�Ĺ������ݽ����û��ṩ�����ݻ�����
 *  ������֤�ı�ǩ��֤�û�����ݣ���֤�����Ƿ��޸�
 *
 ******************************************************************************/
int gcm_auth_decrypt(
        gcm_context *ctx,       // ��������Կ��gcm������
        const uchar *iv,        // ָ��12�ֽڳ�ʼ��������ָ��
        size_t iv_len,          // ָ��12�ֽڳ�ʼ��������ָ��
        const uchar *add,       // ָ��δ���ܸ������ݵ�ָ��
        size_t add_len,         // b����AEAD���ݵ��ֽڳ���
        const uchar *input,     // ָ����������Դ��ָ��
        uchar *output,          // ָ����������Ŀ���ָ��
        size_t length,          // �������ݵ��ֽڳ���
        const uchar *tag,       // ָ��Ҫ��֤�ı�ǵ�ָ��
        size_t tag_len )        // ��ǵ��ֽڳ���<=16
{
    uchar check_tag[16];        // ͨ���������ɲ����صı��
    int diff;                   // ���ڼ�������֤�����OR��־
    size_t i;                   // ���ǵı��ص�����
    gcm_crypt_and_tag(  ctx, DECRYPT, iv, iv_len, add, add_len,
                        input, output, length, check_tag, tag_len );
    for( diff = 0, i = 0; i < tag_len; i++ )
        diff |= tag[i] ^ check_tag[i];

    if( diff != 0 ) {                   // �鿴�����֤��ǩ�Ƿ�ı�
        memset( output, 0, length );    
        return( GCM_AUTH_FAILURE );     // ��������޸ģ����ؽ���ʧ��
    }
    return( 0 );
}

/******************************************************************************
 *
 *  GCM_ZERO_CTX
 *  GCM�����İ���GCM�����ĺ�AES�����ġ�
 *  ������Կ�Ͱ�ȫ���е���Կ��ز��ϣ����ʹ�ú�������
 *  �˺�����ִ�д˲�����
 *
 ******************************************************************************/
void gcm_zero_ctx( gcm_context *ctx )
{
    //���ݻ��������ݹ���
    memset( ctx, 0, sizeof( gcm_context ) );
}