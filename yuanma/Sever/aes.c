#include "/home/laji/keshe2/keshe/yuanma/Sever/AES/aes.h"

static int aes_tables_inited = 0;   
static uchar FSb[256];      
static uint32_t FT0[256];  
static uint32_t FT1[256];
static uint32_t FT2[256];
static uint32_t FT3[256];

#if AES_DECRYPTION        
static uchar RSb[256];      
static uint32_t RT0[256];   
static uint32_t RT1[256];
static uint32_t RT2[256];
static uint32_t RT3[256];
#endif                      /* AES_DECRYPTION */

static uint32_t RCON[10];   // AES 轮密钥

#define GET_UINT32_LE(n,b,i) {                  \
    (n) = ( (uint32_t) (b)[(i)    ]       )     \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )     \
        | ( (uint32_t) (b)[(i) + 2] << 16 )     \
        | ( (uint32_t) (b)[(i) + 3] << 24 ); }

#define PUT_UINT32_LE(n,b,i) {                  \
    (b)[(i)    ] = (uchar) ( (n)       );       \
    (b)[(i) + 1] = (uchar) ( (n) >>  8 );       \
    (b)[(i) + 2] = (uchar) ( (n) >> 16 );       \
    (b)[(i) + 3] = (uchar) ( (n) >> 24 ); }

/*
 *  AES正向和反向加密循环处理宏
 */
#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = *RK++ ^ FT0[ ( Y0       ) & 0xFF ] ^   \
                 FT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X1 = *RK++ ^ FT0[ ( Y1       ) & 0xFF ] ^   \
                 FT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y0 >> 24 ) & 0xFF ];    \
                                                \
    X2 = *RK++ ^ FT0[ ( Y2       ) & 0xFF ] ^   \
                 FT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X3 = *RK++ ^ FT0[ ( Y3       ) & 0xFF ] ^   \
                 FT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y2 >> 24 ) & 0xFF ];    \
}

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = *RK++ ^ RT0[ ( Y0       ) & 0xFF ] ^   \
                 RT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X1 = *RK++ ^ RT0[ ( Y1       ) & 0xFF ] ^   \
                 RT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y2 >> 24 ) & 0xFF ];    \
                                                \
    X2 = *RK++ ^ RT0[ ( Y2       ) & 0xFF ] ^   \
                 RT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X3 = *RK++ ^ RT0[ ( Y3       ) & 0xFF ] ^   \
                 RT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y0 >> 24 ) & 0xFF ];    \
}

#define ROTL8(x) ( ( x << 8 ) & 0xFFFFFFFF ) | ( x >> 24 )
#define XTIME(x) ( ( x << 1 ) ^ ( ( x & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( x && y ) ? pow[(log[x]+log[y]) % 255] : 0 )
#define MIX(x,y) { y = ( (y << 1) | (y >> 7) ) & 0xFF; x ^= y; }
#define CPY128   { *RK++ = *SK++; *RK++ = *SK++; \
                   *RK++ = *SK++; *RK++ = *SK++; }

void aes_init_keygen_tables( void )
{
    int i, x, y, z;     // 通用迭代和计算局部变量
    int pow[256];
    int log[256];

    if (aes_tables_inited) return;

    for( i = 0, x = 1; i < 256; i++ )   {
        pow[i] = x;
        log[x] = i;
        x = ( x ^ XTIME( x ) ) & 0xFF;
    }
    for( i = 0, x = 1; i < 10; i++ )    {
        RCON[i] = (uint32_t) x;
        x = XTIME( x ) & 0xFF;
    }
    FSb[0x00] = 0x63;
#if AES_DECRYPTION  
    RSb[0x63] = 0x00;
#endif /* AES_DECRYPTION */

    for( i = 1; i < 256; i++ )          {
        x = y = pow[255 - log[i]];
        MIX(x,y);
        MIX(x,y);
        MIX(x,y);
        MIX(x,y); 
        FSb[i] = (uchar) ( x ^= 0x63 );
#if AES_DECRYPTION  
        RSb[x] = (uchar) i;
#endif /* AES_DECRYPTION */

    }
    for( i = 0; i < 256; i++ )          {
        x = FSb[i];
        y = XTIME( x ) & 0xFF;
        z =  ( y ^ x ) & 0xFF;

        FT0[i] = ( (uint32_t) y       ) ^ ( (uint32_t) x <<  8 ) ^
                 ( (uint32_t) x << 16 ) ^ ( (uint32_t) z << 24 );

        FT1[i] = ROTL8( FT0[i] );
        FT2[i] = ROTL8( FT1[i] );
        FT3[i] = ROTL8( FT2[i] );

#if AES_DECRYPTION  
        x = RSb[i];

        RT0[i] = ( (uint32_t) MUL( 0x0E, x )       ) ^
                 ( (uint32_t) MUL( 0x09, x ) <<  8 ) ^
                 ( (uint32_t) MUL( 0x0D, x ) << 16 ) ^
                 ( (uint32_t) MUL( 0x0B, x ) << 24 );

        RT1[i] = ROTL8( RT0[i] );
        RT2[i] = ROTL8( RT1[i] );
        RT3[i] = ROTL8( RT2[i] );
#endif /* AES_DECRYPTION */
    }
    aes_tables_inited = 1; 
}                           

int aes_set_encryption_key( aes_context *ctx,
                            const uchar *key,
                            uint keysize )
{
    uint i;                
    uint32_t *RK = ctx->rk; 

    for( i = 0; i < (keysize >> 2); i++ ) {
        GET_UINT32_LE( RK[i], key, i << 2 );
    }

    switch( ctx->rounds )
    {
        case 10:
            for( i = 0; i < 10; i++, RK += 4 ) {
                RK[4]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[3] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[3]       ) & 0xFF ] << 24 );

                RK[5]  = RK[1] ^ RK[4];
                RK[6]  = RK[2] ^ RK[5];
                RK[7]  = RK[3] ^ RK[6];
            }
            break;

        case 12:
            for( i = 0; i < 8; i++, RK += 6 ) {
                RK[6]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[5] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[5]       ) & 0xFF ] << 24 );

                RK[7]  = RK[1] ^ RK[6];
                RK[8]  = RK[2] ^ RK[7];
                RK[9]  = RK[3] ^ RK[8];
                RK[10] = RK[4] ^ RK[9];
                RK[11] = RK[5] ^ RK[10];
            }
            break;

        case 14:
            for( i = 0; i < 7; i++, RK += 8 ) {
                RK[8]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[7] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[7]       ) & 0xFF ] << 24 );

                RK[9]  = RK[1] ^ RK[8];
                RK[10] = RK[2] ^ RK[9];
                RK[11] = RK[3] ^ RK[10];

                RK[12] = RK[4] ^
                ( (uint32_t) FSb[ ( RK[11]       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[11] >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 24 ) & 0xFF ] << 24 );

                RK[13] = RK[5] ^ RK[12];
                RK[14] = RK[6] ^ RK[13];
                RK[15] = RK[7] ^ RK[14];
            }
            break;

	default:
	    return -1;
    }
    return( 0 );
}

#if AES_DECRYPTION  

/******************************************************************************
 *
 *  AES_SET_DECRYPTION_KEY
 *
 ******************************************************************************/
int aes_set_decryption_key( aes_context *ctx,
                            const uchar *key,
                            uint keysize )
{
    int i, j;
    aes_context cty;           
    uint32_t *RK = ctx->rk;     
    uint32_t *SK;
    int ret;

    cty.rounds = ctx->rounds;   // 初始化AES内容
    cty.rk = cty.buf;           // 轮密钥计数和密钥缓冲区的指针

    if (( ret = aes_set_encryption_key( &cty, key, keysize )) != 0 )
        return( ret );

    SK = cty.rk + cty.rounds * 4;

    CPY128  // 将128位块从*SK复制到*RK

    for( i = ctx->rounds - 1, SK -= 8; i > 0; i--, SK -= 8 ) {
        for( j = 0; j < 4; j++, SK++ ) {
            *RK++ = RT0[ FSb[ ( *SK       ) & 0xFF ] ] ^
                    RT1[ FSb[ ( *SK >>  8 ) & 0xFF ] ] ^
                    RT2[ FSb[ ( *SK >> 16 ) & 0xFF ] ] ^
                    RT3[ FSb[ ( *SK >> 24 ) & 0xFF ] ];
        }
    }
    CPY128  //将128位块从*SK复制到*RK
    memset( &cty, 0, sizeof( aes_context ) );   // 清除aes上下文
    return( 0 );
}

#endif /* AES_DECRYPTION */

int aes_setkey( aes_context *ctx,   // 调用AES上下文的调用方
                int mode,           // ENCRYPT or DECRYPT flag
                const uchar *key,   // 指向密钥的指针
                uint keysize )      // 密钥的字节长度
{
    if( !aes_tables_inited ) return ( -1 );  // 未初始化时调用失败。
    
    ctx->mode = mode;       // 捕获我们正在创建的密钥类型
    ctx->rk = ctx->buf;     // 初始化轮密钥指针

    switch( keysize )       // 根据密钥长度设置轮次计数
    {
        case 16: ctx->rounds = 10; break;   // 16-byte, 128-bit key
        case 24: ctx->rounds = 12; break;   // 24-byte, 192-bit key
        case 32: ctx->rounds = 14; break;   // 32-byte, 256-bit key
	default: return(-1);
    }

#if AES_DECRYPTION
    if( mode == DECRYPT )   // 扩展密钥进行加密或解密
        return( aes_set_decryption_key( ctx, key, keysize ) );
    else     /* ENCRYPT */
#endif /* AES_DECRYPTION */
        return( aes_set_encryption_key( ctx, key, keysize ) );
}

int aes_cipher( aes_context *ctx,
                    const uchar input[16],
                    uchar output[16] )
{
    int i;
    uint32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;   

    RK = ctx->rk;

    GET_UINT32_LE( X0, input,  0 ); X0 ^= *RK++;   
    GET_UINT32_LE( X1, input,  4 ); X1 ^= *RK++;   
    GET_UINT32_LE( X2, input,  8 ); X2 ^= *RK++;    
    GET_UINT32_LE( X3, input, 12 ); X3 ^= *RK++;

#if AES_DECRYPTION  

    if( ctx->mode == DECRYPT )
    {
        for( i = (ctx->rounds >> 1) - 1; i > 0; i-- )
        {
            AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
            AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
        }

        AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

        X0 = *RK++ ^ \
                ( (uint32_t) RSb[ ( Y0       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

        X1 = *RK++ ^ \
                ( (uint32_t) RSb[ ( Y1       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );

        X2 = *RK++ ^ \
                ( (uint32_t) RSb[ ( Y2       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

        X3 = *RK++ ^ \
                ( (uint32_t) RSb[ ( Y3       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );
    }
    else /* ENCRYPT */
    {
#endif /* AES_DECRYPTION */

        for( i = (ctx->rounds >> 1) - 1; i > 0; i-- )
        {
            AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
            AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
        }

        AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

        X0 = *RK++ ^ \
                ( (uint32_t) FSb[ ( Y0       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

        X1 = *RK++ ^ \
                ( (uint32_t) FSb[ ( Y1       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );

        X2 = *RK++ ^ \
                ( (uint32_t) FSb[ ( Y2       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

        X3 = *RK++ ^ \
                ( (uint32_t) FSb[ ( Y3       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );

#if AES_DECRYPTION 
    }
#endif /* AES_DECRYPTION */

    PUT_UINT32_LE( X0, output,  0 );
    PUT_UINT32_LE( X1, output,  4 );
    PUT_UINT32_LE( X2, output,  8 );
    PUT_UINT32_LE( X3, output, 12 );

    return( 0 );
}
/* end of aes.c */
