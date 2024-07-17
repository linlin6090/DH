#ifndef AES_HEADER
#define AES_HEADER

/******************************************************************************/
#define AES_DECRYPTION  0       // whether AES decryption is supported
/******************************************************************************/

#include <string.h>

#define ENCRYPT         1       // ѡ����ܻ��ǽ���
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
 *  AES_CONTEXT : ��������/������ü�����
 ******************************************************************************/
typedef struct {
    int mode;           // 1 for Encryption, 0 for Decryption
    int rounds;         // ������Կ��С������
    uint32_t *rk;       // ָ��ǰ����Կ��ָ��
    uint32_t buf[68];   // ��Կ��չ������
} aes_context;


/******************************************************************************
 *  AES_SETKEY : ��չ��Կ�Խ��м��ܻ����
 ******************************************************************************/
int aes_setkey( aes_context *ctx,       // ָ�����ݵ�ָ��
                int mode,               // 1 or 0 for Encrypt/Decrypt
                const uchar *key,       // AES��������Կ
                uint keysize );         // �ֽڳ���
                                        // �ɹ��򷵻�0

/******************************************************************************
 *  AES_CIPHER : �����Լ��ܻ����һ��128λ���ݿ�
 ******************************************************************************/
int aes_cipher( aes_context *ctx,       // ָ�����ݵ�ָ��
                const uchar input[16],  // ������ܻ���ܵ�128λ���ݿ�
                uchar output[16] );     // ������ܻ���ܵ�128λ���ݿ�
                                        // �ɹ�����0
#endif /* AES_HEADER */
