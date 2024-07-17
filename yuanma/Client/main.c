#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "/home/laji/keshe2/keshe/yuanma/Client/MD5/md5.h"
#include "/home/laji/keshe2/keshe/yuanma/Client/DH/my_random.h"
#include "/home/laji/keshe2/keshe/yuanma/Client/AES/gcm.h"
#include "/home/laji/keshe2/keshe/yuanma/Client/AES/aes-gcm.h"


int send_n(int sock,int p,int g, int Pa)
{
    char data[256]={""};
    int s =973;  //存放预共享密钥
    char _secret_key[256];
    char _init_iv[64];
    char _ciphertext[256];
    get_key(_secret_key,_init_iv,s);  //用预共享密钥生成轮密钥和init_iv
    snprintf(data,255,"pgPa%d %d %d",p,g,Pa);
    printf("data is %s\n",data);
    printf("secret_key is %s\n",_secret_key);
    printf("init_iv is %s\n",_init_iv);
    aes_gcm_encrypt(_ciphertext,data,sizeof (data),_secret_key,256,_init_iv,128);  //用预共享密钥对DH算法交换密钥信息进行加密
    write(sock,_ciphertext,256);
}

int main(){
    gcm_initialize();
    //创建套接字
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    //服务器的ip为本地，端口号1234
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("192.168.48.140");
    serv_addr.sin_port = htons(1234);
    //向服务器发送连接请求
    connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    //DH to exchange code
    int p = createprime(1000,2000);
    int g = createprime(3,9);
    int a = createprime(1,p-1);
    int Pa = g^a % p;
    char data[40] = {""};
    send_n(sock,p,g,Pa);
    char * data1;
    char data2[40] = "";
    read(sock,data,sizeof(data));
    data1 = strtok(data,"|");
    strncpy(data2,data1 + 2, sizeof(data1) -2 );
    int Pb = atoi(data2);
    int S2 =Pb^a % p;
    unsigned char init_iv[64]={0};
    unsigned char secret_key[256];
    get_key(secret_key,init_iv,S2);
    printf("the secret key is: ");
    printf("%s\n",secret_key);
    printf("the init iv is: ");
    printf("%s\n",init_iv);
    //发送并接收数据
    int i =0;
    while(i==0){
        unsigned char ciphertext[256];
        unsigned char plaintext[256];
        unsigned char buffer[256];
        char msg[256] = "msg";
        unsigned char recv[256];
        printf("Please input the message:");
        gets(buffer);
        if(!(strcmp(buffer,"quit")))i=1;
        aes_gcm_encrypt(ciphertext,buffer,sizeof (buffer),secret_key,256,init_iv,128);
        strcat(msg,ciphertext);
        write(sock, msg, 256);
        read(sock, recv, 256);
        memset(msg, 0x00 ,sizeof(char)*256);
        strncpy(msg,recv + 3,256);
        aes_gcm_decrypt(plaintext,msg,sizeof(msg),secret_key,256,init_iv,128);
        printf("Server send: %s\n", plaintext);
    }
    //断开连接
    close(sock);
    return 0;
}
