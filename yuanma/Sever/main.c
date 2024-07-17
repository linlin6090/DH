#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include "/home/laji/keshe2/keshe/yuanma/Sever/MD5/md5.h"
#include "/home/laji/keshe2/keshe/yuanma/Sever/AES/aes-gcm.h"
#include "/home/laji/keshe2/keshe/yuanma/Sever/DH/my_random.h"


void read_n(int sock, int a[])
{
    char data[256]={""};
    char data1 [256] = "";
    char * token;
    int s =251;    //预共享密钥
    char _secret_key[256];
    char _init_iv[64];
    char plaintext[256];
    char cmp[10];
    get_key(_secret_key,_init_iv,s);  //用预共享密钥生成轮密钥和Init_iv
    printf("预共享密钥 %s\n",_secret_key);
    printf("初始化向量 %s\n",_init_iv);
    read(sock,data1,256);
    aes_gcm_decrypt(plaintext,data1,sizeof(data1),_secret_key,256,_init_iv,128);  // 对客户端发来的p,g,PA用预共享密钥进行解密
    strncpy(cmp,plaintext,4);
    if(!strcmp(cmp,"pgpa"))printf("the text tittle is pgPa\n");
    printf("p g pa: %s\n",plaintext);
    strncpy(data , plaintext+4 , sizeof(plaintext)-4);
    token = strtok(data , " ");
    for(int i = 0;i<3;i++)
    {
        a[i] = atoi(token);
        token = strtok(NULL," ");
    }
}
int main(){
    gcm_initialize();
    //创建套接字
    int serv_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    //初始化socket元素
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("192.168.48.140");
    serv_addr.sin_port = htons(1234);
    //绑定文件描述符和服务器的ip和端口号
    bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    //进入监听状态，等待用户发起请求
    listen(serv_sock, 20);
    printf("服务器成功启动，等待连接...\n");
    //接受客户端请求
    //定义客户端的套接字，这里返回一个新的套接字，后面通信时，就用这个clnt_sock进行通信
    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size = sizeof(clnt_addr);
    int clientcount = 0;
    while(1){
        int clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
        if (clnt_sock != -1)
        {
            clientcount+=1;
            printf("客户端 %d 连接,IP： ",clientcount);
            printf("%s\n",inet_ntoa(clnt_addr.sin_addr));
        }
        pid_t pid =fork();
        if(!pid){
            //DH to exchange code
            int a[3] = {0};
            read_n(clnt_sock , a);
            int p = a[0];
            int g = a[1];
            int Pa = a[2];
            char data[40]={""};
            int b = createprime(100,1000);
            int Pb = g^b % p;
            int S1 = Pa^b % p;
            snprintf(data,10,"Pb%d|",Pb);
            write(clnt_sock,data,sizeof(data));
            unsigned char init_iv[64]={0};
            unsigned char secret_key[256];
            get_key(secret_key,init_iv,S1);
            printf("密钥: ");
            printf("%s\n",secret_key);
            printf("初始化向量: ");
            printf("%s\n",init_iv);
            //接收客户端数据，并相应
            int i = 0;
            while(i==0){
                unsigned char ciphertext[256];
                unsigned char plaintext[256];
                unsigned char buffer[256];
                unsigned char msg[256];
                read(clnt_sock, buffer, 256);
                memset(msg,0x00,sizeof(char)*256);
                strncpy(msg,buffer+3,256);
                aes_gcm_decrypt(plaintext,msg,sizeof(msg),secret_key,256,init_iv,128);
                printf("客户端 %d : %s\n",clientcount,plaintext);
                if(!(strcmp(plaintext,"quit")))
                {
                    i=1;
                    printf("客户端 %d 关闭连接\n",clientcount);
                    clientcount--;
                }
                strcat(plaintext, "+ACK");
                aes_gcm_encrypt(ciphertext,plaintext,sizeof (plaintext),secret_key,256,init_iv,128);
                memset(msg,0x00,sizeof(char)*256);
                strcpy(msg,"msg");
                strcat(msg,ciphertext);
                write(clnt_sock, msg, 256);
            }
            close(clnt_sock);
            //关闭套接字
            _exit(0);
        }
        close(clnt_sock);
    }
    close(serv_sock);
    return 0;
}
