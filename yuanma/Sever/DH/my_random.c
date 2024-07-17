#include "/home/laji/keshe2/keshe/yuanma/Sever/DH/my_random.h"
#include <time.h>
#include <math.h>

// 生成伪素数
const int MAX_ROW = 50;
size_t Pseudoprime(int m,int n)
{
//    int ifprime = 0;
    size_t a = 0;
//    int arr[MAX_ROW];   //数组arr为{3，4，5，6...52}
//    for (int i = 0; i<MAX_ROW; ++i)
//    {
//        arr[i] = i+3;
//    }
//    while (!ifprime)
//    {
    srand((unsigned)time(0));
//        ifprime = 1;
    a = ((rand()%(n-m))+m)/2; //生成一个范围在m n里的奇数
    a = a*2 +1;
//        for (int j = 0; j<MAX_ROW; ++j)
//        {
//            if (a%arr[j] == 0)
//            {
//                ifprime = 0;
//                break;
//            }
//        }
//    }
    return a;
}

size_t  repeatMod(size_t base, size_t n, size_t mod)//模重复平方算法求(b^n)%m
{
    size_t a = 1;
    while(n)
    {
        if(n&1)
        {
            a = (a*base)%mod;
        }
        base = (base*base)%mod;
        n = n>>1;
    }
    return a;
}

//Miller-Rabin素数检测
int rabinmiller(size_t n, size_t k)
{

    int s = 0;
    int temp = n-1;
    while ((temp & 0x1) == 0 && temp)
    {
        temp = temp>>1;
        s++;
    }   //将n-1表示为(2^s)*t
    size_t t = temp;

    while(k--)  //判断k轮误判概率不大于(1/4)^k
    {
        srand((unsigned)time(0));
        size_t b = rand()%(n-2)+2; //生成一个b(2≤a ≤n-2)

        size_t y = repeatMod(b,t,n);
        if (y == 1 || y == (n-1))
            return 1;
        for(int j = 1; j<=(s-1) && y != (n-1); ++j)
        {
            y = repeatMod(y,2,n);
            if (y == 1)
                return 0;
        }
        if ( y != (n-1))
            return 0;
    }
    return 1;
}

int createprime(int m ,int n)
{
    size_t ret = 0;
    while(1)
    {
        ret = Pseudoprime(m,n);
        if (rabinmiller(ret,10))
            break;
    }
    return ret;
}
