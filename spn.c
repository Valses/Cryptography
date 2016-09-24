/** 任务一：原始SPN加密
 * 描述：
 * 分组长度为4，轮数为4
 * 加解密分别100000次，记录总时间
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define Nr 4        //加密轮数
#define BIT 16      //明文位数，即p盒长度
#define L 4         //每个s盒的输入bit数
#define LS 16       //s盒长度

typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef uint16_t uint16_t;
uint32_t K = 0x3A94D63F;     //原始密钥
uint16_t s[LS] = {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7};
uint16_t s_in[LS] =  {14,3,4,8,1,12,10,15,7,13,9,6,11,2,0,5};
//s盒与s逆的定义

uint16_t sbox(uint16_t c){
	//加密s盒
    uint16_t s_cipher = 0;
    uint16_t mask = 0xf;
    uint16_t m = 0;         //记录s盒函数的中间值
    int i = 1;
    for(i = 1;i <= (BIT/L);i++){
        m = (c >> (BIT - (i*4))) & mask;
        s_cipher = (s[m] << (BIT - (i*4))) | s_cipher;
    }
    return s_cipher;
}

uint16_t sbox_in(uint16_t c){
	//解密s盒
    uint16_t s_cipher = 0;
    uint16_t mask = 0xf;
    uint16_t m = 0;         //记录s盒函数的中间值
    int i = 1;
    for(i = 1;i <= (BIT/L);i++){
        m = (c >> (BIT - (i*4))) & mask;
        s_cipher = (s_in[m] << (BIT - (i*4))) | s_cipher;
    }
    return s_cipher;
}

uint16_t pbox(uint16_t c){
	//p盒置换
    uint16_t v1, v2, v3, v4, v5, v6, v7;
    v1 = c & 0x8421;
    v2 = c & 0x4210;
    v3 = c & 0x0842;
    v4 = c & 0x2100;
    v5 = c & 0x0084;
    v6 = c & 0x1000;
    v7 = c & 0x0008;
    return v1 | (v2 >> 3) | (v3 << 3) | (v4 >> 6) | (v5 << 6) | (v6 >> 9) | (v7 << 9);
}

uint16_t getk(int i){
    //获得轮密钥
    uint16_t k = K >> (BIT - (i*4));
    return k;
}

uint16_t spn(uint16_t plain){
    uint16_t middle = plain;    //middle为中间值
    int i = 0;
    for(i = 0;i < Nr-1 ;i++){
        middle = middle ^ getk(i);
        middle = sbox(middle);
        middle = pbox(middle);
    }
    middle = middle ^ getk(i++);
    middle = sbox(middle);
    return middle ^ getk(i);
}

uint16_t despn(uint16_t cipher){
    uint16_t middle = cipher;
    middle = middle ^ getk(Nr);
    middle = sbox_in(middle);
    int i;
    for(i = Nr - 1; i > 0 ; i--){
        middle = middle ^ getk(i);
        middle = pbox(middle);
        middle = sbox_in(middle);
    }
    return middle ^ getk(0);
}

int main(void){
    uint16_t cipher = 0x0000;         //密文
    uint16_t plain = 0x26b7;          //默认明文
    printf("Plain is: %0x\n\n",plain);
    clock_t clockBegin1 = 0,clockBegin2 = 0,clockEnd = 0;

    int i;
    clockBegin1 = clock();
    for(i = 0;i < 100000; i++){
        cipher = spn(plain);
    }
    clockBegin2 = clock();
    printf("After encryption,cipher is: %0x\n",cipher);
    printf("Encryption time = (%0.2f/100000)ms\n", (double)(clockBegin2 - clockBegin1));

    clockBegin2 = clock();
    for(i = 0;i < 100000; i++){
       plain = despn(cipher);
    }
    clockEnd = clock();
    printf("\nAfter decryption,plain is: %0x\n",plain);
    printf("Decryption time = (%0.2f/100000)ms\n", (double)(clockEnd - clockBegin2));

    return 0;
}
