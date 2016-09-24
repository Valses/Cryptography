/** 任务三：SPN差分分析
 * 描述：
 * T = 100
 * 暴力破解对比十对明密文，有一对不符合则跳出对比循环
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#define Nr 4       //加密轮数
#define BIT 16     //明文位数，即p盒长度
#define L 4        //每个s盒的输入bit数
#define LS 16      //s盒长度
#define T 100      //差分分析选取明密文对数

typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef int bool;
uint32_t K = 0x3A94D63F;     //原始密钥
uint16_t s[LS] = {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7};
uint16_t s_in[LS] = {14,3,4,8,1,12,10,15,7,13,9,6,11,2,0,5};
//s盒和s逆的定义

int spn_diff(void);
int exhaustion(uint32_t key);
bool checkRight(uint32_t key);
uint16_t spn2(uint32_t key,uint16_t plain);
uint16_t getk2(int i,uint32_t key);
uint16_t spn(uint16_t plain);
uint16_t getk(int i);
uint16_t sbox(uint16_t c);
uint16_t pbox(uint16_t c);

int main(void){
    spn_diff();
    return 0;
}

int spn_diff(void){
	//差分分析
    clock_t clockBegin, clockEnd;
    uint16_t x1 = 0,x2 = 0,y1 = 0,y2 = 0;
    uint16_t u1 = 0,v1 = 0,u2 = 0,v2 = 0,up;
    uint32_t key = 0;
    int L1, L2, i, j, count[16][16];
    for(i = 0; i < 16; i++){
		for(j = 0; j < 16; j++){
			count[i][j] = 0;
		}
	}
	clockBegin = clock();
    for(i = 0; i < T; i++){
        x1 = rand() % 0xffff;
        y1 = spn(x1);
        x2 = x1 ^ 0x0b00;
        y2 = spn(x2);
        if(!((((y1 >> 12) ^ (y2 >> 12)) & 0x000f) || (((y1 >> 4) ^ (y2 >> 4)) & 0x000f))){
            for(L1 = 0; L1 < 16; L1++){
                for(L2 = 0; L2 < 16; L2++){
                    u1 = v1 = u2 = v2 = 0;
                    v1 = v1 | (y1 ^ (L1 << 8) ^ L2);
                    int mark = (v1 >> 8) & 0xf;
                    u1 = u1 | (s_in[mark] << 8);
                    mark = v1 & 0xf;
                    u1 = u1 | s_in[mark];
                    v2 = v2 | (y2 ^ (L1 << 8) ^ L2);
                    mark = (v2 >> 8) & 0xf;
                    u2 = u2 | (s_in[mark] << 8);
                    mark = v2 & 0xf;
                    u2 = u2 | s_in[mark];
                    up = (u1 ^ u2) & 0x0f0f;
                    if(up == 0x0606)
                        count[L1][L2]++;
                }
            }
        }
        else
            i--;
    }
    int max = -1;
    for(L1 = 0; L1 < 16; L1++){
        for(L2 = 0; L2 < 16; L2++){
            if(count[L1][L2] > max){
                max = count[L1][L2];
                key = (L1 << 8) | L2;
            }
        }
    }
    printf("After the difference analysis,the uncompleted key is 0x%08x\n",key);
    exhaustion(key);
    clockEnd = clock();
    printf("Time = %.2fms\n", (double)(clockEnd - clockBegin));
    return 0;
}

int exhaustion(uint32_t key){
    //函数用于暴力破解密钥的剩余位
    uint16_t x = 0,y = 0;
    x = rand() % 0xffff;
    y = spn(x);
    uint32_t k;                             //密钥的可能值
    int k1,k2;
    for(k1 = 0; k1 < 0x100000; k1++){
        for(k2 = 0; k2 < 16; k2++){
            k = key | (k1 << 12) | (k2 << 4);
            if(y == spn2(k,x)){
                if(!checkRight(k))
                    printf("K = %08x\n",k);
            }
        }
    }
    return 0;
}

bool checkRight(uint32_t key){
    //函数用于测试已找出的密钥是否正确
    int i,n = 50;                //测试读取的明密文对数量
    bool flag = 0;               //flag来标记密钥是否通过测试，0为默认值，1为有明密文对未通过
    uint16_t x,y;
    for(i = 0; i < n; i++){
        x = rand() % 0xffff;
        y = spn(x);
        if(y != spn2(key,x)){
            flag = 1;
            break;
        }
    }
    return flag;
}

uint16_t sbox(uint16_t c){
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

uint16_t pbox(uint16_t c){
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

uint16_t getk2(int i,uint32_t key){
    //获得轮密钥2
    uint16_t k = key >> (BIT - (i*4));
    return k;
}

uint16_t spn2(uint32_t key,uint16_t plain){
    uint16_t middle = plain;    //middle为中间值
    int i = 0;
    for(i = 0;i < Nr-1 ;i++){
        middle = middle ^ getk2(i,key);
        middle = sbox(middle);
        middle = pbox(middle);
    }
    middle = middle ^ getk2(i++,key);
    middle = sbox(middle);
    return middle ^ getk2(i,key);
}

uint16_t getk(int i){
    //获得轮密钥1
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
