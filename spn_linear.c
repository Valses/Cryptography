#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define Nr 4       //��������
#define BIT 16     //����λ������p�г���
#define L 4        //ÿ��s�е�����bit��
#define LS 16      //s�г���

typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef int bool;

//char *pFile = "spn_8000.txt";

uint32_t K = 0x3A94D63F;     //ԭʼ��Կ
uint16_t s[LS] = {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7};
//uint16_t p[BIT] = {1,5,9,13,2,6,10,14,3,7,11,15,4,8,12,16};
uint16_t s_in[LS] = {14,3,4,8,1,12,10,15,7,13,9,6,11,2,0,5};
//s�к�p�еĶ���

int spn_linear(void);
int exhaustion(uint32_t key);
bool checkRight(uint32_t key);
uint16_t spn2(uint32_t key,uint16_t plain);
uint16_t getk2(int i,uint32_t key);
uint16_t spn(uint16_t plain);
uint16_t getk(int i);
uint16_t sbox(uint16_t c);
uint16_t pbox(uint16_t c);

int main(void){
    spn_linear();
    return 0;
}

int spn_linear(void){
    clock_t clockBegin,clockEnd;

    uint16_t x = 0,y = 0,v = 0,u = 0;
    uint32_t key = 0;
    int i,j,count[16][16];
    for(i = 0;i < 16;i++){
		for(j = 0;j < 16;j++){
			count[i][j] = 0;
		}
	}
    int n,L1,L2;
    scanf("%d",&n);
    clockBegin = clock();
    for(i = 0;i < n;i++){
        x = rand() % 0xffff;
        y = spn(x);
        for(L1 = 0;L1 < 16;L1++){
            for(L2 = 0;L2 < 16;L2++){
                u = v = 0;
                v = v | (y ^ (L1 << 8) ^ L2);
                int mark = (v >> 8) & 0xf;
                u = u | (s_in[mark] << 8);
                mark = v & 0xf;
                u = u | s_in[mark];
                int z = (x >> 11) ^ (x >> 9) ^ (x >> 8)^ (u >> 10) ^ (u >> 8) ^ (u >> 2) ^ u;
                if(!(z & 0x1)) count[L1][L2]++;
            }
        }
    }
    int max = -1;
    for(L1 = 0;L1 < 16;L1++){
        for(L2 = 0;L2 < 16;L2++){
            count[L1][L2] = abs(count[L1][L2] - n/2);
            if(count[L1][L2] > max){
                max = count[L1][L2];
                key = (L1 << 8) | L2;
            }
        }
    }
    printf("After the linear analysis,the uncompleted key is 0x%08x\n",key);
    exhaustion(key);
    clockEnd = clock();
    double t = (double)(clockEnd - clockBegin);
    t = t / CLOCKS_PER_SEC;
    printf("\nTime = %fs\n",t);

    return 0;
}

int exhaustion(uint32_t key){
    //�������ڱ����ƽ���Կ��ʣ��λ
    //freopen(pFile,"rb",stdin);
    uint16_t x = 0, y = 0;
    x = rand() % 0xffff;
    y = spn(x);
    uint32_t k;                             //��Կ�Ŀ���ֵ
    int k1,k2;
    for(k1 = 0; k1 < 0x100000; k1++){
        for(k2 = 0; k2 < 16; k2++){
            k = key ^ (k1 << 12) ^(k2 << 4);
            if(!(y ^ spn2(k,x))){
                //printf("Possible K = %08x\n",k);
                if(!checkRight(k))
                    printf("K = %0x",k);
            }
        }
    }
    return 0;
}

bool checkRight(uint32_t key){
    //�������ڲ������ҳ�����Կ�Ƿ���ȷ
    int i,n = 10;                //���Զ�ȡ�������Ķ�����
    bool flag = 0;               //flag��������Կ�Ƿ�ͨ�����ԣ�0ΪĬ��ֵ��1Ϊ�������Ķ�δͨ��
    uint16_t x, y;
    for(i = 0; i < n; i++){
        x = rand() % 0xffff;
        y = spn(x);
        if(y ^ spn2(key, x)){
            flag = 1;
            break;
        }
    }
    return flag;
}

uint16_t sbox(uint16_t c){
    uint16_t s_chiper = 0;
    uint16_t mask = 0xf;
    uint16_t m = 0;         //��¼s�к������м�ֵ
    int i = 1;
    for(i = 1; i <= (BIT/L); i++){
        m = (c >> (BIT - (i*4))) & mask;
        s_chiper = (s[m] << (BIT - (i*4))) | s_chiper;
    }
    return s_chiper;
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
    //��������Կ
    uint16_t k = key >> (BIT - (i*4));
    return k;
}

uint16_t spn2(uint32_t key,uint16_t plain){
    uint16_t middle = plain;    //middleΪ�м�ֵ
    int i = 0;
    for(i = 0; i < Nr-1 ; i++){
        middle = middle ^ getk2(i,key);
        middle = sbox(middle);
        middle = pbox(middle);
    }
    middle = middle ^ getk2(i++,key);
    middle = sbox(middle);
    return middle ^ getk2(i,key);
}

uint16_t getk(int i){
    //��������Կ
    uint16_t k = K >> (BIT - (i*4));
    return k;
}

uint16_t spn(uint16_t plain){
    uint16_t middle = plain;    //middleΪ�м�ֵ
    int i = 0;
    for(i = 0; i < Nr-1 ; i++){
        middle = middle ^ getk(i);
        middle = sbox(middle);
        middle = pbox(middle);
    }
    middle = middle ^ getk(i++);
    middle = sbox(middle);
    return middle ^ getk(i);
}
