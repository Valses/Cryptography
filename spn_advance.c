/** 任务四：SPN增强
 * 描述：
 * 增强SPN的安全性,如增加分组的长度、密钥的长度、S盒、轮数等
 * 生成10M密文，进行随机性检测
 *
 */

#include <stdio.h>
#include <stdlib.h>
#define Nr 16       //加密轮数

#define BIT 64      //明文位数，即p盒长度
#define L 8         //每个s盒的输入bit数
#define LS 256       //s盒长度
#define PLAIN_FILE_OPEN_ERROR -1
#define CIPHER_FILE_OPEN_ERROR -2
#define TenMNum 1310720


typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

uint64_t iv = 0x1f2f354a5d69718b;    //初向量始
uint64_t K = 0x3A94D63F13794a5f;     //原始密钥
uint64_t KEY[17];
uint16_t s_key[16] = {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7};
uint16_t s[16][16] = {
    {0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
    {0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},
    {0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15},
    {0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75},
    {0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84},
    {0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf},
    {0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8},
    {0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2},
    {0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},
    {0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
    {0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},
    {0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},
    {0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},
    {0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},
    {0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},
    {0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16},
};
uint16_t p[BIT] = {
    1,5,9,13,17,21,25,29,33,37,41,45,49,53,57,61,
    2,6,10,14,18,22,26,30,34,38,42,46,50,54,58,62,
    3,7,11,15,19,23,27,31,35,39,43,47,51,55,59,63,
    4,8,12,16,20,24,28,32,36,40,44,48,52,56,60,64
};
uint16_t s_in[16][16];
uint16_t p_in[BIT];


uint64_t sbox(uint64_t c){
    uint64_t s_cipher = 0;
    uint64_t mask1 = 0xf0, mask2 = 0x0f;
    uint64_t m1 = 0, m2 = 0, m3 = 0;         //记录s盒函数的中间值
    int i = 1;
    for(i = 1; i <= 8; i++){
        m1 = ((c >> (8 - i)*8) & mask1) >> 4;
        m2 = (c >> (8 - i)*8) & mask2;
        m3 = s[m1][m2];
        m3 = m3 << (8 - i) * 8;
        s_cipher = s_cipher | m3;
        /*
        *很奇怪的错误，当s_cipher表达式如下就是错误的
        *s_cipher = s_cipher | (s[m1][m2] << ((8 - i)*8));
        */
    }
    return s_cipher;
}

uint64_t sbox_in(uint64_t c){
    uint64_t s_cipher = 0;
    uint64_t mask1 = 0xf0, mask2 = 0x0f;
    uint64_t m1 = 0, m2 = 0, m3 = 0;         //记录s盒函数的中间值
    int i = 1;
    for(i = 1; i <= 8; i++){
        m1 = (c >> ((8 - i)*8) & mask1) >> 4;
        m2 = (c >> (8 - i)*8) & mask2;
        m3 = s_in[m1][m2];
        m3 = m3 << (8 - i) * 8;
        s_cipher = s_cipher | m3;
    }
    return s_cipher;
}

uint64_t pbox(uint64_t c){
    uint64_t p_cipher = 0;
    uint64_t mask = 0x1;
    uint64_t m = 0;
    int i = 1;
    for(i = 1; i <= BIT; i++){
        m = ((c >> (BIT - i)) & mask);
        m = m << (BIT - p[i-1]);
        p_cipher = p_cipher | m;
    }
    return p_cipher;
}

uint64_t pbox_in(uint64_t c){
    uint64_t p_cipher = 0;
    uint64_t mask = 0x1;
    uint64_t m = 0;
    int i = 1;
    for(i = 1; i <= BIT; i++){
        m = ((c >> (BIT - i)) & mask);
        m = m << (BIT - p_in[i-1]);
        p_cipher = p_cipher | m;
    }
    return p_cipher;
}

uint16_t rol(uint16_t x, int i){
    //循环左移函数
    uint16_t left = x << (16 - i);
    uint16_t right = x >> i;
    return left | right;
}

uint64_t getk(int i){
    //获得i轮轮密钥
	static uint64_t key;
	if(!i){
		key = K;
	}
	else{
        uint64_t mask = 0x000f000f000f000f;
		uint64_t k0 = 0, k1 = 0, k2 = 0, kmask2;
		uint16_t kmask1;
		int j, k;
        for(j = 0; j < 4;j++){
            if(!j){
                k0 = key & mask;
                kmask1 = (uint16_t)((k0 >> 36) | (k0 >> 24) | (k0 >> 12) | k0);
                kmask1 = rol(kmask1,4);
                uint16_t m1 = 0, m2 = 0;
                for(k = 1; k <= 4; k++){
                    m1 = kmask1 >> (16 - (k*4)) ;
                    m1 = m1 & 0xf;
                    m1 = s_key[m1] << (16 - (k*4));
                    m2 = m1 | m2;
                }
                kmask1 = m2;
            }
            k0 = key & (mask << (12-j*4));
            k1 = ((uint64_t)kmask1) << 48;
            kmask2 = (k1 >> (j*4)) | (k1 >> (12 + j*4)) | (k1 >> (24 + j*4)) | (k1 >> (36 + j*4));
            k1 = (k0 ^ kmask2) & (mask << (12-j*4));
            k2 = k2 | k1;
            kmask1 = (uint16_t)((k1 >> (48-j*4)) | (k1 >> (36-j*4)) | (k1 >> (24-j*4)) | (k1 >> (12-j*4)));
        }
        key = k2;
	}
	return key;
	//printf("k%d is: %I64x\n",i,key);
}

void roundk(void){
    //获得全部轮密钥
    int i;
    for(i = 0; i <= Nr; i++){
        KEY[i] = getk(i);
    }
}

void encrypt(uint64_t *plain, uint64_t *cipher){
    //加密
    uint64_t middle = *plain;    //middle为中间值
    int i = 0;
    for(i = 0; i < Nr - 1; i++){
        middle = middle ^ KEY[i];
        middle = sbox(middle);
        middle = pbox(middle);
    }
    middle = middle ^ KEY[Nr-1];
    middle = sbox(middle);
    *cipher = middle ^ KEY[Nr];
}

void decrypt(uint64_t *plain, uint64_t *cipher){
    //解密
    uint64_t middle = *cipher;
    middle = middle ^ KEY[Nr];
    middle = sbox_in(middle);
    int i;
    for(i = Nr - 1; i > 0 ; i--){
        middle = middle ^ KEY[i];
        middle = pbox_in(middle);
        middle = sbox_in(middle);
    }
    *plain = middle ^ KEY[0];
}

void sboxInverse(void){
    //得到sbox的逆
    int i, j, x, y;
    for(i = 0; i < 16; i++){
        for(j = 0; j < 16; j++){
            x = (s[i][j] >> 4) & 0xf;
            y = s[i][j] & 0xf;
            s_in[x][y] = ((i << 4) | j) & 0xff;
        }
    }
}

void pboxInverse(void){
    //得到pbox的逆
    int i, x;
    for(i = 0; i < BIT; i++){
        x = p[i];
        p_in[x-1] = i + 1;
    }
}
int randomTest(char *cipherFile){
    FILE *cipherf;
    uint64_t plainx, cipherx;
    cipherf = fopen(cipherFile, "wb");
    int i;
    cipherx = iv;
    for(i = 0; i < TenMNum; i++){
        plainx = cipherx;
        encrypt(&plainx, &cipherx);
        fwrite(&cipherx, sizeof(uint64_t), 1, cipherf);
    }
    fclose(cipherf);
    return 0;
 }


int main(void){
    printf("\nThis is my Curriculum Design of Cryptography about advanced SPN.");
    char *cipherfile = "zyxcipher.txt";
    uint64_t plain, cipher;
    roundk();
    int op;
    printf("\n------------------MENU-----------------------\n");
    printf("           1.random test\n");
    printf("           1.encrypt\n");
    printf("           2.decrypt\n");
    printf("---------------------------------------------\n");
    printf("Choose one way:");
    scanf("%d",&op);
    switch(op){
        case 1:{
            randomTest(cipherfile);
            printf("\nCreate cipher file for test named \"zyxcipher\"\n");
            break;
        }
        case 2:{
            printf("Please input the plain:");
            scanf("%I64x", &plain);
            encrypt(&plain, &cipher);
            printf("The cipher is %I64x", cipher);
            break;
        }
        case 3:{
            sboxInverse();
            pboxInverse();
            printf("Please input the cipher:");
            scanf("%I64x", &cipher);
            plain = 0;
            decrypt(&plain, &cipher);
            printf("The plain is %I64x", plain);
            break;
        }
        default:{
            printf("Wrong input!\n");
            break;
        }
    }
    return 0;
}

