/** \brief
 *
 * \param
 * \param
 * \return
 *
 */

#include <stdio.h>
#include <stdlib.h>
#define Nr 4       //��������
#define BIT 16      //����λ������p�г���
#define L 4         //ÿ��s�е�����bit��
#define LS 16       //s�г���

typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef uint16_t spncode;
uint32_t K = 0x3A94D63F;     //ԭʼ��Կ
uint16_t s[LS] = {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7};
uint16_t p[BIT] = {1,5,9,13,2,6,10,14,3,7,11,15,4,8,12,16};
//s�к�p�еĶ���

spncode sbox(spncode c){
    spncode s_chiper = 0;
    spncode mask = 0xf;
    spncode m = 0;         //��¼s�к������м�ֵ
    int i = 1;
    for(i = 1;i <= (BIT/L);i++){
        m = (c >> (BIT - (i*4))) & mask;
        s_chiper = (s[m] << (BIT - (i*4))) | s_chiper;
    }
    return s_chiper;
}


spncode pbox(spncode c){
    spncode v1, v2, v3, v4, v5, v6, v7;
    v1 = c & 0x8421;
    v2 = c & 0x4210;
    v3 = c & 0x0842;
    v4 = c & 0x2100;
    v5 = c & 0x0084;
    v6 = c & 0x1000;
    v7 = c & 0x0008;
    return v1 | (v2 >> 3) | (v3 << 3) | (v4 >> 6) | (v5 << 6) | (v6 >> 9) | (v7 << 9);
}

spncode getk(int i){
    //��������Կ
    spncode k = K >> (BIT - (i*4));
    return k;
}

spncode spn(spncode plain){
    spncode middle = plain;    //middleΪ�м�ֵ
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

int main(void){
    spncode chiper = 0;         //����
    spncode plain = 0;          //����
    plain = 0x26b7;
    chiper = spn(plain);
    printf("Chiper is: %0x\n\n",chiper);
    return 0;
}
