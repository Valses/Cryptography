#include <stdio.h>
#include "gmp.h"
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#define LENGTH 1024
#define TESTTIME 100

void keyCreateRSA(mpz_t key_n, mpz_t key_d, mpz_t key_e, mpz_t key_p, mpz_t key_q);
void createBigPrime(mpz_t prime);
void multiplicativeInverse(mpz_t x_inv, mpz_t x, mpz_t n);

void modeRepeatSquare(mpz_t x, mpz_t y, mpz_t e, mpz_t d, mpz_t n);
void ChineseRemainderTheorem(mpz_t x, mpz_t y, mpz_t e, mpz_t d, mpz_t p, mpz_t q, mpz_t n);
void montgomery(mpz_t x, mpz_t y, mpz_t e, mpz_t d, mpz_t n);
void gmp(mpz_t x, mpz_t y, mpz_t e, mpz_t d, mpz_t n);

void montMult(mpz_t p, mpz_t a, mpz_t b, mpz_t n, mp_limb_t n_1);
void montPowerMod(mpz_t z, mpz_t a, mpz_t b, mpz_t n, mpz_t K, mp_limb_t n_1);
void montMult2bit(mpz_t p, mpz_t a, mpz_t b, mpz_t n);
void squareAndMultiply(mpz_t z, mpz_t a, mpz_t b, mpz_t n);
void squareAndMultiply2(mpz_t z, mpz_t a, mpz_t b, mpz_t n);


int main(void){
    printf("\nThis is my Curriculum Design of Cryptography about RSA.");
    printf("\nPress Enter to create all keys needed in RSA.");
    char c;
    scanf("%c",&c);
    mpz_t key_p, key_q, key_d, key_e, key_n;
    mpz_init(key_n);
    mpz_init(key_p);
    mpz_init(key_q);
    mpz_init(key_d);
    mpz_init(key_e);
	clock_t clockBegin, clockEnd;
	printf("\n\nKey creating...\n");
	clockBegin = clock();
    keyCreateRSA(key_n, key_d, key_e, key_p, key_q);
	clockEnd = clock();
    /*
    gmp_printf("p = %ZX\n", key_p);
    gmp_printf("q = %ZX\n", key_q);
    gmp_printf("e = %ZX\n", key_e);
    gmp_printf("d = %ZX\n", key_d);
    gmp_printf("n = %ZX\n", key_n);
	*/
    printf("\nAll keys are created successfully! Time = %dms",clockEnd = clockBegin);
    mpz_t x, y;
    mpz_init(x);
    mpz_init(y);
    printf("\n\nPlain creating...\n");
	gmp_randstate_t grt;
    gmp_randinit_default(grt);          //设置随机数生成算法为默认
    gmp_randseed_ui(grt, time(NULL));   //设置随机化种子为当前时间
	mpz_urandomb(x, grt, LENGTH/2);
	gmp_printf("plain x = %ZX\n", x);
    printf("\n----------------------Methods of RSA decryption-------------------------");
    printf("\n--       1.Mode Repeat Square");
    printf("\n--       2.Chinese Remainder Theorem");
    printf("\n--       3.Montgomery");
	printf("\n--       4.GMP");
    printf("\n--       0.exit");
    printf("\n------------------------------------------------------------------------");
    int i;
    do{
        printf("\nPlease choose one computation:");
        scanf("%d", &i);
        switch(i){
        case 1:{
            modeRepeatSquare(x, y, key_e, key_d, key_n);
            break;
        }
        case 2:{
            ChineseRemainderTheorem(x, y, key_e, key_d, key_p, key_q, key_n);
            break;
        }
        case 3:{
            montgomery(x, y, key_e, key_d, key_n);
            break;
        }
		case 4:{
			gmp(x, y, key_e, key_d, key_n);
			break;
		}
        default:
            break;
        }
    }while(i);
    return 0;
}
void keyCreateRSA(mpz_t key_n, mpz_t key_d, mpz_t key_e, mpz_t key_p, mpz_t key_q){
    /**RSA密钥生成函数
     *
     * key_n, key_e为公钥
     * key_p, key_q, key_d为私钥
     */
    createBigPrime(key_p);
    do{
        createBigPrime(key_q);
    }while(!mpz_cmp(key_p, key_q));

    mpz_t p_sub, q_sub, euler_n;
    mpz_init(p_sub);
    mpz_init(q_sub);
    mpz_init(euler_n);
    mpz_mul(key_n, key_p, key_q);
    mpz_sub_ui(p_sub, key_p, 1);
    mpz_sub_ui(q_sub, key_q, 1);
    mpz_mul(euler_n, p_sub, q_sub);
    mpz_set_ui(key_e, 65537);
    multiplicativeInverse(key_d, key_e, euler_n);
    mpz_clear(euler_n);
    mpz_clear(p_sub);
    mpz_clear(q_sub);
}//keyCreateRSA

void createBigPrime(mpz_t prime){
    /** 随机生成LENGTH/2位大素数函数
     *
     *  生成的素数赋值给prime
     *
     */
    gmp_randstate_t grt;
    gmp_randinit_default(grt);          //设置随机数生成算法为默认
    gmp_randseed_ui(grt, time(NULL));   //设置随机化种子为当前时间
    mpz_t x;
    mpz_init(x);
    mpz_urandomb(x, grt, LENGTH/2);
    if(mpz_even_p(x))
        mpz_add_ui(x, x, 1);
    while(!(mpz_probab_prime_p(x, 10) > 0))
        mpz_add_ui(x, x, 2);
    mpz_set(prime, x);
    mpz_clear(x);
}//createBigPrime

void multiplicativeInverse(mpz_t x_inv, mpz_t x, mpz_t n){
    /** 求逆函数
     *
     *  x_inv为x模n的逆
     *
     */
    mpz_t a, b, t, t0, q, r ,temp;
    mpz_t m1, m2;               //中间变量m1,m2
    mpz_init_set(a, n);
    mpz_init_set(b, x);
    mpz_init_set_ui(t, 1);
    mpz_init_set_ui(t0, 0);
    mpz_inits(q, r, temp, m1, m2, NULL); 
	mpz_fdiv_q(q, a, b);         //q = a / b
    mpz_mul(m1, q, b);
    mpz_sub(r, a, m1);

    while(mpz_cmp_ui(r,0)){
        mpz_mul(m2, q, t);
        mpz_sub(temp, t0, m2);
        mpz_mod(temp, temp, n);
        mpz_set(t0, t);
        mpz_set(t, temp);
        mpz_set(a, b);
        mpz_set(b, r);
        mpz_fdiv_q(q, a, b);
        mpz_mul(m2, q, b);
        mpz_sub(r, a, m2);
    }
	if(mpz_cmp_ui(t,0))               //t > 0，则所求逆为 t
		mpz_set(x_inv, t);
	else                              //否则，所求逆为 t + n
		mpz_add(x_inv, t, n);

    mpz_clear(m1); mpz_clear(m2);
    mpz_clear(a); mpz_clear(b);
    mpz_clear(q); mpz_clear(r);
    mpz_clear(temp);
    mpz_clear(t0); mpz_clear(t);
}//multiplicativeInverse


void gmp(mpz_t x, mpz_t y, mpz_t e, mpz_t d, mpz_t n){
	//自带GMP
	printf("\n--------------------------------GMP--------------------------------\n");
    clock_t clockBegin1,clockBegin2,clockEnd;
    mpz_set_ui(y, 0);
    clockBegin1 = clock();
    mpz_powm(y, x, e, n);
    mpz_set_ui(x, 0);
	int i;
    clockBegin2 = clock();
	for(i  = 0; i < TESTTIME; i++){
		mpz_powm(x, y, d, n);
	}
    clockEnd = clock();
	//gmp_printf("\nAfter encryption:\ny = %ZX\n", y);
	//gmp_printf("\nAfter decryption:\nx = %ZX\n", x);
    printf("\nEncryption time = %dms\n", clockBegin2 - clockBegin1);
	printf("Decryption time = %fms\n", (double)(clockEnd - clockBegin2)/TESTTIME);
	printf("\n--------------------------------GMP--------------------------------\n");
	
}


void squareAndMultiply(mpz_t z, mpz_t a, mpz_t b, mpz_t n){
    /** 平方乘运算
     *
     *
     */
    mpz_t b0, r;
    mpz_init(b0);
    mpz_init(r);
    mpz_set(b0, b);
    mpz_set_ui(z, 1);
	mpz_set(r, a);
    //mpz_mod(r, a, n);
	while(mpz_cmp_ui(b0, 0)){
        if(mpz_tstbit(b0, 0)){
            mpz_mul(z, z, r);
            mpz_mod(z, z, n);
        }
        mpz_mul(r, r, r);
        mpz_mod(r, r, n);
		mpz_fdiv_q_2exp(b0, b0, 1);
    }
    mpz_clear(r);
    mpz_clear(b0);
}

void squareAndMultiply2(mpz_t z, mpz_t a, mpz_t b, mpz_t n){
    /** 平方乘运算2
     *
     *
     */
	int i;
    mpz_t r;
    mpz_init(r);
    mpz_set_ui(z, 1);
	mpz_set(r, a);
	for(i = 0; i < LENGTH; i++){
		if(mpz_tstbit(b, i)){
            mpz_mul(z, z, r);
            mpz_mod(z, z, n);
        }
        mpz_mul(r, r, r);
        mpz_mod(r, r, n);
	}
    mpz_clear(r);
}

void modeRepeatSquare(mpz_t x, mpz_t y, mpz_t e, mpz_t d, mpz_t n){
    /** 模重复平方加密解密
     *
     */
    printf("\n---------------------------Mode Repeat Square---------------------------\n");
    clock_t clockBegin1, clockBegin2, clockEnd1, clockEnd2;
    mpz_set_ui(y, 0);
    clockBegin1 = clock();
    squareAndMultiply1(y, x, e, n);
	clockEnd1 = clock();
    mpz_set_ui(x, 0);
	int i;
    clockBegin2 = clock();
	for(i  = 0; i < TESTTIME; i++){
		//mpz_powm(x, y, d, n);
		squareAndMultiply2(x, y, d, n);
	}
    clockEnd2 = clock();
	//gmp_printf("\nAfter encryption:\ny = %ZX\n", y);
	//gmp_printf("\nAfter decryption:\nx = %ZX\n", x);
    printf("\nEncryption time = %dms\n", clockEnd1 - clockBegin1);
	printf("Decryption time = %fms\n", (double)(clockEnd2 - clockBegin2)/TESTTIME);
	printf("\n---------------------------Mode Repeat Square---------------------------\n");

}


/******************************中国剩余定理****************************/
void ChineseRemainderTheorem(mpz_t x, mpz_t y, mpz_t e, mpz_t d, mpz_t p, mpz_t q, mpz_t n){
	 /** 中国剩余定理解密
     *
     */
    printf("\n-----------------------Chinese Remainder Theorem------------------------\n");
    clock_t clockBegin1, clockBegin2, clockEnd1, clockEnd2;
    mpz_set_ui(y, 0);
    clockBegin1 = clock();
    squareAndMultiply(y, x, e, n);
    mpz_set_ui(x, 0);
	int i;
    clockEnd1 = clock();
	mpz_t x1, x2, p_inv, q_inv, d1, d2, p1, q1;
	mpz_inits(x1, x2, q_inv, p_inv, NULL);
	mpz_inits(d1, d2, p1, q1, NULL);
	multiplicativeInverse(p_inv, p, q);
	multiplicativeInverse(q_inv, q, p);
	mpz_mul(q_inv, q, q_inv);
	mpz_mul(p_inv, p, p_inv);	
	mpz_sub_ui(p1, p, 1);
	mpz_sub_ui(q1, q, 1);
	mpz_mod(d1, d, p1);
	mpz_mod(d2, d, q1);
	clockBegin2 = clock();
	for(i  = 0; i < TESTTIME; i++){
		mpz_powm(x1, y, d1, p);
		mpz_powm(x2, y, d2, q);		
		mpz_mul(x1, x1, q_inv);
		mpz_mul(x2, x2, p_inv);
		mpz_add(x, x1, x2);
		mpz_mod(x, x, n);
	}
    clockEnd2 = clock();
    mpz_clears(x1, x2, p1, q1, d1, d2, q_inv, p_inv, NULL)
    gmp_printf("\nAfter encryption:\ny = %ZX\n", y);
	gmp_printf("\nAfter decryption:\nx = %ZX\n", x);
    printf("\nEncryption time = %dms\n",  clockEnd1 - clockBegin1);
	printf("Decryption time = %fms\n", (double)(clockEnd2 - clockBegin2)/TESTTIME);
    printf("\n-----------------------Chinese Remainder Theorem------------------------\n");
}


/*******************蒙哥马利****************************/

void montPowerMod(mpz_t z, mpz_t a, mpz_t b, mpz_t n, mpz_t K, mp_limb_t n_1){
	/** 蒙哥马利模幂
     *
     */
	int i;
	mpz_t a0, x1;
	mpz_inits(a0, x1, NULL);
	mpz_set_ui(x1, 1);
	montMult(a0, K, a, n, n_1);
	mpz_mul_2exp(z, x1, LENGTH);
	mpz_mod(z, z, n);
	for(i = 0; i < LENGTH; i++){   
        if(mpz_tstbit(b, i))
            montMult(z, z, a0, n, n_1);
		montMult(a0, a0, a0, n, n_1);
    }
	montMult(z, x1, z, n, n_1);
	mpz_clears(a0, x1, NULL);
	
}

void montMult(mpz_t p, mpz_t a, mpz_t b, mpz_t n, mp_limb_t n_1){
	/**蒙哥马利模乘
	*
	*
	*/
	//mpz_t T, T0;
	//mpz_inits(T, T0, NULL);
	//mpz_mul(T, a, b);
	mp_limb_t *temp, q, res[32], carry, t[32];
	if (a->_mp_size > b->_mp_size)
	   mpn_mul(t, a->_mp_d, a->_mp_size,b->_mp_d,b->_mp_size);
	else
	   mpn_mul(t, b->_mp_d, b->_mp_size, a->_mp_d, a->_mp_size);
   
	temp = t;
	int i;
	for(i = 0; i < 32; i++){
		q = (*temp) * n_1;
		res[i] = mpn_addmul_1(temp, n->_mp_d, n->_mp_size, q);
		temp++;
		//mpz_addmul_ui(T, n, q);
		//mpz_fdiv_q_2exp(T, T, 32);
	}
	carry = mpn_add_n(temp, temp, res, n->_mp_size);
	//gmp_printf("T = %ZX\n", T);
	if (carry || mpn_cmp(temp, n->_mp_d, n->_mp_size) >= 0)
		mpn_sub_n(temp, temp, n->_mp_d, n->_mp_size);
	mpz_import(p, n->_mp_size, -1, sizeof(mp_limb_t), 0, 0,temp);
	
}

void montgomery(mpz_t x, mpz_t y, mpz_t e, mpz_t d, mpz_t n){
    /** 蒙哥马利加解密
     *
     */
    printf("\n----------------------------Montgomery----------------------------------\n");
    clock_t clockBegin1, clockBegin2, clockEnd1, clockEnd2;
    mpz_set_ui(y, 0);
    clockBegin1 = clock();
    squareAndMultiply(y, x, e, n);
	clockEnd1 = clock();
    mpz_set_ui(x, 0);
	mp_limb_t n_1;
	int i, k = LENGTH;
	mpz_t n0, r, x1, K;
	mpz_inits(n0, r, K, x1, NULL);
	mpz_init_set_ui(x1, 1);
    mpz_mul_2exp(K, x1, 2*k);
	mpz_mul_2exp(r, x1, 32);
	mpz_mod(K, K, n);
	mpz_mod(n0, n, r);
	mpz_invert(n0, n0, r);
	mpz_sub(n0, r, n0);
	n_1 = *(n0->_mp_d);
	
    clockBegin2 = clock();
	for(i = 0; i < TESTTIME; i++){
		montPowerMod(x, y, d, n, K, n_1);
	}
	
    clockEnd2 = clock();
	mpz_clears(n0, r, x1, K, NULL);
	//gmp_printf("\nAfter encryption:\ny = %ZX\n", y);
	//gmp_printf("\nAfter decryption:\nx = %ZX\n", x);
    printf("\nEncryption time = %dms\n", (int)(clockEnd1 - clockBegin1));
	printf("Decryption time = %fms\n", (double)(clockEnd2 - clockBegin2)/TESTTIME);
    printf("\n----------------------------Montgomery----------------------------------\n");
}
