#include <iostream>
#include <wmmintrin.h>
#include <immintrin.h>
#include <emmintrin.h>
#include <pmmintrin.h>

#define ALIGN(n) __attribute__ ((aligned(n)))
#define pipeline 1
#define size_message 16777216   // Tamaño del mensaje a procesar


#define EXPAND_ASSIST(v1,v2,v3,v4,shuff_const,aes_const)                    \
    v2 = _mm_aeskeygenassist_si128(v4,aes_const);                           \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 16));        \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 140));       \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
    v1 = _mm_xor_si128(v1,v2)

using namespace std;

static void AES_Encrypt_rounds(__m128i * nonce,  __m128i  key, unsigned rounds,unsigned nblks);
static void AES_128_Key_Expansion(const unsigned char *userkey, void *key);
static inline void AES_encrypt(__m128i tmp, __m128i *out,__m128i *key, unsigned rounds);
static void imprimiArreglo(int tam, unsigned char *in );

int main(){
	ALIGN(16) unsigned char key[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    ALIGN(16) unsigned char pt[16]=  {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    ALIGN(16) unsigned char ct[16]=  {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    __m128i roundKeys[11];
    int size=16;

    __m128i block[1];

    AES_128_Key_Expansion(key, roundKeys);

    block[0] = _mm_load_si128((__m128i*) pt);
    
    AES_encrypt(block[0], block, roundKeys,10);

    _mm_store_si128 ((__m128i*)ct,block[0]);

    imprimiArreglo(16,ct);

    return 0;
}


void AES_Encrypt_rounds(__m128i * nonce,  __m128i  key, unsigned rounds,unsigned nblks){
    int i = 0;
    int j = 0;
    for (i=0; i<nblks; ++i)
	    nonce[i] =_mm_xor_si128(nonce[i], key);//4cc
	for(j=1; j<rounds; ++j)
	    for (i=0; i<nblks; ++i)
		    nonce[i] = _mm_aesenc_si128(nonce[i], key); //80cc
    for (i=0; i<nblks; ++i)
	    nonce[i] =_mm_aesenclast_si128(nonce[i], key);
}

// Realizar cifrado AES de un bloque de 128 bits (10 rondas para AES-128)
static inline void AES_encrypt(__m128i tmp, __m128i *out,__m128i *key, unsigned rounds){
	
	int j;
	// Primera ronda (AddRoundKey)
	tmp = _mm_xor_si128 (tmp,key[0]);

    // Rondas intermedias (9 rondas para AES-128)
	for (j=1; j<rounds; j++)  
		tmp = _mm_aesenc_si128 (tmp,key[j]); // SubBytes, ShiftRows, MixColumns y AddRoundKey

	// Última ronda (sin MixColumns)
	tmp = _mm_aesenclast_si128 (tmp,key[j]);// SubBytes, ShiftRows AddRoundKey 
	
	// Guardar el bloque cifrado
	_mm_store_si128 ((__m128i*)out,tmp);
}


static void AES_128_Key_Expansion(const unsigned char *userkey, void *key)
{
    __m128i x0,x1,x2;
    __m128i *kp = (__m128i *)key;
    kp[0] = x0 = _mm_loadu_si128((__m128i*)userkey);
    x2 = _mm_setzero_si128();
    EXPAND_ASSIST(x0,x1,x2,x0,255,1);   kp[1]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,2);   kp[2]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,4);   kp[3]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,8);   kp[4]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,16);  kp[5]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,32);  kp[6]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,64);  kp[7]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,128); kp[8]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,27);  kp[9]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,54);  kp[10] = x0;
}



void imprimiArreglo(int tam, unsigned char *in )
{

    for (int i = 0; i<tam; i++){
        printf("%02x", in[i] );
    }
    printf("\n" );

}