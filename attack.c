#include "attack.h"

#define sampleSize 1

FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream
pid_t pid        = 0;    // process ID (of either parent or child) from fork
int   target_raw[ 2 ];   // unbuffered communication: attacker -> attack target
int   attack_raw[ 2 ];   // unbuffered communication: attack target -> attacker
int interactions;
int keyFound = 0;

// generate random messages for multiple measurements
void generateRandomMessage(uint8_t m[sampleSize][16]){
  // open file to read random bytes from
  FILE *fp = fopen("/dev/urandom", "r");
  int character;
  for(int i=0; i< sampleSize; i++){
    for(int j=0; j<16; j++){
      character = fgetc(fp);
      m[i][j] = character;
    }
  }

  // close file
  fclose(fp);

}

void attack(){
  uint8_t input[sampleSize][16];
  uint8_t c[sampleSize][16];
  uint8_t faulty_c[sampleSize][16];
  uint8_t kAll[16][1024];
  int set1, set2, set3, set4;
  uint8_t k[16];
  uint8_t k9[16];
  uint8_t result[16];
  uint8_t f;
  int tested_keys = 0;

  // get random messages
  generateRandomMessage(input);

  // get correct ciphertext
  for(int i=0; i<sampleSize; i++)
    interact(c[i], 0, 8, 1, 0, 0, 0, input[i]);

  // get faulty ciphertext
  for(int i=0; i<sampleSize; i++)
    interact(faulty_c[i], 1, 8, 1, 0, 0, 0, input[i]);

  // precomute the multiplications in the field
  computeMultiplyTable();
  printf("precomputed multiplication table\n");

  // k1, k8, k11, k14
  set1 = setsEquation1(c, faulty_c, kAll);
  printf("%d possibilities for k1 , k8 , k11, k14\n", set1);
  // k5, k2, k15, k12
  set2 = setsEquation2(c,faulty_c, kAll);
  printf("%d possibilities for k5 , k2 , k15, k12\n", set2);
  // k9, k6, k3, k16
  set3 = setsEquation3(c, faulty_c, kAll);
  printf("%d possibilities for k9 , k6 , k3 , k16\n", set3);
  // k13, k10, k7, k4
  set4 = setsEquation4(c, faulty_c, kAll);
  printf("%d possibilities for k13, k10, k7 , k4 \n", set4);


  printf("Computing last set of equations\n");
  #pragma omp parallel for schedule(auto) private(k, k9, result, f)
  for(int j1 = 0; j1< set1; j1++){
    for(int j2 = 0; j2 < set2; j2++){
      for(int j3 = 0; j3 < set3; j3++){
        for(int j4 = 0; j4 < set4; j4++){
          // key guess after round 10
          k[0]  = kAll[0][j1];  k[7]  = kAll[7][j1];  k[10] = kAll[10][j1];   k[13] = kAll[13][j1];
          k[4]  = kAll[4][j2];  k[1]  = kAll[1][j2];  k[14] = kAll[14][j2];   k[11] = kAll[11][j2];
          k[8]  = kAll[8][j3];  k[5]  = kAll[5][j3];  k[2]  = kAll[2][j3];    k[15] = kAll[15][j3];
          k[12] = kAll[12][j4]; k[9]  = kAll[9][j4];  k[6]  = kAll[6][j4];    k[3]  = kAll[3][j4];

          // same key guess after round 10
          k9[0]  = kAll[0][j1];   k9[7]  = kAll[7][j1];   k9[10] = kAll[10][j1];  k9[13] = kAll[13][j1];
          k9[4]  = kAll[4][j2];   k9[1]  = kAll[1][j2];   k9[14] = kAll[14][j2];  k9[11] = kAll[11][j2];
          k9[8]  = kAll[8][j3];   k9[5]  = kAll[5][j3];   k9[2]  = kAll[2][j3];   k9[15] = kAll[15][j3];
          k9[12] = kAll[12][j4];  k9[9]  = kAll[9][j4];   k9[6]  = kAll[6][j4];   k9[3]  = kAll[3][j4];

          // get key from round 9
          getRoundK(k9, 10);

          // get result of equation
          f = fEquation2(c[0], faulty_c[0], k, k9);

          // check te above result against the other 3 results
          if( f == fEquation3(c[0], faulty_c[0], k, k9) &&  (mul_table[f][3] == fEquation4(c[0], faulty_c[0], k, k9)) && (mul_table[f][2] == fEquation1(c[0], faulty_c[0], k, k9)) ) {
            tested_keys = tested_keys + 1;
            if(tested_keys % 5 == 0)
              printf("potential keys tested: %d \n", tested_keys  );
            // get original key used for encryption
            getOriginalKey(k9, 9);

            // simulate AES encryption using the retrieved key
            AES_KEY rk;
            AES_set_encrypt_key( k9, 128, &rk );
            AES_encrypt( input[0], result, &rk );

            // if result is right, found key
            if( !memcmp( result, c[0], 16 * sizeof( uint8_t ) ) ) {
              printf("potential keys tested: %d \n", tested_keys  );
              printf( "Key found: ");
              printState(k9);
              printf("interactions with the oracle: %d\n", interactions);
              keyFound = 1;
              exit(EXIT_SUCCESS);
            }
          }
        }
      }
    }
  }
  printf("!!!!!!Key not found, something might have gone wrong, try again !!!!\n");
}

void interact(uint8_t c[16],
              const int fault,
              const int r,
              const int f ,
              const int p,
              const int i,
              const int j,
              const uint8_t m[16]) {

  if(fault){
    // Send      G      to   attack target.
    fprintf( target_in, "%d,%d,%d,%d,%d", r, f, p, i, j );
  }
  fprintf(target_in, "\n");

  for(int l=0; l<16; l++){
    fprintf(target_in, "%02X",  m[l]);
  }
  fprintf(target_in,"\n");
  fflush( target_in );

  // Receive ( t, r ) from attack target.
  for(int l=0; l<16; l++)
    if( 1 != fscanf( target_out, "%2hhx", &c[l] ) ) {
      abort();
    }
    interactions++;
}

unsigned char s[256] = {
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

unsigned char inv_s[256] = {
  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
  0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
  0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
  0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
  0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
  0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
  0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
  0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
  0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
  0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
  0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
  0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
  0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
  0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

unsigned char rcon[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

int main( int argc, char* argv[] ){
  if( pipe( target_raw ) == -1 ) {
    abort();
  }
  if( pipe( attack_raw ) == -1 ) {
    abort();
  }

  switch( pid = fork() ) {
    case -1 : {
      // The fork failed; reason is stored in errno, but we'll just abort.
      abort();
    }

    case +0 : {
      // (Re)connect standard input and output to pipes.
      close( STDOUT_FILENO );
      if( dup2( attack_raw[ 1 ], STDOUT_FILENO ) == -1 ) {
        abort();
      }
      close(  STDIN_FILENO );
      if( dup2( target_raw[ 0 ],  STDIN_FILENO ) == -1 ) {
        abort();
      }

      // Produce a sub-process representing the attack target.
      execl( argv[ 1 ], argv[ 0 ], NULL );

      // Break and clean-up once finished.
      break;
   }

    default : {
      // Construct handles to attack target standard input and output.
      if( ( target_out = fdopen( attack_raw[ 0 ], "r" ) ) == NULL ) {
        abort();
      }
      if( ( target_in  = fdopen( target_raw[ 1 ], "w" ) ) == NULL ) {
        abort();
      }

      // Execute a function representing the attacker.
      while(keyFound == 0)
        attack();

      // Break and clean-up once finished.
      break;
   }
 }
}

void computeMultiplyTable(){
  int x, y;
  for(x = 0; x<= 0xFF; x++){
    for(y = 0; y<=0xFF; y++){
      mul_table[x][y] = gf28_mul(x, y);
    }
  }
}

int setEquation1(const uint8_t x[],  const uint8_t x1[], uint8_t k[16][1024]){
  int possibilities = 0;
  int k1, k8, k11, k14, ro;
  for(ro=1; ro <= 0xFF; ro++){

    for(k1 = 0; k1 <= 0xFF; k1++){
      if(mul_table[2][ro] == (inv_s[x[0] ^ k1] ^ inv_s[x1[0] ^ k1]) ){
        for(k14 = 0; k14 <= 0xFF; k14++){

          if(ro == (inv_s[x[13]^ k14] ^ inv_s[x1[13] ^ k14]) )
            for(k11 = 0; k11<= 0xFF; k11++){

              if(ro == (inv_s[x[10] ^ k11] ^ inv_s[x1[10] ^ k11]) )
                for(k8 = 0; k8<= 0xFF; k8++){

                  if(mul_table[3][ro] == (inv_s[x[7] ^ k8] ^ inv_s[x1[7] ^ k8]) ){
                    k[0][possibilities]  = k1;
                    k[13][possibilities] = k14;
                    k[10][possibilities] = k11;
                    k[7][possibilities]  = k8;
                    possibilities++;
              }
            }
          }
        }
      }
    }
  }
  return possibilities;
}

int setsEquation1(const uint8_t x[sampleSize][16], const uint8_t x1[sampleSize][16], uint8_t kAll[16][1024] ){
  int k1, k8, k11, k14, ro;
  uint8_t k[sampleSize][16][1024];
  int possibilities[sampleSize];
  for(int i=0; i<sampleSize; i++){
    possibilities[i] = 0;
    for(ro=1; ro <= 0xFF; ro++){

      for(k1 = 0; k1 <= 0xFF; k1++){
        if(mul_table[2][ro] == (inv_s[x[i][0] ^ k1] ^ inv_s[x1[i][0] ^ k1]) ){
          for(k14 = 0; k14 <= 0xFF; k14++){

            if(ro == (inv_s[x[i][13]^ k14] ^ inv_s[x1[i][13] ^ k14]) )
              for(k11 = 0; k11<= 0xFF; k11++){

                if(ro == (inv_s[x[i][10] ^ k11] ^ inv_s[x1[i][10] ^ k11]) )
                  for(k8 = 0; k8<= 0xFF; k8++){

                    if(mul_table[3][ro] == (inv_s[x[i][7] ^ k8] ^ inv_s[x1[i][7] ^ k8]) ){
                      k[i][0][possibilities[i]]  = k1;
                      k[i][13][possibilities[i]] = k14;
                      k[i][10][possibilities[i]] = k11;
                      k[i][7][possibilities[i]]  = k8;
                      possibilities[i]++;
                }
              }
            }
          }
        }
      }
    }
    // printf("message %d has %d poss\n",i, possibilities[i] );
  }
  int poss = 0, check = 1;
  for( int j=0; j<possibilities[0]; j++){
    k1 = k[0][0][j];
    k14 = k[0][13][j];
    k11 = k[0][10][j];
    k8 = k[0][7][j];
    check = 1;
    for(int i=1; i<sampleSize && check == 1; i++){
      check = 0;
      for(int j1 = 0; j1<possibilities[i]; j1++){
        if( k1 == k[i][0][j1] && k14 == k[i][13][j1] && k11 == k[i][10][j1] && k8 == k[i][7][j1] ){
          check = 1;
          // printf("message %d : %02X %02X %02X %02X\n", i, k1, k14, k11, k8);
        }
      }
    }
    if(check == 1){
      kAll[0][poss] = k1;
      kAll[13][poss] = k14;
      kAll[10][poss] = k11;
      kAll[7][poss] = k8;
      poss++;
    }
  }
  // printf("poss = %d\n",poss );
  return poss;
}


int setsEquation2(const uint8_t x[sampleSize][16], const uint8_t x1[sampleSize][16], uint8_t kAll[16][1024] ){
  int k5, k2, k15, k12, ro;
  uint8_t k[sampleSize][16][1024];
  int possibilities[sampleSize];
  for(int i=0; i<sampleSize; i++){
    possibilities[i] = 0;
    for(ro=1; ro <= 0xFF; ro++){
      for(k5 = 0; k5 <= 0xFF; k5++){

        if(ro == (inv_s[x[i][4] ^ k5] ^ inv_s[x1[i][4] ^ k5]) ){
          for(k2 = 0; k2 <= 0xFF; k2++){

            if(ro == (inv_s[x[i][1]^ k2] ^ inv_s[x1[i][1] ^ k2]) )
            for(k15 = 0; k15<= 0xFF; k15++){

              if(mul_table[3][ro]== (inv_s[x[i][14] ^ k15] ^ inv_s[x1[i][14] ^ k15]) )
              for(k12 = 0; k12<= 0xFF; k12++){

                if(mul_table[2][ro] == (inv_s[x[i][11] ^ k12] ^ inv_s[x1[i][11] ^ k12]) ){
                  k[i][4][possibilities[i]]   = k5;
                  k[i][1][possibilities[i]]   = k2;
                  k[i][14][possibilities[i]]  = k15;
                  k[i][11][possibilities[i]]  = k12;
                  possibilities[i]++;
                }
              }
            }
          }
        }
      }
    }
    // printf("message %d has %d poss\n",i, possibilities[i] );
  }
  int poss = 0, check = 1;
  for( int j=0; j<possibilities[0]; j++){
    k5 = k[0][4][j];
    k2 = k[0][1][j];
    k15 = k[0][14][j];
    k12 = k[0][11][j];
    check = 1;
    for(int i=1; i<sampleSize && check == 1; i++){
      check = 0;
      for(int j1 = 0; j1<possibilities[i]; j1++){
        if( k5 == k[i][4][j1] && k2 == k[i][1][j1] && k15 == k[i][14][j1] && k12 == k[i][11][j1] ){
          check = 1;
          // printf("%02X %02X %02X %02X\n", k5, k2, k15, k12);
        }
      }
    }
    if(check == 1){
      kAll[4][poss] = k5;
      kAll[1][poss] = k2;
      kAll[14][poss] = k15;
      kAll[11][poss] = k12;
      poss++;
    }
  }
  // printf("poss = %d\n",poss );
  return poss;
}

int setEquation2(const uint8_t x[],  const uint8_t x1[], uint8_t k[16][1024]){
  int possibilities = 0;
  int k5, k2, k15, k12, ro;
  for(ro=1; ro <= 0xFF; ro++){
    for(k5 = 0; k5 <= 0xFF; k5++){

      if(ro == (inv_s[x[4] ^ k5] ^ inv_s[x1[4] ^ k5]) ){
        for(k2 = 0; k2 <= 0xFF; k2++){

          if(ro == (inv_s[x[1]^ k2] ^ inv_s[x1[1] ^ k2]) )
            for(k15 = 0; k15<= 0xFF; k15++){

              if(mul_table[3][ro]== (inv_s[x[14] ^ k15] ^ inv_s[x1[14] ^ k15]) )
                for(k12 = 0; k12<= 0xFF; k12++){

                  if(mul_table[2][ro] == (inv_s[x[11] ^ k12] ^ inv_s[x1[11] ^ k12]) ){
                    k[4][possibilities]   = k5;
                    k[1][possibilities]   = k2;
                    k[14][possibilities]  = k15;
                    k[11][possibilities]  = k12;
                    possibilities++;
              }
            }
          }
        }
      }
    }
  }
  return possibilities;
}


int setsEquation3(const uint8_t x[sampleSize][16], const uint8_t x1[sampleSize][16], uint8_t kAll[16][1024] ){
  int k9, k6, k3, k16, ro;
  uint8_t k[sampleSize][16][1024];
  int possibilities[sampleSize];
  for(int i=0; i<sampleSize; i++){
    possibilities[i] = 0;
    for(ro=1; ro <= 0xFF; ro++){
      for(k9 = 0; k9 <= 0xFF; k9++){

        if(ro == (inv_s[x[i][8] ^ k9] ^ inv_s[x1[i][8] ^ k9]) ){
          for(k6 = 0; k6 <= 0xFF; k6++){

            if(mul_table[3][ro] == (inv_s[x[i][5]^ k6] ^ inv_s[x1[i][5] ^ k6]) )
            for(k3 = 0; k3<= 0xFF; k3++){

              if(mul_table[2][ro] == (inv_s[x[i][2] ^ k3] ^ inv_s[x1[i][2] ^ k3]) )
              for(k16 = 0; k16<= 0xFF; k16++){

                if(ro == (inv_s[x[i][15] ^ k16] ^ inv_s[x1[i][15] ^ k16]) ){
                  k[i][8][possibilities[i]]   = k9;
                  k[i][5][possibilities[i]]   = k6;
                  k[i][2][possibilities[i]]   = k3;
                  k[i][15][possibilities[i]]  = k16;
                  possibilities[i]++;
                }
              }
            }
          }
        }
      }
    }
    // printf("message %d has %d poss\n",i, possibilities[i] );
  }
  int poss = 0, check = 1;
  for( int j=0; j<possibilities[0]; j++){
    k9 = k[0][8][j];
    k6 = k[0][5][j];
    k3 = k[0][2][j];
    k16 = k[0][15][j];
    check = 1;
    for(int i=1; i<sampleSize && check == 1; i++){
      check = 0;
      for(int j1 = 0; j1<possibilities[i]; j1++){
        if( k9 == k[i][8][j1] && k6 == k[i][5][j1] && k3 == k[i][2][j1] && k16 == k[i][15][j1] ){
          check = 1;
          // printf("%02X %02X %02X %02X\n", k9, k6, k3, k16);
        }
      }
    }
    if(check == 1){
      kAll[8][poss] = k9;
      kAll[5][poss] = k6;
      kAll[2][poss] = k3;
      kAll[15][poss] = k16;
      poss++;
    }
  }
  // printf("poss = %d\n",poss );
  return poss;
}

int setEquation3(const uint8_t x[],  const uint8_t x1[], uint8_t k[16][1024]){
  int possibilities = 0;
  int k9, k6, k3, k16, ro;
  for(ro=1; ro <= 0xFF; ro++){
    for(k9 = 0; k9 <= 0xFF; k9++){

      if(ro == (inv_s[x[8] ^ k9] ^ inv_s[x1[8] ^ k9]) ){
        for(k6 = 0; k6 <= 0xFF; k6++){

          if(mul_table[3][ro] == (inv_s[x[5]^ k6] ^ inv_s[x1[5] ^ k6]) )
            for(k3 = 0; k3<= 0xFF; k3++){

              if(mul_table[2][ro] == (inv_s[x[2] ^ k3] ^ inv_s[x1[2] ^ k3]) )
                for(k16 = 0; k16<= 0xFF; k16++){

                  if(ro == (inv_s[x[15] ^ k16] ^ inv_s[x1[15] ^ k16]) ){
                    k[8][possibilities]   = k9;
                    k[5][possibilities]   = k6;
                    k[2][possibilities]   = k3;
                    k[15][possibilities]  = k16;
                    possibilities++;
              }
            }
          }
        }
      }
    }
  }
  return possibilities;
}


int setsEquation4(const uint8_t x[sampleSize][16], const uint8_t x1[sampleSize][16], uint8_t kAll[16][1024] ){
  int k13, k10, k7, k4, ro;
  uint8_t k[sampleSize][16][1024];
  int possibilities[sampleSize];
  for(int i=0; i<sampleSize; i++){
    possibilities[i] = 0;
    for(ro=1; ro <= 0xFF; ro++){
      for(k13 = 0; k13 <= 0xFF; k13++){

        if(mul_table[3][ro] == (inv_s[x[i][12] ^ k13] ^ inv_s[x1[i][12] ^ k13]) ){
          for(k10 = 0; k10 <= 0xFF; k10++){

            if( mul_table[2][ro] == (inv_s[x[i][9]^ k10] ^ inv_s[x1[i][9] ^ k10]) )
            for(k7 = 0; k7<= 0xFF; k7++){

              if(ro == (inv_s[x[i][6] ^ k7] ^ inv_s[x1[i][6] ^ k7]) )
              for(k4 = 0; k4<= 0xFF; k4++){

                if(ro == (inv_s[x[i][3] ^ k4] ^ inv_s[x1[i][3 ] ^ k4]) ){
                  k[i][12][possibilities[i]]  = k13;
                  k[i][9][possibilities[i]]   = k10;
                  k[i][6][possibilities[i]]   = k7;
                  k[i][3][possibilities[i]]   = k4;
                  possibilities[i]++;
                }
              }
            }
          }
        }
      }
    }
    // printf("message %d has %d poss\n",i, possibilities[i] );
  }
  int poss = 0, check = 1;
  for( int j=0; j<possibilities[0]; j++){
    k13 = k[0][12][j];
    k10 = k[0][9][j];
    k7  = k[0][6][j];
    k4  = k[0][3][j];
    check = 1;
    for(int i=1; i<sampleSize && check == 1; i++){
      check = 0;
      for(int j1 = 0; j1<possibilities[i]; j1++){
        if( k13 == k[i][12][j1] && k10 == k[i][9][j1] && k7 == k[i][6][j1] && k4 == k[i][3][j1] ){
          check = 1;
          // printf("%02X %02X %02X %02X\n", k13, k10, k7, k4);
        }
      }
    }
    if(check == 1){
      kAll[12][poss] = k13;
      kAll[9][poss] = k10;
      kAll[6][poss] = k7;
      kAll[3][poss] = k4;
      poss++;
    }
  }
  // printf("poss = %d\n",poss );
  return poss;
}

int setEquation4(const uint8_t x[],  const uint8_t x1[], uint8_t k[16][1024]){
  int possibilities = 0;
  int k13, k10, k7, k4, ro;
  for(ro=1; ro <= 0xFF; ro++){
    for(k13 = 0; k13 <= 0xFF; k13++){

      if(mul_table[3][ro] == (inv_s[x[12] ^ k13] ^ inv_s[x1[12] ^ k13]) ){
        for(k10 = 0; k10 <= 0xFF; k10++){

          if( mul_table[2][ro] == (inv_s[x[9]^ k10] ^ inv_s[x1[9] ^ k10]) )
            for(k7 = 0; k7<= 0xFF; k7++){

              if(ro == (inv_s[x[6] ^ k7] ^ inv_s[x1[6] ^ k7]) )
                for(k4 = 0; k4<= 0xFF; k4++){

                  if(ro == (inv_s[x[3] ^ k4] ^ inv_s[x1[3 ] ^ k4]) ){
                    k[12][possibilities]  = k13;
                    k[9][possibilities]   = k10;
                    k[6][possibilities]   = k7;
                    k[3][possibilities]   = k4;
                    possibilities++;
              }
            }
          }
        }
      }
    }
  }
  return possibilities;
}


uint8_t fEquation1(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]){
  uint8_t result;

  result = inv_s[ mul_table[14][ inv_s[ x[0]  ^  k[0] ] ^ k9[0] ] ^
                  mul_table[11][ inv_s[ x[13] ^ k[13] ] ^ k9[1] ] ^
                  mul_table[13][ inv_s[ x[10] ^ k[10] ] ^ k9[2] ] ^
                  mul_table[9 ][ inv_s[  x[7] ^  k[7] ] ^ k9[3] ]
                ] ^
          inv_s[ mul_table[14][ inv_s[ x1[0]  ^  k[0] ] ^ k9[0] ] ^
                 mul_table[11][ inv_s[ x1[13] ^ k[13] ] ^ k9[1] ] ^
                 mul_table[13][ inv_s[ x1[10] ^ k[10] ] ^ k9[2] ] ^
                 mul_table[9 ][ inv_s[  x1[7] ^  k[7] ] ^ k9[3] ]
              ];
  return result;
}

uint8_t fEquation2(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]){
  uint8_t a, b;
  uint8_t result1;

  a = mul_table[9 ][ inv_s[ x[12] ^ k[12] ] ^ k9[12] ] ^
      mul_table[14][ inv_s[ x[9]  ^  k[9] ] ^ k9[13] ] ^
      mul_table[11][ inv_s[ x[6]  ^  k[6] ] ^ k9[14] ] ^
      mul_table[13][ inv_s[ x[3]  ^  k[3] ] ^ k9[15] ];

  b = mul_table[9 ][ inv_s[ x1[12] ^ k[12] ] ^  k9[12] ] ^
      mul_table[14][ inv_s[ x1[9]  ^  k[9] ] ^  k9[13] ] ^
      mul_table[11][ inv_s[ x1[6]  ^  k[6] ] ^  k9[14] ] ^
      mul_table[13][ inv_s[ x1[3]  ^  k[3] ] ^  k9[15] ];

  result1 = inv_s[ a] ^ inv_s[ b ] ;

  return result1;
}

uint8_t fEquation3(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]){
  uint8_t result;

  result = inv_s[ mul_table[13][ inv_s[ x[8]  ^  k[8] ] ^ k9[8]  ] ^
                  mul_table[9 ][ inv_s[ x[5]  ^  k[5] ] ^ k9[9]  ] ^
                  mul_table[14][ inv_s[ x[2]  ^  k[2] ] ^ k9[10] ] ^
                  mul_table[11][ inv_s[ x[15] ^ k[15] ] ^ k9[11] ]
                ] ^
          inv_s[ mul_table[13][ inv_s[ x1[8]  ^  k[8] ] ^ k9[8]  ] ^
                 mul_table[9 ][ inv_s[ x1[5]  ^  k[5] ] ^ k9[9]  ] ^
                 mul_table[14][ inv_s[ x1[2]  ^  k[2] ] ^ k9[10] ] ^
                 mul_table[11][ inv_s[ x1[15] ^ k[15] ] ^ k9[11] ]
               ] ;
  return result;
}

uint8_t fEquation4(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]){
  uint8_t result;


  result = inv_s[ mul_table[11][ inv_s[ x[4 ] ^ k[4 ] ] ^ k9[4] ] ^
                  mul_table[13][ inv_s[ x[1 ] ^ k[1 ] ] ^ k9[5] ] ^
                  mul_table[9 ][ inv_s[ x[14] ^ k[14] ] ^ k9[6] ] ^
                  mul_table[14][ inv_s[ x[11] ^ k[11] ] ^ k9[7] ]
                ] ^
          inv_s[ mul_table[11][ inv_s[ x1[4 ] ^ k[4 ] ] ^ k9[4] ] ^
                 mul_table[13][ inv_s[ x1[1]  ^ k[1 ] ] ^ k9[5] ] ^
                 mul_table[9 ][ inv_s[ x1[14] ^ k[14] ] ^ k9[6] ] ^
                 mul_table[14][ inv_s[ x1[11] ^ k[11] ] ^ k9[7] ]
              ];
  return result;
}

void getOriginalKey(uint8_t k[16], int currentRound){
  for(int i=currentRound; i>0; i--){
    getRoundK(k, i);
  }
}

void getRoundK(uint8_t k[16], const int r){
  k[12] ^=  k[8];
  k[13] ^=  k[9];
  k[14] ^=  k[10];
  k[15] ^=  k[11];

  k[8]  ^=  k[4];
  k[9]  ^=  k[5];
  k[10] ^=  k[6];
  k[11] ^=  k[7];

  k[4] ^= k[0];
  k[5] ^= k[1];
  k[6] ^= k[2];
  k[7] ^= k[3];

  k[0] ^=  s[ k[13]  ] ^ rcon[r];
  k[1] ^=  s[ k[14]  ];
  k[2] ^=  s[ k[15]  ];
  k[3] ^=  s[ k[12]  ];
}

void printState(const uint8_t state[16]){
  for(int i=0; i<16; i++){
      if(i%4 == 0)
        printf("\n");
    printf("%02X ", state[i]);
  }
  printf("\n");
}

uint8_t gf28_mulx ( uint8_t a ) {
  if( ( a & 0x80 ) == 0x80 ) {
    return 0x1B ^ ( a << 1 );
  }
  else {
    return ( a << 1 );
  }
}

uint8_t gf28_mul( uint8_t a, uint8_t b ) {
  uint8_t t = 0;
  for( int i = 7; i >= 0; i-- ) {
    t = gf28_mulx ( t );
    if( ( b >> i ) & 1 ) {
      t ^= a;
    }
  }

  return t;
}
