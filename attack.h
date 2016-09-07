#ifndef __ATTACK_H
#define __ATTACK_H

#include  <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include  <signal.h>
#include  <unistd.h>
#include   <fcntl.h>

#include <openssl/aes.h>

uint8_t mul_table[256][256];
uint8_t gf28_mul( uint8_t a, uint8_t b );

int setEquation1(const uint8_t x[],  const uint8_t x1[], uint8_t k[16][1024]);
int setEquation2(const uint8_t x[],  const uint8_t x1[], uint8_t k[16][1024]);
int setEquation3(const uint8_t x[],  const uint8_t x1[], uint8_t k[16][1024]);
int setEquation4(const uint8_t x[],  const uint8_t x1[], uint8_t k[16][1024]);

int setsEquation1(const uint8_t x[][16], const uint8_t x1[][16], uint8_t k[16][1024]);
int setsEquation2(const uint8_t x[][16], const uint8_t x1[][16], uint8_t k[16][1024]);
int setsEquation3(const uint8_t x[][16], const uint8_t x1[][16], uint8_t k[16][1024]);
int setsEquation4(const uint8_t x[][16], const uint8_t x1[][16], uint8_t k[16][1024]);

uint8_t fEquation1(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]);
uint8_t fEquation2(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]);
uint8_t fEquation3(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]);
uint8_t fEquation4(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]);

void printState(const uint8_t state[16]);
void computeMultiplyTable();
void getOriginalKey(uint8_t k[16], int currentRound);
void getRoundK(uint8_t k[16], const int r);
void interact(uint8_t c[16],
              const int fault,          /* fault or not */
              const int r,              /*round */
              const int f ,             /*function */
              const int p,              /*before or after */
              const int i,              /*i-th row */
              const int j,              /*j-th column  */
              const uint8_t m[16]);     /*message block */

#endif
