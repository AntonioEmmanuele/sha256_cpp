#ifndef SHA_256_HPP
#define SHA_256_HPP
#include "math.h"
#include <cstring>
#include <iostream>
#include <array>
#include <algorithm>
/* Debug flg*/
#define SHA256_DBG 0
/*Static flg, in this mode the algoritm will work with a static mode never using dynamic alloc*/
#define SHA256_STATIC 0
#if SHA256_DBG
using namespace std;
#endif
/*
  Algorithm:
  1- Obtain the string
  2- Append a one (0b10000000)
  3- Make this number divible with 448 bits
  4- For every chunk of 512 bits:
      Initialize hash_values for the chunk, basically a copy of the sha256_hash_values sha256_constant
      create 64 elements array of 32 bits(The first 16 elements are the 512bits chunks and the others are created from the first 16)-> messageSchedule
      Do compression -> compression updates the hash_values of the specific chunk(of 512 bits)
      Update the global hash_values of the object
  In pseudo code
    obtain string                                                           input
                                                                                |
    append one                                                              input.append(0b10000000)
                                                                                |
    make the string                                                             |
    divisible with 512                                                      input filled with 0 in case len in bits input.append(0b10000000) + 64 bits (the len of the original message in bits)
                                                                                |
    for each 512 bits chunk:                                                chunk of 512 bits <-----------------------------------------------------|
      init a temporary hash_values for the chunk                                |                                                                   |
                                                                                |                                                                   |
      messageSchedule                                                       Generating a 32*64 word                                                 | While number of 512 bits chunks >0
                                                                                |                                                                   |
      compress                                                              generated hash value for the chunk                                      |
                                                                                |                                                                   |
      update digest                                                         digest udate(chunk digest+ global digest) -------------------------------
*/

#define rightRotate(to_rot,bits) (((to_rot) >> (bits)) | ((to_rot) << ((sizeof(to_rot))*8-(bits))))

#define leftRotate(to_rot,bits) (((to_rot) << (bits)) | ((to_rot) >> ((sizeof(to_rot))*8-(bits))))

/* The namespace of security things..*/
namespace sec{

  /****************************/
  /*USED TO ALLOCATE THE RESULT IN AN ARRAY OF CHAR OR AN ARRAY OF UINT32*/
  const uint8_t  sha256_digestuint32_dim = 8;
  /* 8bytes for uint32_t*8 + string term*/
  const uint8_t sha256_digestchar_dim = 65;
  /***************************/
  /*Hash values are the first 32 bits of the fractional part of the square roots of  the first 8 prime numbers*/
  const uint32_t sha256_hash_values[8]=
  {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
  };
  /*Hash values are the first 32 bits of the fractional part of the cube roots of  the first 64 prime numbers*/
  const uint32_t sha256_round_constants[64]=
  {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };

  /* Class sha256*/
  class sha256{
    /*********************************************************************************************************************
    This implementation can use dynamic allocation or not.
    SHA256_STATIC for use static.

    Dynamic functions:
      1-init_originals
      2-preprocess
      3-getOriginal
      4-getOriginalLen
      5-delArrayUtil
      6-calcDigest
      7-constructor with args

    Common Functions:
      1-Destructor
      2,3-getDigest
      4-messageSchedule
      5-compress
      6-updateDigest
      7-doCalc
      8-resetDigest
    Static Functions:
      1-update
      2- costructor without args

      API Dynamic : Function written in lower camel case.
            Pay attention to get functions.
            In getOriginal the function uses dynamic allocation.
            You can delete this values using delArrayUtil.
            For getDigest static allocation is used.
            To allocate correctly these arrays use the constants sha256_digestchar_dim and sha256_digestuint32_dim
            i.e.:
              uint32_t digest_array[sec::sha256_digestuint32_dim]
              char digest [sec::sha256_digestchar_dim]
    **********************************************************************************************************************/
  private:
#if !SHA256_STATIC
    /* Original string value*/
    uint8_t *original_value;
    /*original string value len*/
    uint64_t original_value_len;
#endif
    /*digest*/
    uint32_t digest[8];
    /*Some utility functions*/
#if !SHA256_STATIC
    void init_originals(const uint8_t *const , const uint64_t);
    void preprocess(uint8_t* &,uint64_t&);
#elif SHA256_STATIC
    void initBlock512(void);
#endif
    void init_digest(void);
    uint64_t obtain_filled_len(uint64_t);
    void messageSchedule(uint8_t *,uint32_t*);
    void compress(uint32_t*,uint32_t*);
    void doCalc(uint8_t*,uint64_t );
    void updateDigest(uint32_t*);

  public:
    /* Copy Constructor*/
    sha256( const sha256&);
#if !SHA256_STATIC
    sha256(const uint8_t *const , const uint64_t );
    uint64_t getOriginal(uint8_t**);
    uint64_t getOriginalLen(void);
    void delArrayUtil(uint8_t**);
    void calcDigest(void);
#elif SHA256_STATIC
      sha256(void);
      void update(uint8_t *,uint64_t );
#endif
    ssize_t getDigest(uint32_t*);
    ssize_t getDigest( char*);
    void resetDigest(void);
    /*Destructor*/
    ~sha256();
  };
};
#endif
