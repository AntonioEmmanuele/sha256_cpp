#ifndef SHA_256_HPP
#define SHA_256_HPP

/* Debug flg*/
#define DBG 1
#if DBG
#include <iostream>
using namespace std;
#endif

/* The namespace of security things..*/
namespace sec{
  /* Class sha256*/
  class sha256{
  private:
    /* Original string value*/
    uint8_t *original_value;
    uint64_t original_value_len;
    uint64_t filled_len;
    uint8_t *filled_value;
    /*Some utility functions*/
    void init_originals(const uint8_t *const , const uint64_t);
    void append_one(uint8_t*,uint64_t&);
    uint64_t obtain_filled_len(void);
    void fill(void);
  public:
    /* Constructor*/
     sha256(const uint8_t *const , const uint64_t );
     sha256(const sha256&);
     uint64_t getOriginal(uint8_t*);
     uint64_t getOriginalLen(void);
     /*Destructor*/
     ~sha256();
  };

};


#endif
