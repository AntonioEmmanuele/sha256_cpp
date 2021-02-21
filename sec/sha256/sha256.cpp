#include "sha256.hpp"
namespace sec{
  /*
      @helper function used in the messageSchedule to generate the first 16 elements of the new array
  */
  static inline uint32_t __from8to32(uint8_t*base_ptr){
      return ((uint32_t)base_ptr[0]<<24)|((uint32_t)base_ptr[1]<<16)|((uint32_t)base_ptr[2]<<8)|((uint32_t)base_ptr[3]);
  }
  /*
      @helper function used in the getDigit to generate the string
  */
  static inline void __from32tochar(char*buff,uint32_t v){
      sprintf(buff,"%08x",v);
  }
  /*
    @brief: Utility function used to append one  fill with zeroes and inserting the dimension
    @in: len of the string,dimension of the processed string, dimension in bit of the original string
    @out: processed string
  */
  static void append_fill_insdim(uint8_t*base_ptr,uint64_t original_value_len,uint64_t max_dim,uint64_t dimension){
    uint64_t index_btm,index=0;
    uint64_t btm_rev=7;
    base_ptr[original_value_len] = 0b10000000;
    /*Start from the last value and insert all 0*/
    for(  index = original_value_len+1 ; index<  max_dim ; index++)
      base_ptr[index]=0;
    /*Inserting the len of the original value,remember that original value is in bytes...*/
    for( index  = max_dim - 8 ; index< ( max_dim ); index++)
    {
        base_ptr[index]=((dimension)&(0xFF00000000000000>>(8*index_btm)))>>btm_rev*8;
        index_btm++;
        btm_rev--;
    }
  }
  /*
      @brief: append 1 bit to the array and then make it congruent with 448, append 0 bits making it integer divisible for 512,then add the dimension of the array.
      @in: bit len of the original string,original value
      @out: processed string, processed string len
  */
  void sha256::preprocess(uint8_t* &to_process,uint64_t& processed_len,uint8_t*original_value,uint64_t bit_dim)
  {
      /*
        Calculating the bit dimension
      */
      /*number of bits +1 */
      uint32_t to_resize=ceil(((float)(bit_dim)+1+64)/512);
      /* resizing, the result of the operation will be a multiple of 512*/
      processed_len=to_resize*512;
      /* Converting in byte*/
      processed_len=processed_len/8;
      to_process = new uint8_t [processed_len];
      memcpy(to_process,original_value,bit_dim/8);
      /* Append one, fill with 0(eventually),insert the dimension*/
      append_fill_insdim(to_process,bit_dim/8,processed_len,bit_dim);
  }
/*
    @brief: Resets the digest to its original value (hash_values)
*/
  void sha256::resetDigest(void)
  {
      init_digest();
  }
  /*
      @brief: obtain the digest
      @out : pointer to the copyed string
      @ret : lenght of the string
      @add info: This function doesn't use dinamic allocation because you actually know the number of elements in the digest array(8)
  */
  ssize_t  sha256::getDigest(uint32_t* to_cpy)
  {
    if(to_cpy==NULL)
      return -1;
    memcpy(to_cpy,this->digest,sha256_digestuint32_dim*sizeof(uint32_t));
    return sha256_digestuint32_dim;
  }
  /*
      @brief: obtain the digest as a string (array of char )
      @out : pointer to the copyed string
      @ret : lenght of the string
      @add info: Same as previously, return 32
  */
  ssize_t sha256::getDigest( char*to_cpy)
  {
    uint8_t index=0;
    if(to_cpy==NULL){
      return -1;
    }
    for(index=0;index<sha256_digestuint32_dim;index++)
    {
      __from32tochar(&to_cpy[index*8],this->digest[index]);
    }
    return sha256_digestchar_dim;
  }
  /*
    @brief: copy constructor
  */

  sha256::sha256(const sha256& to_cpy)
  {
    memcpy(this->digest,to_cpy.digest,sizeof(uint32_t)*sha256_digestuint32_dim);
  }
  /* Destructor*/
  sha256::~sha256(void)
  {

  }
  /*
    @brief:Inits the digest value with the hash values(first 32 bits of the fractional part of the square root of the first 8
            prime numbers)
    @post:digit value initialized
  */
  void sha256::init_digest(void)
  {
    memcpy(digest,sha256_hash_values,32);
  }
  /*
      @brief: in message schedule step the filled value,after being divided in chunks of 512 bits (512/8 elements of the filled array)
              and then a 64 32bit word is created.
              After converting a chunk the values of the new array are created with this formula:
              for i from 16 to 63
                s0 := rightRotate(new_32_64bitword_ptr[i-15],7)^rightRotate(new_32_64bitword_ptr[i-15] ,18) ^( new_32_64bitword_ptr[i-15] >> 3)
                s1 := rightRotate(new_32_64bitword_ptr[i-2],17)^rightRotate(new_32_64bitword_ptr[i-2] ,19) ^( new_32_64bitword_ptr[i-2] >> 10)
                new_32_64bitword_ptr[i] := new_32_64bitword_ptr[i-16] + s0 + new_32_64bitword_ptr[i-7] + s1
    @in: base_ptr obtained from fill function,pass the base for every 16 values
    @out: new chunk (64 bits ) elaborated.
  */
  void sha256::messageSchedule(uint8_t*base_ptr,uint32_t *new_32_64bitword_ptr){
    uint32_t s0,s1=0;
    uint32_t index=0;
    /* Creating the new word..*/
    for(index=0;index<16;index++)
      new_32_64bitword_ptr[index]=__from8to32(&base_ptr[index*4]);
    for (index= 16;index <64;index++){
      s0 = rightRotate(new_32_64bitword_ptr[index-15],7)^rightRotate(new_32_64bitword_ptr[index-15] ,18) ^(new_32_64bitword_ptr[index-15] >> 3);
      s1 = rightRotate(new_32_64bitword_ptr[index-2],17)^(rightRotate(new_32_64bitword_ptr[index-2] ,19) )^(new_32_64bitword_ptr[index-2] >> 10);
      new_32_64bitword_ptr[index] = s1 + new_32_64bitword_ptr[index-7] + s0 + new_32_64bitword_ptr[index-16];
    }
  }
/*
  @brief: do the last part of the algorithm (compression)
  @in : new 64*32bit word
  @out: chunk hash calculated
*/
  void sha256::compress(uint32_t* _64_32bitword,uint32_t*chunk_hash){
    uint32_t index,s0,s1,maj,t1,t2,ch=0;
    for (index=0;index<64;index++){
      /*Calculating stuff..*/
       s0 = (rightRotate(chunk_hash[0],2)) ^ (rightRotate(chunk_hash[0],13)) ^(rightRotate(chunk_hash[0],22));
       ch = (chunk_hash[4] &chunk_hash[5]) ^ (~(chunk_hash[4]) & (chunk_hash[6]));
       s1 = (rightRotate(chunk_hash[4],6)) ^ (rightRotate(chunk_hash[4],11)) ^ (rightRotate(chunk_hash[4],25));
       maj= (chunk_hash[0]&chunk_hash[1]) ^ (chunk_hash[0]&chunk_hash[2]) ^ (chunk_hash[1]&chunk_hash[2]);
       t2 = s0 + maj;
       t1= chunk_hash[7] + s1 + ch + sha256_round_constants[index] + _64_32bitword[index];
       /*Updating 64 hashes*/
       chunk_hash[7]=chunk_hash[6];
       chunk_hash[6]=chunk_hash[5];
       chunk_hash[5]=chunk_hash[4];
       chunk_hash[4]=chunk_hash[3]+t1;
       chunk_hash[3]=chunk_hash[2];
       chunk_hash[3]=chunk_hash[2];
       chunk_hash[2]=chunk_hash[1];
       chunk_hash[1]=chunk_hash[0];
       chunk_hash[0]=t1+t2;
     }
  }
  /*
    @brief: Updates the digest with a new value*
  */
  void sha256::updateDigest(uint32_t*chunk_hash){
    uint8_t index=0;
    for(index=0;index<8;index++)
      digest[index]+=chunk_hash[index];
  }
  /*
    @brief: Function that given a processed string updates digest
    @pre: The string in input should be previously processed
  */
  void sha256::doCalc(uint8_t*processed_string,uint64_t processed_string_len){

    uint64_t index=0;
    uint32_t chunks[64];
    uint32_t chunk_hash[8];
    memset(chunks,0xFF,sizeof(uint32_t)*64);
    /*
     For every chunk of 512 bits (64 bytes or 64 elements of the filled array )
       1-initialize hash for the values for the chunk(with prev digest value)
       2-generate the 32 *64 bits word
       3-update hash value for the chunk
       4-update digest value
    */
    for(index=0;index<processed_string_len;index=index+64)
    {
      /*Must initialize it with the current value of digest*/
        memcpy(chunk_hash,digest,sizeof(uint32_t)*8);
        messageSchedule(&processed_string[index],chunks);
        compress(chunks,chunk_hash);
        updateDigest(chunk_hash);
    }
  }
  /*
    @brief: constructor for static mode.
    @pre:Block uninitialized
  */
  sha256::sha256(void){
    init_digest();
  }
  /*
      @brief: Calculates the hash.
      @input: string to be calculated, len of string in bytes.
  */
  void sha256::update(uint8_t *to_calc,uint64_t to_calc_len)
  {
    uint8_t *processed_string=nullptr;
    uint64_t processed_string_len=0;
    preprocess(processed_string,processed_string_len,to_calc,to_calc_len*8);
    doCalc(processed_string,processed_string_len);
    delete[]processed_string;
    processed_string=nullptr;
  }
};
