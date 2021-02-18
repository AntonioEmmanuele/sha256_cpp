#include "sha256.hpp"
namespace sec{
  /*
      @helper function used in the messageSchedule to generate the first 16 elements of the new array
  */
  static inline uint32_t __from8to32(uint8_t*base_ptr){
      return ((uint32_t)base_ptr[0]<<24)|((uint32_t)base_ptr[1]<<16)|((uint32_t)base_ptr[2]<<8)|((uint32_t)base_ptr[3]);
  }
  /*
      @helper function used getDigest(char*)
  */
  static inline void __from32to8(uint8_t*base_ptr,uint32_t val){
      base_ptr[0]=    ( ( (val) >> 24 ) & (0xFF) );
      base_ptr[1]=    ( ( (val) & (0x00FF0000) ) >> 16 );
      base_ptr[2]=    ( ( (val) & (0x0000FF00) ) >> 8 );
      base_ptr[3]=    ( ( (val) & (0x000000FF) )  );
      #if SHA256_DBG
        printf("Base %x \n ",base_ptr[0]);
      #endif
  }
  /*
    @brief: Default Constructor
    @input: string to copy, lenght of the string
  */
  sha256::sha256(const uint8_t* const  string,const uint64_t len)
  {
    init_originals(string,len);
    fill();
    init_digest();
  }
  /*
      @brief: return the lenght of the original string
      @ret: original_value_len
  */
  uint64_t sha256::getOriginalLen(void)
  {
    return original_value_len;
  }
  /*
      @brief:obtain the original string
      @out : pointer to the copyed string
      @ret : lenght of the string
      @add info: after using you should delete the string
  */
  uint64_t sha256::getOriginal(uint8_t** to_cpy)
  {
    if (*to_cpy!=0)
      delete[]*to_cpy;
    *to_cpy=new uint8_t[original_value_len];
    memcpy(*to_cpy,this->original_value,getOriginalLen());
    return getOriginalLen();
  }
  /*
      @brief: return the lenght of the filled string
      @ret: original_value_len
  */
  uint64_t sha256::getFilledLen(void)
  {
    return filled_len;
  }
  /*
      @brief: obtain the filled  string
      @out : pointer to the copyed string
      @ret : lenght of the string
      @add info: after using you should delete the string
  */
  uint64_t sha256::getFilled(uint8_t** to_cpy)
  {
    if (*to_cpy!=0)
      delete[]*to_cpy;
    *to_cpy=new uint8_t[filled_len];
    memcpy(*to_cpy,this->filled_value,getFilledLen());
    return getFilledLen();
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
  ssize_t sha256::getDigest( char*to_cpy){
    if(to_cpy==NULL)
      return -1;
    /*Number of bytes in the string, one char is one byte (4 byte(32 bits)*8)*/
    uint8_t* ptr=(uint8_t*)to_cpy;
    uint8_t index=0;
    for(index=0;index<sha256_digestchar_dim/4;index++)
      __from32to8(&ptr[index*4],this->digest[index]);
    return sha256_digestchar_dim;
  }
  /*
    @brief: copy constructor
  */

  sha256::sha256(const sha256& to_cpy)
  {
    uint8_t *string=0;
    uint64_t len=getOriginal(&string);
    sha256(string,len);
    /* String is now useless*/
    delete[]string;
  }

  sha256::~sha256()
  {
    delete[]original_value;
    delete[]filled_value;
  }
  /*
    @brief:Inits original string and original len
    @in : string ptr, len ptr
    @pre: those values shouldn't have been initialized yet
    @post:original values initialized
  */
  void sha256::init_originals(const uint8_t *const string , const uint64_t len)
  {
    if(string==NULL||len==0)
    {
      perror("Invalid input \n");
      exit(1);
    }
    original_value_len=len;
    original_value=new uint8_t[original_value_len];
    memcpy(original_value,string,len);
    #if SHA256_DBG
    cout<<"[SHA256 Len passed ] "<<len<< endl;
    cout<<"[SHA256 Len of string] "<<strlen((char*)original_value)+1<<endl;
    for(uint64_t i=0;i<len;i++)
      cout<< original_value[i];
    cout<<endl;
    #endif
  }
  /*
      @brief: This function returns the number of elements in the filled array.
              In sha256 we need to work with a string of byte composed by a number of bytes that is integer multiple
              of the string.
              So we need to append to the original string the value of one and then add  zeroes
              (in a big endian way) to obtain an integer multiple.
              the len of the string in 64 bits.
              To obtain a general case we have:
                division=len/512.
                multiply_value=ceil of division-to_mul
                number of byte to add=512+len
      @in : len -> This is the number of bits of the string(not bytes)
      @ret: number of bytes of the filled string.
  */
  uint64_t sha256::obtain_filled_len(uint64_t len)
  {
    double div=(double)len/512;
    double exc=ceil(div);
    double to_mul=exc-div;
    uint64_t to_add=512*to_mul;
    return (to_add+len)/8;
  }
  /*
    @brief: Append one to the original string
    @output: original string appended to one (big endian) and output string len
  */
  void sha256::append_one(uint8_t**output_string,uint64_t& output_len)
  {
      uint8_t *ptr;
      output_len=original_value_len+1;
      *output_string=new uint8_t[output_len];
      ptr=*output_string;
      memcpy(*output_string,original_value,original_value_len);
      /*Original len is output-1*/
      ptr[original_value_len]=0b10000000;
      #if SHA256_DBG
      cout <<" [SHA256 Step1 Appended ]\n"<< endl;
      for(uint8_t i=0;i<output_len;i++)
      {
        printf( "%x ",ptr[i]);
      }
      printf("\n \n");
    #endif
  }
  /*
      @brief: Create the filled_value appending one and then filling the string with 0 (in case len(string appended+ 64 bits)%512!=0 )
      @pre: filled_value uninitialized
      @post:filled value initialized
  */
  void sha256::fill(void)
  {
      uint8_t* appended_one;
      uint64_t appended_one_len=0;
      uint64_t index=0;
      uint8_t index_btm=0;
      uint8_t btm_rev=7;
      append_one(&appended_one,appended_one_len);
      /*
        Should pass the number of bits+ bitlen of the original string (64 bits value)
      */
      filled_len=obtain_filled_len((appended_one_len*8+64));
      filled_value=new uint8_t [filled_len];
      memcpy(filled_value,appended_one,appended_one_len);
      delete[]appended_one;
      /*Start from the last value and insert all 0*/
      for(  index = appended_one_len ; index<  filled_len ; index++)
        filled_value[index]=0;
      /*Inserting the len of the original value,remember that original value is in bytes...*/
      for( index  = filled_len - 8 ; index< ( filled_len ); index++)
      {
          filled_value[index]=((original_value_len*8)&(0xFF00000000000000>>(8*index_btm)))>>btm_rev*8;
          index_btm++;
          btm_rev--;
      }
      #if SHA256_DBG
      printf("[SHA256 Step1 Filled ]\n");
      for(uint8_t i=0;i<filled_len;i++)
      {
        printf( "%x ",filled_value[i]);
        if((i+1)%8==0 && i!=0)
          printf ("\n");
      }
      printf("\n");
    #endif
  }
  /*
    @brief:Inits the digest value with the hash values(first 32 bits of the fractional part of the square root of the first 8
            prime numbers)
    @post:digit value initialized
  */
  void sha256::init_digest(void)
  {
    memcpy(digest,sha256_hash_values,32);
    #if SHA256_DBG
      for(uint8_t i=0;i<8;i++)
        printf("[SHA256 Digest init ] %u %x \n",i,digest[i]);
    #endif
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
    #if SHA256_DBG
      printf("[SHA256 MESSAGE_SCHEDULE NEW WORDS ] \n");
      for(index=0;index<64;index++){
        printf(" %x ",new_32_64bitword_ptr[index]);
        if((index+1)%2==0&&index !=0)
          printf(" \n");
      }
      printf("\n");
    #endif
  }

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
  void sha256::updateDigest(uint32_t*chunk_hash){
    uint8_t index=0;
    for(index=0;index<8;index++)
      digest[index]+=chunk_hash[index];
  }
  /*
      @brief: All in one function that calculates the digest value.
      @pre : Filled initialized
      @post : digest obtained
  */
  void sha256::calcDigest(void){
    uint32_t chunks[64];
    uint32_t chunk_hash[8];
    uint64_t index=0;
    memset(chunks,0x00,sizeof(uint32_t)*64);
    /* For every chunk of 512 bits (64 bytes or 64 elements of the filled array )
       1-initialize hash for the values for the chunk
       2-generate the 32 *64 bits word
       3-update hash value for the chunk
       4-update digest value
    */
    for(index=0;index<filled_len;index=index+64)
    {
      memcpy(chunk_hash,sha256_hash_values,sizeof(uint32_t)*8);
      messageSchedule(filled_value,chunks);
      compress(chunks,chunk_hash);
      updateDigest(chunk_hash);
    }
    #if SHA256_DBG
      for(unsigned int i=0;i<8;i++)
        printf("%x",digest[i]);
      printf("\n");
    #endif
  }
  /*
      @brief:getFilled and getOriginal allocates an array, this function deletes the allocated array
      @pre: The array should be previously allocated
      @in/out: the array prev. allocated (used with getFilled or getOriginal)
  */
  void sha256::delArrayUtil(uint8_t**array){
    delete[]*array;
    *array=NULL;
  }
};
