#include "sha256.hpp"

namespace sec{
  /*
    @brief: Default Constructor
    @input: string to copy, lenght of the string
  */
  sha256::sha256(const uint8_t* const  string,const uint64_t len)
  {
    init_originals(string,len);
    fill();
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
  */
  uint64_t sha256::getOriginal(uint8_t* to_cpy)
  {
    if(to_cpy!=NULL)
      delete[]to_cpy;
    to_cpy=new uint8_t[getOriginalLen()];
    memcpy(to_cpy,this->original_value,getOriginalLen());
    return getOriginalLen();
  }
  /*
    @brief: copy constructor
  */

  sha256::sha256(const sha256& to_cpy)
  {
    uint8_t *string=0;
    uint64_t len=getOriginal(string);
    sha256(string,len);
  }

  sha256::~sha256()
  {
    delete[]original_value;
    //delete[]filled_value;
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
              In sha256 we need to work with a string of byte composed by a number of byte that is integer multiple
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
        printf( "%x ,",ptr[i]);
      }
      printf("\n \n");
    #endif
  }
  /*
      @brief: Create the filled_value appending one, filling the string with 0
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
      /*Inserting the len of the original value*/
      for( index  = filled_len - 8 ; index< ( filled_len ); index++)
      {
          filled_value[index]=((original_value_len)&(0xFF00000000000000>>(8*index_btm)))>>btm_rev*8;
          index_btm++;
          btm_rev--;
      }
      #if SHA256_DBG
      printf("[SHA256 Step1 Filled ]\n");
      for(uint8_t i=0;i<filled_len;i++)
      {
        printf( "%x ,",filled_value[i]);
        if(i%8==0 && i!=0)
          printf ("\n");
      }
      printf("\n");
    #endif
  }

};
