#include "sha256.hpp"

namespace sec{
  /*
    @brief: Default Constructor
    @input: string to copy, lenght of the string
  */
  sha256::sha256(const uint8_t* const  string,const uint64_t len)
  {
    init_originals(string,len);
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
    #if DBG
    cout<<"[SHA256_DBG] Len passed "<<len<< endl;
    cout<<"[SHA256_DBG]Len of string "<<strlen((char*)original_value)+1<<endl;
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
      @ret: number of byte of the filled string.
  */
  uint64_t sha256::obtain_filled_len(uint64_t len)
  {
    double div=len/512;
    double exc=ceil(div);
    double to_mul=exc-div;
    uint64_t to_add=512*to_mul;
    return len+original_len;
  }
  /*
    @brief: Append one to the original string
    @output: original string appended to one (big endian) and output string len
  */
  void sha256::append_one(uint8_t*output_string,uint8_t& output_len)
  {
      output_len=original_len+1;
      if(output_string!=NULL)
        delete[]output_string;
      output_string=new uint8_t[output_len];
      memcpy(output_string,original_value,original_len);
      /*Original len is output-1*/
      output_string[original_len]=0b10000000;
  }
  void sha256::fill(void)
  {
      uint8_t*appended_one=NULL;
      uint8_t appended_one_len=0;
      append_one(appended_one,appended_one_len);
      filled_len=obtain_filled_len(appended_one_len);
      filled_value=new uint8_t [filled_len];
      
  }
};
