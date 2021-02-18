#include "sha256.hpp"
#include <cstring>
#include <iostream>
using namespace std;
int main(void){
  char to_pass[]="helloworldhelloworldhelloworldhelloworldhelloworld";
  ssize_t ret=0;
  const uint8_t d_len1=sec::sha256_digestuint32_dim;
  const uint8_t d_len2=sec::sha256_digestchar_dim;
  uint32_t digest_value[d_len1];
  char digest_value_char[d_len2];
  sec::sha256 Key((uint8_t*)to_pass,(strlen(to_pass)));
  Key.calcDigest();
  ret=Key.getDigest(digest_value);
  ret=Key.getDigest((char*)digest_value_char);
  cout<<ret<< endl;
  cout << "Value in uint32 : "<<endl;
  for(uint8_t i=0 ; i< d_len1;i++)
    printf("%x",digest_value[i]);
  cout<<endl;
  printf("String value %s,strlen %ld \n",digest_value_char,strlen(digest_value_char));
  return 0;
}
