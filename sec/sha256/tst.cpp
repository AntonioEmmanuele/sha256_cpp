#include "sha256.hpp"
#include <cstring>
#include <iostream>
using namespace std;
int main(void){
  char to_pass[]= "hello world";
  ssize_t ret=0;
  const uint8_t d_len1=sec::sha256_digestuint32_dim;
  const uint8_t d_len2=sec::sha256_digestchar_dim;
  uint32_t digest_value[d_len1];
  char digest_value_char[d_len2];
  sec::sha256 Key((uint8_t*)to_pass,(strlen(to_pass)));
  Key.calcDigest();
  ret=Key.getDigest(digest_value);
  ret=Key.getDigest(digest_value_char);
  cout<<ret<< endl;
  cout << "Value in uint32 : "<<endl;
  for(uint8_t i=0 ; i< d_len1;i++)
    printf("%x",digest_value[i]);
  cout<<endl;
  cout<<"String value "<<endl;
  for(uint8_t i=0;i<d_len2;i++)
    printf("Idx %u  Character %c Hex: %x \n ",i,digest_value_char[i],digest_value_char[i]);
  cout<<endl;
  return 0;
}
