#include "sha256.hpp"
#include <cstring>
#include <iostream>

using namespace std;
int main(void){
  char to_pass[]="helloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworld";
  char to_pass2[]="helloworldhelloworldhelloworldhelloworldhelloworldhelloworld";
  char to_pass3[]="machebelcastellomarcondirondirondellomachebelcastellomarcondirondirondellomachebelcastelloabcdeefgh";
  cout<<strlen(to_pass3)<<endl;
  ssize_t ret=0;
  const uint8_t d_len1=sec::sha256_digestuint32_dim;
  const uint8_t d_len2=sec::sha256_digestchar_dim;
  uint32_t digest_value[d_len1];
  char digest_value_char[d_len2];

  #if !SHA256_STATIC
  /***************************************
  Dynamic example
  ************************************/
  sec::sha256 Key((uint8_t*)to_pass3,(strlen(to_pass3)));
  Key.calcDigest();
  ret=Key.getDigest((char*)digest_value_char);
  cout << "Value in returned   "<<ret<<endl;
  printf("String value %s,strlen %ld \n",digest_value_char,strlen(digest_value_char));

  #elif SHA256_STATIC
  /******************************
  Static example
  *******************************/
  sec::sha256 Key;
  Key.update((uint8_t*)to_pass3,(uint64_t)strlen(to_pass3));
  ret=Key.getDigest((char*)digest_value_char);
  cout << "Value in returned   "<<ret<<endl;
  printf("String value %s,strlen %ld \n",digest_value_char,strlen(digest_value_char));
  #endif
  return 0;
}
