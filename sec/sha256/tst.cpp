#include "sha256.hpp"
#include <cstring>
#include <iostream>

using namespace std;
int main(void)
{
  char to_pass[]="helloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldmachebelcastellomarcondirondirondellohelloworldhelloabcd";
  char to_pass2[]="helloworld";
  char to_pass3[]="machebelcastellomarcondirondirondellohelloworldhelloabcd";
  char to_pass4[]="machebelcastellomarcondirondirondellohelloworldhelloabcdmachebelcastellomarcondirondirondellohelloworldhelloabcd";
  ssize_t ret=0;
  cout<<strlen(to_pass3)<<endl;
  const uint8_t d_len1=sec::sha256_digestuint32_dim;
  const uint8_t d_len2=sec::sha256_digestchar_dim;
  uint32_t digest_value[d_len1];
  char digest_value_char[d_len2];
  /***************************************
  Dynamic example
  ************************************/
  sec::sha256 Key;
  Key.update((uint8_t*)to_pass2,(strlen(to_pass2)));
  ret=Key.getDigest((char*)digest_value_char);
  cout << "Value in returned   "<<ret<<endl;
  printf("String value %s,strlen %ld \n",digest_value_char,strlen(digest_value_char));
  return 0;
}
