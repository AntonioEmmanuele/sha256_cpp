#include "sha256.hpp"
#include <cstring>
#include <iostream>

using namespace std;
int main(void)
{
  char to_pass[]="helloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldmachebelcastellomarcondirondirondellohelloworldhelloabcd";
  char to_pass2[]="helloworld";
  char to_pass4[]="machebelcastellomarcondirondirondellohelloworldhelloabcdmachebelcastellomarcondirondirondelloabcdefghilmnopqrstuvz";
  char to_pass5[]="machebelcastellomarcondirondirondellohelloworldhelloabcdmachebelcastellomarcondirondirondelloabcdefghilmnopqrstuvzmachebelcastellomarcondirondirondellohelloworldhelloabcdefghilmnopqrst";
  uint64_t len=4098;
  uint8_t to_crash[len];
  memset(to_crash,0xA5,len);
  ssize_t ret=0;
  const uint8_t d_len2=sec::sha256_digestchar_dim;
  char digest_value_char[d_len2];
  /***************************************
  Dynamic example
  ************************************/
  sec::sha256 Key;
  Key.update((uint8_t*)to_crash,len);
  ret=Key.getDigest((char*)digest_value_char);
  cout << "Value in returned   "<<ret<<endl;
  printf("String value %s,strlen %ld \n",digest_value_char,strlen(digest_value_char));
  cout<<"Another test .."<<endl;
  Key.resetDigest();
  Key.update((uint8_t*)to_pass2,strlen(to_pass2));
  ret=Key.getDigest((char*)digest_value_char);
  cout << "Value in returned   "<<ret<<endl;
  printf("crash hash value %s,strlen %ld \n",digest_value_char,strlen(digest_value_char));

  return 0;
}
