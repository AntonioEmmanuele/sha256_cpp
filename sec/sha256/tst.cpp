#include "sha256.hpp"
#include <cstring>
int main(void){
  char to_pass[]= "hello world";
  sec::sha256 Key((uint8_t*)to_pass,(strlen(to_pass)));
  printf("%x \n",rightRotate((uint8_t)0x02,6));
  Key.calcDigest();
  return 0;
}
