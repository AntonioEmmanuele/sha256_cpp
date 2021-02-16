#include "sha256.hpp"
#include <cstring>
int main(void){
  char to_pass[]= "Hello my name is Antonio Emmanuele and I'm almost a Computer Engineer";
  sec::sha256 Key((uint8_t*)to_pass,strlen(to_pass)+1);

  return 0;
}
