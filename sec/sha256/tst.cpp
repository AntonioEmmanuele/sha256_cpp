#include "sha256.hpp"
#include <cstring>
#include <iostream>
#include <ctime>
#include <array>
using namespace std;
int main(void)
{
  clock_t beginD,endD,beginS,endS;
  double timeD,timeS;
  uint8_t to_pass2[4098*2];
  for(uint64_t i=0;i<4098*2;i++)
    to_pass2[i]=0xAA;
  string digest;
  /***************************************
  Dynamic example
  ************************************/
  sec::sha256 Key;
  beginD=clock();
  Key.update((uint8_t*)to_pass2,4098*2);
  endD=clock();
  Key.getDigest(digest);
  cout <<endl<<digest <<endl;
  /*********************************
  Static example
  **********************************/
  Key.resetDigest();
  char hi[]="helloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworld";
  cout<<"Dim"<<strlen(hi)<<endl;
  Key.updateS((uint8_t*)hi,strlen(hi));
  Key.getDigest(digest);
  cout<<"New digest "<< digest<<endl;
/*******************************
  Dynamic
  *************************/
  Key.resetDigest();
  cout<<"Dim"<<strlen(hi)<<endl;
  Key.update((uint8_t*)hi,strlen(hi));
  Key.getDigest(digest);
  cout<<"New digest pt2 "<< digest<<endl;
/********************************
  static
  ****************************/
  cout<< "Last static test "<< endl;
  Key.resetDigest();
  beginS=clock();
  Key.updateS(to_pass2,4098*2);
  endS=clock();
  Key.getDigest(digest);
  cout<<"New digest pt2 "<< digest<<endl;

  /*******************
    Time comparison (not so professional I know but quick)
    ***************/
  timeD=(double)(endD-beginD)/CLOCKS_PER_SEC;
  timeS=(double)(endS-beginS)/CLOCKS_PER_SEC;
  cout<<"Time static"<<timeS<<"Time dyn"<<timeD<< endl;
  /***********************************
  Test with arrays...
  **********************************/
  Key.resetDigest();
  array<uint8_t , 2048> a;
  a.fill(0xFF);
  Key.updateS(a.begin(),a.size());
  Key.getDigest(digest);
  cout<<"New digest "<<digest<<endl;
  /***********
  INFO TO READ :
    Creating an interface for std::array would be useless because I actually don't know the dimension.
  ************/

  return 0;
}
