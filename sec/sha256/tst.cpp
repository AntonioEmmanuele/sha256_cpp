/****************************************************************************************
* This file is part of sha256_cpp Project. *
* *
* Copyright  © 2021 By Antonio Emmanuele. All rights reserved. *
* @mail: antony.35.ae@gmail.com *
* *
* sha256_cpp is free software: you can redistribute it and/or modify *
* it under the terms of the GNU General Public License as published by *
* the Free Software Foundation, either version 3 of the License, or *
* (at your option) any later version. *
* *
* sha256_cpp is distributed in the hope that it will be useful, *
* but WITHOUT ANY WARRANTY; without even the implied warranty of *
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the *
* GNU General Public License for more details. *
* *
* You should have received a copy of the GNU General Public License *
* along with The sha256_cpp Project. If not, see <https://www.gnu.org/licenses/>. *
* *
* In case of use of this project, I ask you to mention me, to whom it may concern. *
*****************************************************************************************/

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
