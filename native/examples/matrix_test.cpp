#include <cstddef>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <memory>
#include <limits>

#include "seal/seal.h"

using namespace std;
using namespace seal;


int main(){

    char bertha[2][3] = {{'A','T','C'}, {'G','T','A'}};
    char doug[2][3] = {{'A','C','C'}, {'G','A','A'}};

    for (int row=0; row<2; row++){
        for (int col=0; col<3; col++){

            cout << " bertha: " << bertha[row][col] << " __ " << " doug: " << doug[row][col] << endl;
        }

        cout << endl;
    }
    
}


