#include <chrono>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <fstream>
#include <iostream>
#include <list>
#include <vector>

#define poly_mod 4096
//#define poly_mod 2048
#define EPSILON 1

#include "seal/seal.h"

using namespace std;
using namespace seal;


int main() {
    ifstream in_file_1;
    in_file_1.open("encrypted_1.txt");
    Ciphertext cipher_1;
    cipher_1.unsafe_load(in_file_1);


    ifstream in_file_2;
    in_file_2.open("encrypted_2.txt");
    Ciphertext cipher_2;
    cipher_2.unsafe_load(in_file_2);

    

}

