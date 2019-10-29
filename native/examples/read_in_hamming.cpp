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

//#define poly_mod 2048

// #define poly_mod 4096
// #define plain_mod_batch 40961

// this one doesnt work properly

#define poly_mod 8192
#define plain_mod_batch 114689

// #define poly_mod 16384
// #define plain_mod_batch 163841

#define EPSILON 1

#include "seal/seal.h"

using namespace std;
using namespace seal;



int main() {
    // Set up encryption parameters
    // read in site_A parms //
    ifstream infile_parms_A;
    infile_parms_A.open("parms_A.txt");
    EncryptionParameters parms(scheme_type::BFV);
    parms = EncryptionParameters::Load(infile_parms_A);


    /*
    We create the SEALContext as usual and print the parameters.
    */
    auto context = SEALContext::Create(parms);

    /*
    We can verify that batching is indeed enabled by looking at the encryption
    parameter qualifiers created by SEALContext.
    
    */
    auto qualifiers = context->context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching
         << endl;

    //KeyGenerator keygen(context);
    //auto secret_key = keygen.secret_key();
    KeyGenerator keygen(context);

    ifstream sk_A;
    sk_A.open("sk_A.txt");
    SecretKey s_key;
    s_key.unsafe_load(sk_A);
    
    /*
    We also set up a Decryptor here.
    */
    Decryptor decryptor(context, s_key);

    
    /*
    Batching is done through an instance of the BatchEncoder class so need to
    construct one.
    */
    BatchEncoder batch_encoder(context);

    ifstream infile_ham;
    infile_ham.open("compared.txt");
    Ciphertext compared_ham;
    compared_ham.unsafe_load(infile_ham);
            
    Plaintext plain_result;
    decryptor.decrypt(compared_ham, plain_result);

    vector<uint64_t> result;
    batch_encoder.decode(plain_result, result);

    cout << "Different Between The Two Seqs: " << result[0]/2 << endl;
    cout << endl;

}
