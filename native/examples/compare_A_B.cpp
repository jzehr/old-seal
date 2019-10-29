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

int main()

{
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

    KeyGenerator keygen(context);

    ifstream gk_A;
    gk_A.open("gk_A.txt");
    GaloisKeys g_keys;
    g_keys.unsafe_load(gk_A);
    //auto gal_keys = keygen.galois_keys(30);
    
    ifstream rk_A;
    rk_A.open("rk_A.txt");
    RelinKeys r_keys;
    r_keys.unsafe_load(rk_A);
    //auto relin_keys16 = keygen.relin_keys(16);

    /*
    We also set up an Evaluator here.
    */
    Evaluator evaluator(context);
    
    // read in site_A encrypted //
    ifstream in_file_A;
    in_file_A.open("encrypted_A_0.txt");
    Ciphertext cipher_A;
    cipher_A.unsafe_load(in_file_A);

    // read in site_B encrypted //
    ifstream in_file_B;
    in_file_B.open("encrypted_B_0.txt");
    Ciphertext cipher_B;
    cipher_B.unsafe_load(in_file_B);

    /*
     hxb2 - ref
    */
    
    cout << "Comparing seqs: " << endl;
    // make sure the first matrix becomes the output matrix
    cout << "size of matrix before subtraction: " << cipher_A.size() << endl;
    evaluator.sub_inplace(cipher_A, cipher_B);

    cout << "size of matrix after subtraction: " << cipher_A.size() << endl;
    evaluator.square_inplace(cipher_A);
    // We decrypt and decompose the plaintext to recover the result as a
    // matrix.
    evaluator.relinearize_inplace(cipher_A, r_keys);
    Ciphertext temp_enc_mat;

    cout << "size of matrix after relinerize: " << cipher_A.size() << endl;

    // !! make the 4096 a variable at the top and backfill //
    // !! push back each of these results to a vector, send vector of vectors to output file //
    for (auto i = 0; i < (log2(poly_mod) - 1); i++) {
        evaluator.rotate_rows(cipher_A, -(pow(2,i)), g_keys, temp_enc_mat);
        evaluator.add_inplace(cipher_A, temp_enc_mat);
    }
    ofstream myfile;
    myfile.open("compared.txt");
    cipher_A.save(myfile);
}