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


/*
void compare_and_encrypt (int i, int j, Evaluator evaluator, RelinKeys r_keys, GaloisKeys g_keys )
{
    string a_num_str = to_string(i); 
    string b_num_str = to_string(j);

    string a_file = "encrypted_A_" + a_num_str + ".txt";
    string b_file = "encrypted_B_" + b_num_str + ".txt";
    string o_file =  "Enc_A_" + a_num_str + "_B_" + b_num_str + ".txt";

    //cout << "A goes to --> " << a_file << " B goes to --> " << b_file << endl;
    
    ifstream in_file_A;
    ifstream in_file_B;

    in_file_A.open(a_file);
    in_file_B.open(b_file);

    Ciphertext cipher_A;
    Ciphertext cipher_B;

    cipher_A.unsafe_load(in_file_A);
    cipher_B.unsafe_load(in_file_B);

    //cout << "A goes to --> " << a_file << " B goes to --> " << b_file << endl;
    evaluator.sub_inplace(cipher_A, cipher_B);
    evaluator.square_inplace(cipher_A);
    evaluator.relinearize_inplace(cipher_A, r_keys);
    
    Ciphertext temp_enc_mat;
    for (auto i = 0; i < (log2(poly_mod) - 1); i++) {
        evaluator.rotate_rows(cipher_A, -(pow(2,i)), g_keys, temp_enc_mat);
        evaluator.add_inplace(cipher_A, temp_enc_mat);
    }
    
    ofstream myfile;
    myfile.open(o_file);
    cipher_A.save(myfile);

}
*/

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
    
    ifstream in_file_A;
    in_file_A.open("Site_A_number_seqs.txt");
    int num_seqs_A = 0;
    
    // add a error message if file empty //
    string line;
    while (getline(in_file_A, line)) {
        stringstream seq_num(line);
        seq_num >> num_seqs_A;
    }
    cout << "these are the number of seqs in A " << num_seqs_A << endl;

    ifstream in_file_B;
    in_file_B.open("Site_B_number_seqs.txt");
    int num_seqs_B = 0;
    
    // add a error message if file empty //
    line = "";
    while (getline(in_file_B, line)) {
        stringstream seq_num(line);
        seq_num >> num_seqs_B;
    }
    cout << "these are the number of seqs in B " << num_seqs_B << endl;

    for(int i = 0; i < num_seqs_A; i++){
        for(int j = 0; j < num_seqs_B; j++){
            // do a comparison //
            string a_num_str = to_string(i); 
            string b_num_str = to_string(j);

            string a_file = "encrypted_A_" + a_num_str + ".txt";
            string b_file = "encrypted_B_" + b_num_str + ".txt";
            string o_file =  "Enc_A_" + a_num_str + "_B_" + b_num_str + ".txt";

            //cout << "A goes to --> " << a_file << " B goes to --> " << b_file << endl;
            
            ifstream in_file_A;
            ifstream in_file_B;

            in_file_A.open(a_file);
            in_file_B.open(b_file);

            Ciphertext cipher_A;
            Ciphertext cipher_B;

            cipher_A.unsafe_load(in_file_A);
            cipher_B.unsafe_load(in_file_B);

            //cout << "A goes to --> " << a_file << " B goes to --> " << b_file << endl;
            evaluator.sub_inplace(cipher_A, cipher_B);
            evaluator.square_inplace(cipher_A);
            evaluator.relinearize_inplace(cipher_A, r_keys);
            
            // making changes 11/5
            Ciphertext temp_enc_mat;
            for (auto i = 0; i < (log2(poly_mod) - 1); i++) {
            //for (auto i = 0; i < log2(poly_mod); i++) {
                evaluator.rotate_rows(cipher_A, -(pow(2,i)), g_keys, temp_enc_mat);
                evaluator.add_inplace(cipher_A, temp_enc_mat);
            }
            
            ofstream myfile;
            myfile.open(o_file);
            cipher_A.save(myfile);

        }
    }
}
