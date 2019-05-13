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

/*

This scheme will operate on INTS

*/

vector<uint64_t> one_hot(string seq) {

    vector<uint64_t> one_hot_encoded;

    std::map<char, vector<uint64_t>> one_hot_map;

    one_hot_map['A'] = vector<uint64_t>{0, 0, 0, 1};
    one_hot_map['G'] = vector<uint64_t>{0, 0, 1, 0};
    one_hot_map['C'] = vector<uint64_t>{0, 1, 0, 0};
    one_hot_map['T'] = vector<uint64_t>{1, 0, 0, 0};

    if (!seq.empty()) {

        for (auto n : seq) {
            std::copy(one_hot_map[n].begin(), one_hot_map[n].end(),
                      std::back_inserter(one_hot_encoded));
        }

        return one_hot_encoded;
    }

    return {};
}

int main()

{

    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(poly_mod);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(poly_mod));
    parms.set_plain_modulus(40961);
   
   // save the parms here, write to a file to then be loaded in another script //
    ofstream parm_file;
    parm_file.open("parms_A.txt");
    EncryptionParameters::Save(parms, parm_file);

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
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto gal_keys = keygen.galois_keys(30);
    auto relin_keys16 = keygen.relin_keys(16);
    
    ofstream pk_file;
    pk_file.open("pk_A.txt");
    public_key.save(pk_file);

    ofstream sk_file;
    sk_file.open("sk_A.txt");
    secret_key.save(sk_file);

    ofstream gk_file;
    gk_file.open("gk_A.txt");
    gal_keys.save(gk_file);

    ofstream rk_file;
    rk_file.open("rk_A.txt");
    relin_keys16.save(rk_file);

    /*
    We also set up an Encryptor here.
    */
    Encryptor encryptor(context, public_key);

    /*
    Batching is done through an instance of the BatchEncoder class so need to
    construct one.
    */
    BatchEncoder batch_encoder(context);

    /*
    The total number of batching `slots' is poly_modulus_degree. The matrices
    we encrypt are of size 2-by-(slot_count / 2).
    */
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    /*
    Remeber each vector has to be of type uint64_t
    */
    // Read FASTA file
    ifstream hxb2;
    hxb2.open("../examples/rsrc/HXB2_prrt_multiple.fa");

    string header;
    string sequence;
    string line;
    vector<pair<string, string>> sequences;

    while (getline(hxb2, line)) {
        // cout << "line in the file: " << line << endl;
        if (line.rfind(">", 0) == 0) {
            if (!sequence.empty()) {
                sequences.push_back(make_pair(header, sequence));
            }

            header = line;
            sequence.clear();
        } else {
            sequence += line;
        }
    }

    if (!sequence.empty()) {
        sequences.push_back(make_pair(header, sequence));
    }

    hxb2.close();

    cout << endl;
    cout << "These are sequences from the first input: ";

    vector<vector<uint64_t>> dogs;

    for (auto const& i : sequences) {
        // cout << i.first << endl << i.second << endl;
        auto sequence = one_hot(i.second);

        cout << endl << "dog" << endl;
        for (auto i = 0; i < sequence.size(); i++) {
            cout << sequence.at(i);
        }
        cout << endl;
        dogs.push_back(sequence);
    }
    for (int i = 0; i < 3; i++) {

        auto dog_vector = dogs[i];

        auto dog_size = dog_vector.size();

        Plaintext plain_matrix;
        batch_encoder.encode(dog_vector, plain_matrix);

        // plaintext (input 1) becomes the `encrypted_matrix` 
        Ciphertext encrypted_matrix;
        encryptor.encrypt(plain_matrix, encrypted_matrix);
        
        // saving the ciphertext here //
        string s = to_string(i);

        ofstream myfile;
        myfile.open("encrypted_A_" + s + ".txt");
        encrypted_matrix.save(myfile);
    }
}