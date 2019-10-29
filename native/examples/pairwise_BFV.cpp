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

/*
Helper function: Prints the name of the example in a fancy banner.
*/
void print_example_banner(string title) {
    if (!title.empty()) {
        size_t title_length = title.length();
        size_t banner_length = title_length + 2 + 2 * 10;
        string banner_top(banner_length, '*');
        string banner_middle =
            string(10, '*') + " " + title + " " + string(10, '*');

        cout << endl
             << banner_top << endl
             << banner_middle << endl
             << banner_top << endl
             << endl;
    }
}

/*
Helper function: Prints the parameters in a SEALContext.
*/
void print_parameters(shared_ptr<SEALContext> context) {
    // Verify parameters
    if (!context) {
        throw invalid_argument("context is not set");
    }
    auto& context_data = *context->context_data();

    /*
    Which scheme are we using?
    */
    string scheme_name;
    switch (context_data.parms().scheme()) {
    case scheme_type::BFV:
        scheme_name = "BFV";
        break;
    case scheme_type::CKKS:
        scheme_name = "CKKS";
        break;
    default:
        throw invalid_argument("unsupported scheme");
    }

    cout << "/ Encryption parameters:" << endl;
    cout << "| scheme: " << scheme_name << endl;
    cout << "| poly_modulus_degree: "
         << context_data.parms().poly_modulus_degree() << endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    cout << "| coeff_modulus size: "
         << context_data.total_coeff_modulus_bit_count() << " bits" << endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == scheme_type::BFV) {
        cout << "| plain_modulus: "
             << context_data.parms().plain_modulus().value() << endl;
    }

    cout << "\\ noise_standard_deviation: "
         << context_data.parms().noise_standard_deviation() << endl;
    cout << endl;
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
ostream& operator<<(ostream& stream, parms_id_type parms_id) {
    stream << hex << parms_id[0] << " " << parms_id[1] << " " << parms_id[2]
           << " " << parms_id[3] << dec;
    return stream;
}

/*
Helper function: Prints a vector of floating-point values.
*/
template <typename T>
void print_vector(vector<T> vec, size_t print_size = 4, int prec = 3) {
    /*
    Save the formatting information for std::cout.
    */
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);

    size_t slot_count = vec.size();

    cout << fixed << setprecision(prec) << endl;
    if (slot_count <= 2 * print_size) {
        cout << "    [";
        for (size_t i = 0; i < slot_count; i++) {
            cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    } else {
        vec.resize(max(vec.size(), 2 * print_size));
        cout << "    [";
        for (size_t i = 0; i < print_size; i++) {
            cout << " " << vec[i] << ",";
        }
        if (vec.size() > 2 * print_size) {
            cout << " ...,";
        }
        for (size_t i = slot_count - print_size; i < slot_count; i++) {
            cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    cout << endl;

    /*
    Restore the old std::cout formatting.
    */
    cout.copyfmt(old_fmt);
}

using namespace std;

int main()

{
    print_example_banner("Example: BFV Basics III");
    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(poly_mod);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(poly_mod));
    parms.set_plain_modulus(40961);

    /*
    We create the SEALContext as usual and print the parameters.
    */
    auto context = SEALContext::Create(parms);
    print_parameters(context);

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

    /*
    We also set up an Encryptor, Evaluator, and Decryptor here.
    */
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

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
    Printing the matrix is a bit of a pain.
    */
    auto print_matrix = [row_size](auto& matrix) {
        cout << endl;

        /*
        We're not going to print every column of the matrix (there are 2048).
        Instead print this many slots from beginning and end of the matrix.
        */
        size_t print_size = 5;

        cout << "    [";
        for (size_t i = 0; i < print_size; i++) {
            cout << setw(3) << matrix[i] << ",";
        }
        cout << setw(3) << " ...,";
        for (size_t i = row_size - print_size; i < row_size; i++) {
            cout << setw(3) << matrix[i]
                 << ((i != row_size - 1) ? "," : " ]\n");
        }
        cout << "    [";
        for (size_t i = row_size; i < row_size + print_size; i++) {
            cout << setw(3) << matrix[i] << ",";
        }
        cout << setw(3) << " ...,";
        for (size_t i = 2 * row_size - print_size; i < 2 * row_size; i++) {
            cout << setw(3) << matrix[i]
                 << ((i != 2 * row_size - 1) ? "," : " ]\n");
        }
        cout << endl;
    };

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

    // Read FASTA file
    ifstream ref;
    ref.open("../examples/rsrc/ref_prrt_multiple.fa");

    header.clear();
    sequence.clear();
    line.clear();

    vector<pair<string, string>> sequences2;

    while (getline(ref, line)) {
        // cout << "line in the file: " << line << endl;
        if (line.rfind(">", 0) == 0) {
            if (!sequence.empty()) {
                sequences2.push_back(make_pair(header, sequence));
            }

            header = line;
            sequence.clear();
        } else {
            sequence += line;
        }
    }

    if (!sequence.empty()) {
        sequences2.push_back(make_pair(header, sequence));
    }
    ref.close();

    // turning the strings into vectors for SEAL
    cout << endl;
    cout << "These are sequences from the first input: ";

    vector<vector<uint64_t>> dogs;

    for (auto const& i : sequences) {
        // cout << i.first << endl << i.second << endl;
        auto sequence = one_hot(i.second);

        cout << endl << "Patient 2" << endl;
        for (auto i = 0; i < sequence.size(); i++) {
            cout << sequence.at(i);
        }

        dogs.push_back(sequence);
    }
    
    cout << endl;

    cout << endl << "These are sequences from the second input: ";

    vector<vector<uint64_t>> cats;
    for (auto const& i : sequences2) {
        // cout << i.first << endl << i.second << endl;
        auto sequence = one_hot(i.second);

        cout << endl << "Patient 2" << endl;
        for (auto i = 0; i < sequence.size(); i++) {
            cout << sequence.at(i);
        }

        cats.push_back(sequence);
    }

    cout << endl;
    cout << endl;

    ofstream outfile;

    // for (int i = 0; i<dogs.size(); i++) {
    // ** right now this is set up to just do the first sequence comparison //
    // !! this for loop will need to loop over EVERY sequence in the fasta. make a variable //
    // ?? want to push back each vector (each sequence) comparison? send that to output? //

    for (int i = 0; i < 3; i++) {

        auto dog_vector = dogs[i];
        auto cat_vector = cats[i];

        auto dog_size = dog_vector.size();

        Plaintext plain_matrix;
        batch_encoder.encode(dog_vector, plain_matrix);

        // plaintext (input 1) becomes the `encrypted_matrix` 
        Ciphertext encrypted_matrix;
        encryptor.encrypt(plain_matrix, encrypted_matrix);
        
        // saving the ciphertext here //
        
        string s = to_string(i);

        ofstream myfile;

        myfile.open("encrypted_" + s + ".txt");
        // matrix is now saved... so how do i write this to a file now.. ? 
        encrypted_matrix.save(myfile);
        


        // plaintext (input 2) becomes the `encrypted_matrix2`
        // batch encoding input 2
        Plaintext plain_matrix2;
        batch_encoder.encode(cat_vector, plain_matrix2);

        Ciphertext encrypted_matrix2;
        batch_encoder.encode(cat_vector, plain_matrix2);
        encryptor.encrypt(plain_matrix2, encrypted_matrix2);

        /*
        We now subtract the second (plaintext2 (input2)) matrix to the encrypted
        one using another new operation hxb2 - ref
        */
       
        // need to save this as an object to iterate over so that no one can see
        // the decrypted results
        cout << "Comparing seqs: " << i+1 << endl;
        // make sure the first matrix becomes the output matrix
        cout << "size of matrix before subtraction: " << encrypted_matrix.size() << endl;
        evaluator.sub_inplace(encrypted_matrix, encrypted_matrix2);

        cout << "size of matrix after subtraction: " << encrypted_matrix.size() << endl;
        evaluator.square_inplace(encrypted_matrix);
        // We decrypt and decompose the plaintext to recover the result as a
        // matrix.
        evaluator.relinearize_inplace(encrypted_matrix, relin_keys16);
        Ciphertext temp_enc_mat;

        cout << "size of matrix after relinerize: " << encrypted_matrix.size() << endl;

        // !! make the 4096 a variable at the top and backfill //
        // !! push back each of these results to a vector, send vector of vectors to output file //
        for (auto i = 0; i < (log2(poly_mod) - 1); i++) {
            evaluator.rotate_rows(encrypted_matrix, -(pow(2,i)), gal_keys, temp_enc_mat);
            evaluator.add_inplace(encrypted_matrix, temp_enc_mat);
        }



        Plaintext plain_result;
        decryptor.decrypt(encrypted_matrix, plain_result);

        vector<uint64_t> result;
        batch_encoder.decode(plain_result, result);

        //auto cnt = 0;

        // for (auto n : result) {
        //     // cout << "these are all the n: " << n << endl;
        //     //cout << n << endl;
        //     cnt++;
        // }

        cout << "Different Between The Two Seqs: " << result[0]/2 << endl;
        cout << "size of matrix: " << result.size() << endl;
        cout << endl;
    }
    outfile.close();
    cout << endl;
}
