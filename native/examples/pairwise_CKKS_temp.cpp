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

#include <fstream>
#include <iostream>
#include <list>
#include <vector>

#define EPSILON 1

#include "seal/seal.h"

using namespace std;
using namespace seal;

/*
                This scheme will operate on FLOATS
*/

/*
Helper function: Prints the parameters in a SEALContext.
*/
void print_parameters(shared_ptr<SEALContext> context)
{
    // Verify parameters
    if (!context)
    {
        throw invalid_argument("context is not set");
    }
    auto &context_data = *context->context_data();

    /*
    Which scheme are we using?
    */
    string scheme_name;
    switch (context_data.parms().scheme())
    {
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
    cout << "| poly_modulus_degree: " << 
        context_data.parms().poly_modulus_degree() << endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    cout << "| coeff_modulus size: " << context_data.
        total_coeff_modulus_bit_count() << " bits" << endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == scheme_type::BFV)
    {
        cout << "| plain_modulus: " << context_data.
            parms().plain_modulus().value() << endl;
    }

    cout << "\\ noise_standard_deviation: " << context_data.
        parms().noise_standard_deviation() << endl;
    cout << endl;
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
ostream &operator <<(ostream &stream, parms_id_type parms_id)
{
    stream << hex << parms_id[0] << " " << parms_id[1] << " "
        << parms_id[2] << " " << parms_id[3] << dec;
    return stream;
}

/*
Helper function: Prints a vector of floating-point values.
*/
template<typename T>
void print_vector(vector<T> vec, size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);

    size_t slot_count = vec.size();

    cout << fixed << setprecision(prec) << endl;
    if(slot_count <= 2 * print_size)
    {
        cout << "    [";
        for (size_t i = 0; i < slot_count; i++)
        {
            cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(max(vec.size(), 2 * print_size));
        cout << "    [";
        for (size_t i = 0; i < print_size; i++)
        {
            cout << " " << vec[i] << ",";
        }
        if(vec.size() > 2 * print_size)
        {
            cout << " ...,";
        }
        for (size_t i = slot_count - print_size; i < slot_count; i++)
        {
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

    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));

    /*
    We create the SEALContext as usual and print the parameters.
    */
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    /*
    Keys are created the same way as for the BFV scheme.
    */
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys(DefaultParams::dbc_max());

    /*
    We also set up an Encryptor, Evaluator, and Decryptor as usual.
    */
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key); 

    CKKSEncoder encoder(context);

    /*
    In CKKS the number of slots is poly_modulus_degree / 2 and each slot encodes 
    one complex (or real) number. This should be contrasted with BatchEncoder in
    the BFV scheme, where the number of slots is equal to poly_modulus_degree 
    and they are arranged into a 2-by-(poly_modulus_degree / 2) matrix. 
    */
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    // Read FASTA file
    ifstream hxb2;
    hxb2.open("../examples/rsrc/Site_1_aligned.fa");

    string header;
    string sequence;
    string line;
    vector<pair<string, string> > sequences;

    while( getline (hxb2, line))
    {
        //cout << "line in the file: " << line << endl;
        if (line.rfind(">",0)==0)
        {
            if (!sequence.empty()){
                sequences.push_back(make_pair(header,sequence));
            
            }
            
            header = line;
            sequence.clear();
        }
        else
        {
            sequence += line;
        }
    }

    if (!sequence.empty()){
        sequences.push_back(make_pair(header,sequence));          
    }

    hxb2.close();

    // Read FASTA file
    ifstream ref;
    ref.open("../examples/rsrc/Site_2_aligned.fa");

    header.clear();
    sequence.clear();
    line.clear();

    vector<pair<string, string> > sequences2;

    while( getline (ref, line))
    {
        //cout << "line in the file: " << line << endl;
        if (line.rfind(">",0)==0)
        {
            if (!sequence.empty()){
                sequences2.push_back(make_pair(header,sequence));
            
            }
            
            header = line;
            sequence.clear();
        }
        else
        {
            sequence += line;
        }
    }

    if (!sequence.empty()){
        sequences2.push_back(make_pair(header,sequence));          
    }
    ref.close();


    // turning the strings into vectors for SEAL 
    cout << endl;
    cout << "These are sequences from the first input: " << endl;
    vector<vector<double> > dogs;
    for (auto const& i: sequences) {
        //cout << i.first << endl << i.second << endl;
        string sequence = i.second;
        //cout << "seq string --> double: " << i.second << endl;
        vector<double> temp;
        std::copy(sequence.begin(), sequence.end(), std::back_inserter(temp));
        dogs.push_back(temp);
    }
    cout << endl;
    
    cout << "These are sequences from the second input: " << endl;
    vector<vector<double> > cats;
    for (auto const& i: sequences2) {
        auto sequence = i.second;
        //cout << "seq string --> double: " << i.second << endl;
        vector<double> temp;
        std::copy(sequence.begin(), sequence.end(), std::back_inserter(temp));
        cats.push_back(temp);
    }
    cout << endl;

    // printing out each item in the row of rows // 
    for (int i = 0; i<dogs.size(); i++) {
        // this is where I will want to encrypt the vector to do stuff... // 
        vector dog_vector = dogs[i];
        vector cat_vector = cats[i];
        Plaintext plain;
        double scale = pow(2.0, 60);
        encoder.encode(dog_vector, scale, plain);
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);
            
        // this is the second input row
        Plaintext plain2;
        encoder.encode(cat_vector, encrypted.parms_id(), encrypted.scale(), 
        plain2);

        evaluator.sub_plain_inplace(encrypted, plain2); 

        /*
        we want to be able to get the counts from here
        BEFORE the ciphertext gets decrypted. 
        */

        // for (auto i : encrypted){
        //     cout << "this is the encrypt: " << i << endl;
        // }

        decryptor.decrypt(encrypted, plain);
        encoder.decode(plain, dog_vector);

        auto cnt = 0;

        for(auto n : dog_vector) {
        //cout << "these are all the n: " << n << endl;
        // want to add switch statements here
            if(abs(n) >= EPSILON) {

                cnt++;
            }
        }

        cout << "Different Between The Two Seqs: " << cnt << endl;

    }
    
    cout << endl;

}



