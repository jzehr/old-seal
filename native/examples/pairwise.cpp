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
Helper function: Prints the name of the example in a fancy banner.
*/
void print_example_banner(string title)
{
    if (!title.empty())
    {
        size_t title_length = title.length();
        size_t banner_length = title_length + 2 + 2 * 10;
        string banner_top(banner_length, '*');
        string banner_middle = string(10, '*') + " " + title + " " + string(10, '*');

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
    hxb2.open("../examples/HXB2_prrt_temp.fa");

    string header;
    string sequence;
    string line;

    std::vector<double> input;

    getline (hxb2, header);
    while(getline (hxb2, line)) {
        sequence += line;
    }

    std::copy(sequence.begin(), sequence.end(), std::back_inserter(input));
    hxb2.close();

    // Read FASTA file
    ifstream ref;
    ref.open("../examples/ref_prrt_temp.fa");

    header.clear();
    sequence.clear();
    line.clear();

    std::vector<double> input2;

    getline (ref, header);

    while(getline (ref, line)) {
        sequence += line;
    }

    std::copy(sequence.begin(), sequence.end(), std::back_inserter(input2));
    ref.close();

    cout << "Input vector: " << endl;
    print_vector(input);

    cout << "Plaintext input2 : " << endl;
    print_vector(input2);

    Plaintext plain;
    double scale = pow(2.0, 60);

    encoder.encode(input, scale, plain);

    /*
    The vector is encrypted the same was as in BFV.
    */
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    /*
    Get the parms_id and scale from encrypted and do the addition.
    */

    // rename plain2 so that it is encrypted? not just 'plain2'
    Plaintext plain2;
    encoder.encode(input2, encrypted.parms_id(), encrypted.scale(), 
        plain2);

    evaluator.sub_plain_inplace(encrypted, plain2); 

    /*
    Decryption and decoding should give the correct result.
    */
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, input);
    cout << "Difference: " << endl;

    // this is where we can separate what the counts mean from 'input'
    auto cnt = 0;
    auto cntAG = 0;
    auto cntAT = 0;
    auto cntAC = 0;
    auto cntGA = 0;
    auto cntGC = 0;
    auto cntGT = 0;
    auto cntCG = 0;
    auto cntCA = 0;
    auto cntCT = 0;
    auto cntTG = 0;
    auto cntTA = 0;
    auto cntTC = 0;

    for(auto n : input) {
        //cout << "these are all the n: " << n << endl;
        
        // want to add switch statements hear
        if(abs(n) >= EPSILON) {

            int x = n;
            cout << "this is x: " << x << endl;
            
            if(x == -6)
            {
                cntAG++;
                cout << " A --> G " << endl;
            } 
            else if(x == -5)
            {
                cntAG++;
                cout << " A --> G " << endl;
            } 
            else if(x == -19)
            {
                cntAT++;
                cout << " A --> T " << endl;
            } 
            else if(x == -18)
            {
                cntAT++;
                cout << " A --> T " << endl;
            } 
            // this one is acting up //
            else if(x == -2)
            {
                cntAC++; 
                cout << " A --> C " << endl;
            }
            else if(x == -1)
            {
                cntAC++; 
                cout << " A --> C " << endl;
            } 
            else if(x == 6)
            {
                cntGA++;
                cout << " G --> A " << endl;
            } 
            else if(x == 5)
            {
                cntGA++;
                cout << " G --> A " << endl;
            } 
            else if(x == -13)
            {
                cntGT++;
                cout << " G --> T " << endl;
            }
            else if(x == -12)
            {
                cntGT++;
                cout << " G --> T " << endl;
            } 
            else if(x == 4)
            {
                cntGC++;
                cout << " G --> C " << endl;
            } 
            else if(x == 3)
            {
                cntGC++;
                cout << " G --> C " << endl;
            } 
            else if(x == 19)
            {
                cntTA++;
                cout << " T --> A " << endl;
            } 
            else if(x == 18)
            {
                cntTA++;
                cout << " T --> A " << endl;
            } 
            else if(x == 13)
            {
                cntTG++;
                cout << " T --> G " << endl;
            } 
            else if(x == 12)
            {
                cntTG++;
                cout << " T --> G " << endl;
            } 
            else if(x == 17)
            {
                cntTC++;
                cout << " T -- C " << endl;
            } 
            else if(x == 16)
            {
                cntTC++;
                cout << " T -- C " << endl;
            } 
            else if(x == 2)
            {
                cntCA++;
                cout << " C --> A " << endl;
            }
            else if(x == 1)
            {
                cntCA++;
                cout << " C --> A " << endl;
            }  
            else if (x == -4)
            {
                cntCG++;
                cout << " C --> G " << endl;
            } 
            else if (x == -3)
            {
                cntCG++;
                cout << " C --> G " << endl;
            } 
            else 
            {
                cntCT++;
                cout << " C --> T " << endl;
            }
            
            cnt++;
            cout << "done with this number: " << x << endl;
            cout << endl;
        }
       
    }

    
    auto transversions = cntAC + cntCA + cntGT + cntTG;
    auto tansitions = cntAG + cntGA + cntCT + cntTC;


    cout << "these are the total counts: " << cnt << endl;
    cout << "These are all transitions: " << tansitions << endl;
    cout << "These are all transversions: " << transversions << endl;

}



