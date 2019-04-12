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
#include "gtest/gtest.h"
#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/encryptor.h"
#include "seal/memorymanager.h"
#include "seal/defaultparams.h"

using namespace std;
using namespace seal;
using namespace seal::util;

/*

This scheme will operate on INTS,

The workflow is:
1. read in a fasta
2. encrypt line by line
3. output each encrypted line to a file

*/


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
    print_example_banner("Example: BFV Basics III");

    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(4096);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(4096));
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
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();

    /*
    We also set up an Encryptor, Evaluator, and Decryptor here.
    */
    Encryptor encryptor(context, public_key);
    
    // want to save this to be loaded into a file as well //

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
    auto print_matrix = [row_size](auto &matrix)
    {
        cout << endl;

        /*
        We're not going to print every column of the matrix (there are 2048). Instead
        print this many slots from beginning and end of the matrix.
        */
        size_t print_size = 5;

        cout << "    [";
        for (size_t i = 0; i < print_size; i++)
        {
            cout << setw(3) << matrix[i] << ",";
        }
        cout << setw(3) << " ...,";
        for (size_t i = row_size - print_size; i < row_size; i++)
        {
            cout << setw(3) << matrix[i] << ((i != row_size - 1) ? "," : " ]\n");
        }
        cout << "    [";
        for (size_t i = row_size; i < row_size + print_size; i++)
        {
            cout << setw(3) << matrix[i] << ",";
        }
        cout << setw(3) << " ...,";
        for (size_t i = 2 * row_size - print_size; i < 2 * row_size; i++)
        {
            cout << setw(3) << matrix[i] << ((i != 2 * row_size - 1) ? "," : " ]\n");
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


    // turning the strings into vectors for SEAL 
    cout << endl;
    cout << "These are sequences from the first input: " << endl;
    vector<vector<uint64_t> > site_1;
    for (auto const& i: sequences) {
        //cout << i.first << endl << i.second << endl;
        string sequence = i.second;
        cout << "seq string --> uint64_t: " << i.second << endl;
        vector<uint64_t> temp;
        std::copy(sequence.begin(), sequence.end(), std::back_inserter(temp));
        site_1.push_back(temp);
    }
    cout << endl;


    // ofstream outfile;
    // outfile.open("test.txt");
    
    // just like len // 
    cout << "num of seqs --> " << site_1.size() << endl;
    cout << endl;

    for (int i = 0; i<site_1.size(); i++) {
        cout << "test loop of seqs: " << i << endl;
        for (int j = 0; j<site_1[i].size(); j++){
            cout << " " << site_1[i][j];

        }
        cout << endl;
    }   


    for (int i = 0; i<site_1.size(); i++) {
        //cout << "here is a sequence: " << endl;
        vector dog_vector = site_1[i];

        /*
        this is how you have to iterate through a vector...
        you need to print out each index, not just a row at a time. 
        */

        // for (int j = 0; j<site_1[i].size(); j++){
        //     cout << " " << site_1[i][j];

        // }
        cout << endl; 

        //---------------------------------------------------------------------------        
        /*
        This is an example of the matrix being encrypted and then decrypted 
        from start to finish
        */
        // Plaintext plain_matrix;
        // batch_encoder.encode(dog_vector, plain_matrix);
        
        // // plaintext (input 1) becomes the encrypted matrix in this example
        // Ciphertext encrypted_matrix_1;
        // encryptor.encrypt(plain_matrix, encrypted_matrix_1);

        // Plaintext plain_result;
        // decryptor.decrypt(encrypted_matrix_1, plain_result);

        // vector<uint64_t> result;
        // batch_encoder.decode(plain_result, result);

        // auto cnt = 0;

        // for (i=0; i<=10; i++){
        //     cout << "test 1 --> " << result[i] << endl;   

        // }

       //---------------------------------------------------------------------------

        /*
        This is an example of the matrix being encrypted, saved, and then decrypted 
        from start to finish
        */

        stringstream stream;
        Plaintext plain_matrix;
        batch_encoder.encode(dog_vector, plain_matrix);
        
        // plaintext (input 1) becomes the encrypted matrix in this example
        Ciphertext encrypted_matrix_1;
        Ciphertext encrypted_matrix_2;

        encryptor.encrypt(plain_matrix, encrypted_matrix_1);
    
        encrypted_matrix_1.save(stream);
        encrypted_matrix_2.load(context, stream);

        Plaintext plain_result;
        decryptor.decrypt(encrypted_matrix_2, plain_result);

        vector<uint64_t> result;
        batch_encoder.decode(plain_result, result);

        auto cnt = 0;

        for (i=0; i<=10; i++){
            cout << "test 2 --> " << result[i] << endl;   

        }


        //cout << "Different Between The Two Seqs: " << cnt << endl;

        

        // the encrypted matrix is a vector of long longs 

        

        // //fprintf(outfile, "%\n",encrypted_matrix);

        // //outfile << encrypted_matrix << endl;
        // for (i=0; i<=10; i++){
        //     cout << encrypted_matrix[i] << endl;
        //     //printf("%llu\n",encrypted_matrix[i]);
        // }

        // cout  << "this is a new seq" << endl;

        //cout << typeid(encrypted_matrix).name() << endl;


    }

    //outfile.close();
    cout << endl;

}





