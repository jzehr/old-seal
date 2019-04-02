
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

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

int main()
{
    print_example_banner("Example: BFV Basics III");

    /*
    In this fundamental example we discuss and demonstrate a powerful technique 
    called `batching'. If N denotes the degree of the polynomial modulus, and T
    the plaintext modulus, then batching is automatically enabled for the BFV
    scheme when T is a prime number congruent to 1 modulo 2*N. In batching the 
    plaintexts are viewed as matrices of size 2-by-(N/2) with each element an 
    integer modulo T. Homomorphic operations act element-wise between encrypted 
    matrices, allowing the user to obtain speeds-ups of several orders of 
    magnitude in naively vectorizable computations. We demonstrate two more 
    homomorphic operations which act on encrypted matrices by rotating the rows 
    cyclically, or rotate the columns (i.e. swap the rows). These operations 
    require the construction of so-called `Galois keys', which are very similar 
    to relinearization keys.

    The batching functionality is totally optional in the BFV scheme and is 
    exposed through the BatchEncoder class. 
    */
    EncryptionParameters parms(scheme_type::BFV);


    // can we change this to be 100?
    parms.set_poly_modulus_degree(4096);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(4096));

    /*
    Note that 40961 is a prime number and 2*4096 divides 40960, so batching will
    automatically be enabled for these parameters.
    */
    parms.set_plain_modulus(40961);

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
    We need to create so-called `Galois keys' for performing matrix row and 
    column rotations on encrypted matrices. Like relinearization keys, the 
    behavior of Galois keys depends on a decomposition bit count. The noise 
    budget consumption behavior of matrix row and column rotations is exactly 
    like that of relinearization (recall example_bfv_basics_ii()).

    Here we use a moderate size decomposition bit count.
    */
    auto gal_keys = keygen.galois_keys(30);

    /*
    Since we are going to do some multiplications we will also relinearize.
    */
    auto relin_keys = keygen.relin_keys(30);

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

    cout << "Slot count: " << slot_count << endl;

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
//////////////////////////////////////////////////////////////////////////////////////////
/* 
   This is where you would define the FIRST matrix you would want to use
*/
//////////////////////////////////////////////////////////////////////////////////////////

    /*
    The matrix plaintext is simply given to BatchEncoder as a flattened vector
    of numbers of size slot_count. The first row_size numbers form the first row, 
    and the rest form the second row. Here we create the following matrix:

        [ 0,  1,  2,  3,  0,  0, ...,  0 ]
        [ 4,  5,  6,  7,  0,  0, ...,  0 ]
    */
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;


    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix);

    /*
    First we use BatchEncoder to compose the matrix into a plaintext.
    */
    Plaintext plain_matrix;
    batch_encoder.encode(pod_matrix, plain_matrix);

    /*
    Next we encrypt the plaintext as usual.
    */
    Ciphertext encrypted_matrix;
    cout << "Encrypting: ";
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "Done" << endl;
    cout << "Noise budget in fresh encryption: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

//////////////////////////////////////////////////////////////////////////////////////////
/* 
   This is where you would define the SECOND matrix you would want to use
*/
//////////////////////////////////////////////////////////////////////////////////////////

    /*
    Operating on the ciphertext results in homomorphic operations being performed
    simultaneously in all 4096 slots (matrix elements). To illustrate this, we 
    form another plaintext matrix

        [ 1,  2,  1,  2,  1,  2, ..., 2 ]
        [ 1,  2,  1,  2,  1,  2, ..., 2 ]

    and compose it into a plaintext.
    */
    vector<uint64_t> pod_matrix2;
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_matrix2.push_back((i % 2) + 1);
    }
    Plaintext plain_matrix2;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    cout << "Second input plaintext matrix:" << endl;
    print_matrix(pod_matrix2);

    /*
    We now add the second (plaintext) matrix to the encrypted one using another 
    new operation -- plain addition -- and square the sum.
    */
    cout << "Adding and squaring: ";
    evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2);
    evaluator.square_inplace(encrypted_matrix);
    evaluator.relinearize_inplace(encrypted_matrix, relin_keys);
    cout << "Done" << endl;

    /*
    How much noise budget do we have left?
    */
    cout << "Noise budget in result: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;
    
    /*
    We decrypt and decompose the plaintext to recover the result as a matrix.
    */
    Plaintext plain_result;
    cout << "Decrypting result: ";
    decryptor.decrypt(encrypted_matrix, plain_result);
    cout << "Done" << endl;

    vector<uint64_t> pod_result;
    batch_encoder.decode(plain_result, pod_result);

    cout << "Result plaintext matrix:" << endl;
    print_matrix(pod_result);

    /*
    Note how the operation was performed in one go for each of the elements of 
    the matrix. It is possible to achieve incredible performance improvements by 
    using this method when the computation is easily vectorizable.

    Our discussion so far could have applied just as well for a simple vector 
    data type (not matrix). Now we show how the matrix view of the plaintext can 
    be used for more functionality. Namely, it is possible to rotate the matrix 
    rows cyclically, and same for the columns (i.e. swap the two rows). For this
    we need the Galois keys that we generated earlier.

    We return to the original matrix that we started with.
    */
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "Unrotated matrix: " << endl;
    print_matrix(pod_matrix);
    cout << "Noise budget in fresh encryption: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    Now rotate the rows to the left 3 steps, decrypt, decompose, and print.
    */
    evaluator.rotate_rows_inplace(encrypted_matrix, 3, gal_keys);
    cout << "Rotated rows 3 steps left: " << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_result);
    print_matrix(pod_result);
    cout << "Noise budget after rotation: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    Rotate columns (swap rows), decrypt, decompose, and print.
    */
    evaluator.rotate_columns_inplace(encrypted_matrix, gal_keys);
    cout << "Rotated columns: " << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_result);
    print_matrix(pod_result);
    cout << "Noise budget after rotation: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    Rotate rows to the right 4 steps, decrypt, decompose, and print.
    */
    evaluator.rotate_rows_inplace(encrypted_matrix, -4, gal_keys);
    cout << "Rotated rows 4 steps right: " << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_result);
    print_matrix(pod_result);
    cout << "Noise budget after rotation: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    The output is as expected. Note how the noise budget gets a big hit in the
    first rotation, but remains almost unchanged in the next rotations. This is 
    again the same phenomenon that occurs with relinearization, where the noise 
    budget is consumed down to some bound determined by the decomposition bit 
    count and the encryption parameters. For example, after some multiplications 
    have been performed rotations come basically for free (noise budget-wise), 
    whereas they can be relatively expensive when the noise budget is nearly 
    full unless a small decomposition bit count is used, which on the other hand
    is computationally costly.
    */
}