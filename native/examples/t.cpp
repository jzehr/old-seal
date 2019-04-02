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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main()
{
/*
    In this example we demonstrate using the Cheon-Kim-Kim-Song (CKKS) scheme
    for encrypting and computing on floating point numbers. For full details on 
    the CKKS scheme, we refer the reader to https://eprint.iacr.org/2016/421.
    For better performance, Microsoft SEAL implements the "FullRNS" optimization for CKKS 
    described in https://eprint.iacr.org/2018/931.
    */

    /*
    We start by creating encryption parameters for the CKKS scheme. One major
    difference to the BFV scheme is that the CKKS scheme does not use the
    plain_modulus parameter.
    */
    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));

    /*
    We create the SEALContext as usual and print the parameters.
    */
    auto context = SEALContext::Create(parms);
    print_parameters(context);
    cout << "these are the parameters --> " << context << endl;

    /*
    Keys are created the same way as for the BFV scheme.
    */
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    // puts("public key -->");
    // cout << keygen.public_key() << endl;
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys(DefaultParams::dbc_max());

    /*
    We also set up an Encryptor, Evaluator, and Decryptor as usual.
    */
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key); 

    // why can i not print this out? 
    //cout << public_key << endl;
    
    /*
    To create CKKS plaintexts we need a special encoder: we cannot create them
    directly from polynomials. Note that the IntegerEncoder, FractionalEncoder, 
    and BatchEncoder cannot be used with the CKKS scheme. The CKKS scheme allows 
    encryption and approximate computation on vectors of real or complex numbers 
    which the CKKSEncoder converts into Plaintext objects. At a high level this 
    looks a lot like BatchEncoder for the BFV scheme, but the theory behind it
    is different.
    */
    CKKSEncoder encoder(context);

    /*
    In CKKS the number of slots is poly_modulus_degree / 2 and each slot encodes 
    one complex (or real) number. This should be contrasted with BatchEncoder in
    the BFV scheme, where the number of slots is equal to poly_modulus_degree 
    and they are arranged into a 2-by-(poly_modulus_degree / 2) matrix. 
    */
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    /*
    We create a small vector to encode; the CKKSEncoder will implicitly pad it 
    with zeros to full size (poly_modulus_degree / 2) when encoding. 
    */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // this is the first vector to be input
    vector<double> input{ 0.0, 10.1, 20.2, 30.3 };
    cout << "Input vector: " << endl;
    print_vector(input);

    /*
    Now we encode it with CKKSEncoder. The floating-point coefficients of input
    will be scaled up by the parameter `scale'; this is necessary since even in
    the CKKS scheme the plaintexts are polynomials with integer coefficients. 
    It is instructive to think of the scale as determining the bit-precision of 
    the encoding; naturally it will also affect the precision of the result. 
    
    In CKKS the message is stored modulo coeff_modulus (in BFV it is stored 
    modulo plain_modulus), so the scale must not get too close to the total size 
    of coeff_modulus. In this case our coeff_modulus is quite large (218 bits) 
    so we have little to worry about in this regard. For this example a 60-bit 
    scale is more than enough.
    */
    Plaintext plain;
    double scale = pow(2.0, 60);
    encoder.encode(input, scale, plain);

    /*
    The vector is encrypted the same was as in BFV.
    */
    Ciphertext encrypted;

    // I am flying blind, how do i print out these variable    

    encryptor.encrypt(plain, encrypted);
    cout << encrypted.parms_id() << endl;

    /*
    Another difference to the BFV scheme is that in CKKS also plaintexts are
    linked to specific parameter sets: they carry the corresponding parms_id.
    An overload of CKKSEncoder::encode(...) allows the caller to specify which
    parameter set in the modulus switching chain (identified by parms_id) should 
    be used to encode the plaintext. This is important as we will see later.
    */
    cout << "parms_id of plain: " << plain.parms_id() << endl;
    cout << "parms_id of encrypted: " << encrypted.parms_id() << endl << endl;

    /*
    The ciphertexts will keep track of the scales in the underlying plaintexts.
    The current scale in every plaintext and ciphertext is easy to access.
    */
    cout << "Scale in plain: " << plain.scale() << endl;
    cout << "Scale in encrypted: " << encrypted.scale() << endl << endl;

    /*
    Homomorphic addition and subtraction naturally require that the scales of
    the inputs are the same, but also that the encryption parameters (parms_id)
    are the same. Here we add a plaintext to encrypted. Note that a scale or
    parms_id mismatch would make Evaluator::add_plain(..) throw an exception;
    there is no problem here since we encode the plaintext just-in-time with
    exactly the right scale.
    */
    
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////    
    // this is the second vector to be input 
    vector<double> vec_diff{ 2.2, 3.3, 4.4, 5.5 };
    cout << "Plaintext difference: " << endl;
    print_vector(vec_diff);

    /*
    Get the parms_id and scale from encrypted and do the addition.
    */
    Plaintext plain_diff;
    encoder.encode(vec_diff, encrypted.parms_id(), encrypted.scale(), 
        plain_diff);
    
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /// this is where the in place subtraction takes place
    evaluator.sub_plain_inplace(encrypted, plain_diff); 

    /*
    Decryption and decoding should give the correct result.
    */
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, input);
    cout << "Difference: " << endl;
    print_vector(input);

    /*
    Note that we have not mentioned noise budget at all. In fact, CKKS does not
    have a similar concept of a noise budget as BFV; instead, the homomorphic
    encryption noise will overlap the low-order bits of the message. This is why
    scaling is needed: the message must be moved to higher-order bits to protect
    it from the noise. Still, it is difficult to completely decouple the noise 
    from the message itself; hence the noise/error budget cannot be exactly 
    measured from a ciphertext alone. 
    */
}


















