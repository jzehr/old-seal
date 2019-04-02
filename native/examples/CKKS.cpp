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
int main(){
    puts("dogs and cats");
    return 0;
}
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

void example_ckks_basics_i();

void example_ckks_basics_ii();

void example_ckks_basics_iii();

// void example_bfv_performance();

void example_ckks_performance();

int main()
{
#ifdef SEAL_VERSION
    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
#endif
    while (true)
    {
        cout << "\nSEAL Examples:" << endl << endl;
        cout << " 6. CKKS Basics I" << endl;
        cout << " 7. CKKS Basics II" << endl;
        cout << " 8. CKKS Basics III" << endl;
        cout << " 9. CKKS Performance Test" << endl;
        cout << " 0. Exit" << endl;

        /*
        Print how much memory we have allocated from the current memory pool.
        By default the memory pool will be a static global pool and the
        MemoryManager class can be used to change it. Most users should have
        little or no reason to touch the memory allocation system.
        */
        cout << "\nTotal memory allocated from the current memory pool: "
            << (MemoryManager::GetPool().alloc_byte_count() >> 20) << " MB" << endl;

        int selection = 0;
        cout << endl << "Run example: ";
        if (!(cin >> selection))
        {
            cout << "Invalid option." << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            continue;
        }
        
        switch (selection)
        {
        case 6:
            example_ckks_basics_i();
            break;

        case 7:
            example_ckks_basics_ii();
            break;

        case 8:
            example_ckks_basics_iii();
            break;

        case 9: {
            example_ckks_performance();
            break;
        }

        case 0:
            return 0;

        default:
            cout << "Invalid option." << endl;
        }
    }

    return 0;
}


void example_ckks_basics_i()
{
    print_example_banner("Example: CKKS Basics I");

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
    vector<double> input{ 0.0, 1.1, 2.2, 3.3 };
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
    encryptor.encrypt(plain, encrypted);

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
    Basic operations on the ciphertexts are still easy to do. Here we square 
    the ciphertext, decrypt, decode, and print the result. We note also that 
    decoding returns a vector of full size (poly_modulus_degree / 2); this is 
    because of the implicit zero-padding mentioned above. 
    */
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, input);
    cout << "Squared input: " << endl;
    print_vector(input);

    /*
    We notice that the results are correct. We can also print the scale in the 
    result and observe that it has increased. In fact, it is now the square of 
    the original scale (2^60). 
    */
    cout << "Scale in the square: " << encrypted.scale() 
        << " (" << log2(encrypted.scale()) << " bits)" << endl;

    /*
    CKKS supports modulus switching just like the BFV scheme. We can switch
    away parts of the coefficient modulus.
    */
    cout << "Current coeff_modulus size: "
        << context->context_data(encrypted.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl; 

    cout << "Modulus switching ..." << endl;
    evaluator.mod_switch_to_next_inplace(encrypted);

    cout << "Current coeff_modulus size: "
        << context->context_data(encrypted.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl; 
    cout << endl;

    /*
    At this point if we tried switching further Microsoft SEAL would throw an 
    exception. This is because the scale is 120 bits and after modulus switching 
    we would be down to a total coeff_modulus smaller than that, which is not 
    enough to contain the plaintext. We decrypt and decode, and observe that the 
    result is the same as before. 
    */
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, input);
    cout << "Squared input: " << endl;
    print_vector(input);

    /*
    In some cases it can be convenient to change the scale of a ciphertext by
    hand. For example, multiplying the scale by a number effectively divides the 
    underlying plaintext by that number, and vice versa. The caveat is that the 
    resulting scale can be incompatible with the scales of other ciphertexts.
    Here we divide the ciphertext by 3.
    */
    encrypted.scale() *= 3; 
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, input);
    cout << "Divided by 3: " << endl;
    print_vector(input);

    /*
    Homomorphic addition and subtraction naturally require that the scales of
    the inputs are the same, but also that the encryption parameters (parms_id)
    are the same. Here we add a plaintext to encrypted. Note that a scale or
    parms_id mismatch would make Evaluator::add_plain(..) throw an exception;
    there is no problem here since we encode the plaintext just-in-time with
    exactly the right scale.
    */
    vector<double> vec_summand{ 20.2, 30.3, 40.4, 50.5 };
    cout << "Plaintext summand: " << endl;
    print_vector(vec_summand);

    /*
    Get the parms_id and scale from encrypted and do the addition.
    */
    Plaintext plain_summand;
    encoder.encode(vec_summand, encrypted.parms_id(), encrypted.scale(), 
        plain_summand);
    evaluator.add_plain_inplace(encrypted, plain_summand); 

    /*
    Decryption and decoding should give the correct result.
    */
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, input);
    cout << "Sum: " << endl;
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

void example_ckks_basics_ii()
{
    print_example_banner("Example: CKKS Basics II");

    /*
    The previous example did not really make it clear why CKKS is useful at all.
    Certainly one can scale floating-point numbers to integers, encrypt them,
    keep track of the scale, and operate on them by just using BFV. The problem
    with this approach is that the scale quickly grows larger than the size of
    the coefficient modulus, preventing further computations. The true power of 
    CKKS is that it allows the scale to be switched down (`rescaling') without 
    changing the encrypted values. 
    
    To demonstrate this, we start by setting up the same environment we had in 
    the previous example.
    */
    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));

    auto context = SEALContext::Create(parms);
    print_parameters(context);

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys(DefaultParams::dbc_max());

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key); 

    CKKSEncoder encoder(context);

    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input{ 0.0, 1.1, 2.2, 3.3 };
    cout << "Input vector: " << endl;
    print_vector(input);

    /*
    We use a slightly smaller scale in this example.
    */
    Plaintext plain;
    double scale = pow(2.0, 60);
    encoder.encode(input, scale, plain);

    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    /*
    Print the scale and the parms_id for encrypted.
    */
    cout << "Chain index of (encryption parameters of) encrypted: " 
        << context->context_data(encrypted.parms_id())->chain_index() << endl;
    cout << "Scale in encrypted before squaring: " << encrypted.scale() << endl;

    /*
    We did this already in the previous example: square encrypted and observe 
    the scale growth.
    */
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "Scale in encrypted after squaring: " << encrypted.scale() 
        << " (" << log2(encrypted.scale()) << " bits)" << endl;
    cout << "Current coeff_modulus size: "
        << context->context_data(encrypted.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl; 
    cout << endl;

    /*
    Now, to prevent the scale from growing too large in subsequent operations,
    we apply rescaling.
    */
    cout << "Rescaling ..." << endl << endl;
    evaluator.rescale_to_next_inplace(encrypted);

    /*
    Rescaling changes the coefficient modulus as modulus switching does. These
    operations are in fact very closely related. Moreover, the scale indeed has 
    been significantly reduced: rescaling divides the scale by the coefficient
    modulus prime that was switched away. Since our coefficient modulus in this
    case consisted of the primes (see seal/utils/global.cpp)

        0x7fffffff380001,  0x7ffffffef00001,
        0x3fffffff000001,  0x3ffffffef40001,

    the last of which is 54 bits, the bit-size of the scale was reduced by 
    precisely 54 bits. Finer granularity rescaling would require smaller primes
    to be used, but this might lead to performance problems as the computational 
    cost of homomorphic operations and the size of ciphertexts depends linearly 
    on the number of primes in coeff_modulus.
    */
    cout << "Chain index of (encryption parameters of) encrypted: " 
        << context->context_data(encrypted.parms_id())->chain_index() << endl;
    cout << "Scale in encrypted: " << encrypted.scale() 
        << " (" << log2(encrypted.scale()) << " bits)" << endl;
    cout << "Current coeff_modulus size: "
        << context->context_data(encrypted.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl; 
    cout << endl;

    /*
    We can even compute the fourth power of the input. Note that it is very
    important to first relinearize and then rescale. Trying to do these two
    operations in the opposite order will make Microsoft SEAL throw and exception.
    */
    cout << "Squaring and rescaling ..." << endl << endl;
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted);

    cout << "Chain index of (encryption parameters of) encrypted: " 
        << context->context_data(encrypted.parms_id())->chain_index() << endl;
    cout << "Scale in encrypted: " << encrypted.scale() 
        << " (" << log2(encrypted.scale()) << " bits)" << endl;
    cout << "Current coeff_modulus size: "
        << context->context_data(encrypted.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl; 
    cout << endl;

    /*
    At this point our scale is 78 bits and the coefficient modulus is 110 bits.
    This means that we cannot square the result anymore, but if we rescale once
    more and then square, things should work out better. We cannot relinearize
    with relin_keys at this point due to the large decomposition bit count we 
    used: the noise from relinearization would completely destroy our result 
    due to the small scale we are at.
    */
    cout << "Rescaling and squaring (no relinearization) ..." << endl << endl;
    evaluator.rescale_to_next_inplace(encrypted);
    evaluator.square_inplace(encrypted);

    cout << "Chain index of (encryption parameters of) encrypted: " 
        << context->context_data(encrypted.parms_id())->chain_index() << endl;
    cout << "Scale in encrypted: " << encrypted.scale() 
        << " (" << log2(encrypted.scale()) << " bits)" << endl;
    cout << "Current coeff_modulus size: "
        << context->context_data(encrypted.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl; 
    cout << endl;

    /*
    We decrypt, decode, and print the results.
    */
    decryptor.decrypt(encrypted, plain);
    vector<double> result;
    encoder.decode(plain, result);
    cout << "Eighth powers: " << endl;
    print_vector(result);

    /*
    We have gone pretty low in the scale at this point and can no longer expect
    to get entirely accurate results. Still, our results are quite accurate. 
    */
    vector<double> precise_result{};
    transform(input.begin(), input.end(), back_inserter(precise_result), 
        [](auto in) { return pow(in, 8); });
    cout << "Precise result: " << endl;
    print_vector(precise_result);
}

void example_ckks_basics_iii()
{
    print_example_banner("Example: CKKS Basics III");

    /*
    In this example we demonstrate evaluating a polynomial function on
    floating-point input data. The challenges we encounter will be related to
    matching scales and encryption parameters when adding together terms of
    different degrees in the polynomial evaluation. We start by setting up an
    environment similar to what we had in the above examples.
    */
    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(8192);

    /*
    In this example we decide to use four 40-bit moduli for more flexible 
    rescaling. Note that 4*40 bits = 160 bits, which is well below the size of 
    the default coefficient modulus (see seal/util/globals.cpp). It is always
    more secure to use a smaller coefficient modulus while keeping the degree of
    the polynomial modulus fixed. Since the coeff_mod_128(8192) default 218-bit 
    coefficient modulus achieves already a 128-bit security level, this 160-bit 
    modulus must be much more secure.

    We use the DefaultParams::small_mods_40bit(int) function to get primes from 
    a hard-coded list of 40-bit prime numbers; it is important that all primes 
    used for the coefficient modulus are distinct.
    */
    parms.set_coeff_modulus({
        DefaultParams::small_mods_40bit(0), 
        DefaultParams::small_mods_40bit(1),
        DefaultParams::small_mods_40bit(2), 
        DefaultParams::small_mods_40bit(3) });

    auto context = SEALContext::Create(parms);
    print_parameters(context);

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys(DefaultParams::dbc_max());

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    /*
    In this example our goal is to evaluate the polynomial PI*x^3 + 0.4x + 1 on 
    an encrypted input x for 4096 equidistant points x in the interval [0, 1]. 
    */
    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0, step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);
    cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 ..." << endl << endl;

    /*
    Now encode and encrypt the input using the last of the coeff_modulus primes 
    as the scale for a reason that will become clear soon.
    */
    auto scale = static_cast<double>(parms.coeff_modulus().back().value());
    Plaintext plain_x;
    encoder.encode(input, scale, plain_x);
    Ciphertext encrypted_x1;
    encryptor.encrypt(plain_x, encrypted_x1);

    /*
    We create plaintext elements for PI, 0.4, and 1, using an overload of
    CKKSEncoder::encode(...) that encodes the given floating-point value to
    every slot in the vector.
    */
    Plaintext plain_coeff3, plain_coeff1, plain_coeff0;
    encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, scale, plain_coeff1);
    encoder.encode(1.0, scale, plain_coeff0);

    /*
    To compute x^3 we first compute x^2, relinearize, and rescale.
    */
    Ciphertext encrypted_x3;
    evaluator.square(encrypted_x1, encrypted_x3);
    evaluator.relinearize_inplace(encrypted_x3, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_x3);

    /*
    Now encrypted_x3 is at different encryption parameters than encrypted_x1, 
    preventing us from multiplying them together to compute x^3. We could simply 
    switch encrypted_x1 down to the next parameters in the modulus switching 
    chain. Since we still need to multiply the x^3 term with PI (plain_coeff3), 
    we instead compute PI*x first and multiply that with x^2 to obtain PI*x^3.
    This product poses no problems since both inputs are at the same scale and 
    use the same encryption parameters. We rescale afterwards to change the 
    scale back to 40 bits, which will also drop the coefficient modulus down to 
    120 bits. 
    */
    Ciphertext encrypted_x1_coeff3;
    evaluator.multiply_plain(encrypted_x1, plain_coeff3, encrypted_x1_coeff3);
    evaluator.rescale_to_next_inplace(encrypted_x1_coeff3);

    /*
    Since both encrypted_x3 and encrypted_x1_coeff3 now have the same scale and 
    use same encryption parameters, we can multiply them together. We write the 
    result to encrypted_x3.
    */
    evaluator.multiply_inplace(encrypted_x3, encrypted_x1_coeff3);
    evaluator.relinearize_inplace(encrypted_x3, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_x3);

    /*
    Next we compute the degree one term. All this requires is one multiply_plain 
    with plain_coeff1. We overwrite encrypted_x1 with the result.
    */
    evaluator.multiply_plain_inplace(encrypted_x1, plain_coeff1);
    evaluator.rescale_to_next_inplace(encrypted_x1);

    /*
    Now we would hope to compute the sum of all three terms. However, there is 
    a serious problem: the encryption parameters used by all three terms are 
    different due to modulus switching from rescaling. 
    */
    cout << "Parameters used by all three terms are different:" << endl;
    cout << "Modulus chain index for encrypted_x3: "
        << context->context_data(encrypted_x3.parms_id())->chain_index() << endl;
    cout << "Modulus chain index for encrypted_x1: "
        << context->context_data(encrypted_x1.parms_id())->chain_index() << endl;
    cout << "Modulus chain index for plain_coeff0: "
        << context->context_data(plain_coeff0.parms_id())->chain_index() << endl;
    cout << endl;

    /*
    Let us carefully consider what the scales are at this point. If we denote 
    the primes in coeff_modulus as q1, q2, q3, q4 (order matters here), then all
    fresh encodings start with a scale equal to q4 (this was a choice we made 
    above). After the computations above the scale in encrypted_x3 is q4^2/q3:

        * The product x^2 has scale q4^2;
        * The produt PI*x has scale q4^2;
        * Rescaling both of these by q4 (last prime) results in scale q4; 
        * Multiplication to obtain PI*x^3 raises the scale to q4^2;
        * Rescaling by q3 (last prime) yields a scale of q4^2/q3.

    The scale in both encrypted_x1 and plain_coeff0 is just q4.
    */
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "Scale in encrypted_x3: " << encrypted_x3.scale() << endl;
    cout << "Scale in encrypted_x1: " << encrypted_x1.scale() << endl;
    cout << "Scale in plain_coeff0: " << plain_coeff0.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt);

    /*
    There are a couple of ways to fix this this problem. Since q4 and q3 are 
    really close to each other, we could simply "lie" to Microsoft SEAL and set 
    the scales to be the same. For example, changing the scale of encrypted_x3 to 
    be q4 simply means that we scale the value of encrypted_x3 by q4/q3 which is 
    very close to 1; this should not result in any noticeable error. 
    
    Another option would be to encode 1 with scale q4, perform a multiply_plain 
    with encrypted_x1, and finally rescale. In this case we would additionally 
    make sure to encode 1 with the appropriate encryption parameters (parms_id). 
    
    A third option would be to initially encode plain_coeff1 with scale q4^2/q3. 
    Then, after multiplication with encrypted_x1 and rescaling, the result would 
    have scale q4^2/q3. Since encoding can be computationally costly, this may 
    not be a realistic option in some cases.
    
    In this example we will use the first (simplest) approach and simply change
    the scale of encrypted_x3.
    */
    encrypted_x3.scale() = encrypted_x1.scale();

    /*
    We still have a problem with mismatching encryption parameters. This is easy
    to fix by using traditional modulus switching (no rescaling). Note that we
    use here the Evaluator::mod_switch_to_inplace(...) function to switch to
    encryption parameters down the chain with a specific parms_id.
    */
    evaluator.mod_switch_to_inplace(encrypted_x1, encrypted_x3.parms_id());
    evaluator.mod_switch_to_inplace(plain_coeff0, encrypted_x3.parms_id());

    /*
    All three ciphertexts are now compatible and can be added.
    */
    Ciphertext encrypted_result;
    evaluator.add(encrypted_x3, encrypted_x1, encrypted_result);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0);

    /*
    Print the chain index and scale for encrypted_result. 
    */
    cout << "Modulus chain index for encrypted_result: "
        << context->context_data(encrypted_result.parms_id())
        ->chain_index() << endl;
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "Scale in encrypted_result: " << encrypted_result.scale();
    cout.copyfmt(old_fmt);
    cout << " (" << log2(encrypted_result.scale()) << " bits)" << endl;

    /*
    We decrypt, decode, and print the result.
    */
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "Result of PI*x^3 + 0.4x + 1:" << endl;
    print_vector(result, 3, 7);

    /*
    At this point if we wanted to multiply encrypted_result one more time, the 
    other multiplicand would have to have scale less than 40 bits, otherwise 
    the scale would become larger than the coeff_modulus itself. 
    */
    cout << "Current coeff_modulus size for encrypted_result: "
        << context->context_data(encrypted_result.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl << endl; 
    
    /*
    A very extreme case for multiplication is where we multiply a ciphertext 
    with a vector of values that are all the same integer. For example, let us 
    multiply encrypted_result by 7. In this case we do not need any scaling in 
    the multiplicand due to a different (much simpler) encoding process.
    */
    Plaintext plain_integer_scalar;
    encoder.encode(7, encrypted_result.parms_id(), plain_integer_scalar);
    evaluator.multiply_plain_inplace(encrypted_result, plain_integer_scalar);

    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "Scale in plain_integer_scalar scale: " 
        << plain_integer_scalar.scale() << endl;
    cout << "Scale in encrypted_result: " << encrypted_result.scale() << endl;
    cout.copyfmt(old_fmt);

    /*
    We decrypt, decode, and print the result.
    */
    decryptor.decrypt(encrypted_result, plain_result);
    encoder.decode(plain_result, result);
    cout << "Result of 7 * (PI*x^3 + 0.4x + 1):" << endl;
    print_vector(result, 3, 7);

    /*
    Finally, we show how to apply vector rotations on the encrypted data. This
    is very similar to how matrix rotations work in the BFV scheme. We try this
    with three sizes of Galois keys. In some cases it is desirable for memory
    reasons to create Galois keys that support only specific rotations. This can
    be done by passing to KeyGenerator::galois_keys(...) a vector of signed 
    integers specifying the desired rotation step counts. Here we create Galois
    keys that only allow cyclic rotation by a single step (at a time) to the left.
    */
    auto gal_keys30 = keygen.galois_keys(30, vector<int>{ 1 });
    auto gal_keys15 = keygen.galois_keys(15, vector<int>{ 1 });

    Ciphertext rotated_result;
    evaluator.rotate_vector(encrypted_result, 1, gal_keys15, rotated_result); 
    decryptor.decrypt(rotated_result, plain_result);
    encoder.decode(plain_result, result);
    cout << "Result rotated with dbc 15:" << endl;
    print_vector(result, 3, 7);

    evaluator.rotate_vector(encrypted_result, 1, gal_keys30, rotated_result); 
    decryptor.decrypt(rotated_result, plain_result);
    encoder.decode(plain_result, result);
    cout << "Result rotated with dbc 30:" << endl;
    print_vector(result, 3, 5);

    /*
    We notice that the using the smallest decomposition bit count introduces 
    the least amount of error in the result. The problem is that our scale at 
    this point is very small -- only 40 bits -- so a rotation with decomposition 
    bit count 30 or bigger already destroys most or all of the message bits. 
    Ideally rotations would be performed right after multiplications before any
    rescaling takes place. This way the scale is as large as possible and the
    additive noise coming from the rotation (or relinearization) will be totally
    shadowed by the large scale, and subsequently scaled down by the following 
    rescaling. Of course this may not always be possible to arrange.

    We did not show any computations on complex numbers in these examples, but
    the CKKSEncoder would allow us to have done that just as easily. Additions
    and multiplications behave just as one would expect. It is also possible
    to complex conjugate the values in a ciphertext by using the functions
    Evaluator::complex_conjugate[_inplace](...).
    */
}

void example_ckks_performance()
{
    print_example_banner("Example: CKKS Performance Test");

    /*
    In this example we time all the basic operations. We use the following 
    lambda function to run the test. This is largely similar to the function
    in the previous example.
    */
    auto performance_test = [](auto context)
    {
        chrono::high_resolution_clock::time_point time_start, time_end;

        print_parameters(context);
        auto &curr_parms = context->context_data()->parms();
        size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

        cout << "Generating secret/public keys: ";
        KeyGenerator keygen(context);
        cout << "Done" << endl;

        auto secret_key = keygen.secret_key();
        auto public_key = keygen.public_key();

        int dbc = DefaultParams::dbc_max();
        cout << "Generating relinearization keys (dbc = " << dbc << "): ";
        time_start = chrono::high_resolution_clock::now();
        auto relin_keys = keygen.relin_keys(dbc);
        time_end = chrono::high_resolution_clock::now();
        auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        if (!context->context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }
        cout << "Generating Galois keys (dbc = " << dbc << "): ";
        time_start = chrono::high_resolution_clock::now();
        auto gal_keys = keygen.galois_keys(dbc);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        Encryptor encryptor(context, public_key);
        Decryptor decryptor(context, secret_key);
        Evaluator evaluator(context);
        CKKSEncoder ckks_encoder(context);

        chrono::microseconds time_encode_sum(0);
        chrono::microseconds time_decode_sum(0);
        chrono::microseconds time_encrypt_sum(0);
        chrono::microseconds time_decrypt_sum(0);
        chrono::microseconds time_add_sum(0);
        chrono::microseconds time_multiply_sum(0);
        chrono::microseconds time_multiply_plain_sum(0);
        chrono::microseconds time_square_sum(0);
        chrono::microseconds time_relinearize_sum(0);
        chrono::microseconds time_rescale_sum(0);
        chrono::microseconds time_rotate_one_step_sum(0);
        chrono::microseconds time_rotate_random_sum(0);
        chrono::microseconds time_conjugate_sum(0);

        /*
        How many times to run the test?
        */
        int count = 10;

        /*
        Populate a vector of floating-point values to batch.
        */
        vector<double> pod_vector;
        random_device rd;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            pod_vector.push_back(1.001 * static_cast<double>(i));
        }

        cout << "Running tests ";
        for (int i = 0; i < count; i++)
        {
            /*
            [Encoding]
            */
            Plaintext plain(curr_parms.poly_modulus_degree() * 
                curr_parms.coeff_modulus().size(), 0);
            time_start = chrono::high_resolution_clock::now();
            ckks_encoder.encode(pod_vector, 
                static_cast<double>(curr_parms.coeff_modulus().back().value()), plain);
            time_end = chrono::high_resolution_clock::now();
            time_encode_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Decoding]
            */
            vector<double> pod_vector2(ckks_encoder.slot_count());
            time_start = chrono::high_resolution_clock::now();
            ckks_encoder.decode(plain, pod_vector2);
            time_end = chrono::high_resolution_clock::now();
            time_decode_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Encryption]
            */
            Ciphertext encrypted(context);
            time_start = chrono::high_resolution_clock::now();
            encryptor.encrypt(plain, encrypted);
            time_end = chrono::high_resolution_clock::now();
            time_encrypt_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Decryption]
            */
            Plaintext plain2(poly_modulus_degree, 0);
            time_start = chrono::high_resolution_clock::now();
            decryptor.decrypt(encrypted, plain2);
            time_end = chrono::high_resolution_clock::now();
            time_decrypt_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Add]
            */
            Ciphertext encrypted1(context);
            ckks_encoder.encode(i + 1, plain);
            encryptor.encrypt(plain, encrypted1);
            Ciphertext encrypted2(context);
            ckks_encoder.encode(i + 1, plain2);
            encryptor.encrypt(plain2, encrypted2);
            time_start = chrono::high_resolution_clock::now();
            evaluator.add_inplace(encrypted1, encrypted1);
            evaluator.add_inplace(encrypted2, encrypted2);
            evaluator.add_inplace(encrypted1, encrypted2);
            time_end = chrono::high_resolution_clock::now();
            time_add_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) / 3;

            /*
            [Multiply]
            */
            encrypted1.reserve(3);
            time_start = chrono::high_resolution_clock::now();
            evaluator.multiply_inplace(encrypted1, encrypted2);
            time_end = chrono::high_resolution_clock::now();
            time_multiply_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Multiply Plain]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.multiply_plain_inplace(encrypted2, plain);
            time_end = chrono::high_resolution_clock::now();
            time_multiply_plain_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Square]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.square_inplace(encrypted2);
            time_end = chrono::high_resolution_clock::now();
            time_square_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Relinearize]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.relinearize_inplace(encrypted1, relin_keys);
            time_end = chrono::high_resolution_clock::now();
            time_relinearize_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Rescale]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.rescale_to_next_inplace(encrypted1);
            time_end = chrono::high_resolution_clock::now();
            time_rescale_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Rotate Vector]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.rotate_vector_inplace(encrypted, 1, gal_keys);
            evaluator.rotate_vector_inplace(encrypted, -1, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_rotate_one_step_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) / 2;

            /*
            [Rotate Vector Random]
            */
            int random_rotation = static_cast<int>(rd() % ckks_encoder.slot_count());
            time_start = chrono::high_resolution_clock::now();
            evaluator.rotate_vector_inplace(encrypted, random_rotation, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_rotate_random_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Complex Conjugate]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.complex_conjugate_inplace(encrypted, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_conjugate_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            Print a dot to indicate progress.
            */
            cout << ".";
            cout.flush();
        }

        cout << " Done" << endl << endl;
        cout.flush();

        auto avg_encode = time_encode_sum.count() / count;
        auto avg_decode = time_decode_sum.count() / count;
        auto avg_encrypt = time_encrypt_sum.count() / count;
        auto avg_decrypt = time_decrypt_sum.count() / count;
        auto avg_add = time_add_sum.count() / count;
        auto avg_multiply = time_multiply_sum.count() / count;
        auto avg_multiply_plain = time_multiply_plain_sum.count() / count;
        auto avg_square = time_square_sum.count() / count;
        auto avg_relinearize = time_relinearize_sum.count() / count;
        auto avg_rescale = time_rescale_sum.count() / count;
        auto avg_rotate_one_step = time_rotate_one_step_sum.count() / count;
        auto avg_rotate_random = time_rotate_random_sum.count() / count;
        auto avg_conjugate = time_conjugate_sum.count() / count;

        cout << "Average encode: " << avg_encode << " microseconds" << endl;
        cout << "Average decode: " << avg_decode << " microseconds" << endl;
        cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
        cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
        cout << "Average add: " << avg_add << " microseconds" << endl;
        cout << "Average multiply: " << avg_multiply << " microseconds" << endl;
        cout << "Average multiply plain: " << avg_multiply_plain << " microseconds" << endl;
        cout << "Average square: " << avg_square << " microseconds" << endl;
        cout << "Average relinearize: " << avg_relinearize << " microseconds" << endl;
        cout << "Average rescale: " << avg_rescale << " microseconds" << endl;
        cout << "Average rotate vector one step: " << avg_rotate_one_step << " microseconds" << endl;
        cout << "Average rotate vector random: " << avg_rotate_random << " microseconds" << endl;
        cout << "Average complex conjugate: " << avg_conjugate << " microseconds" << endl;
        cout.flush();
    };

    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(4096);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(4096));
    performance_test(SEALContext::Create(parms));

    cout << endl;
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));
    performance_test(SEALContext::Create(parms));

    cout << endl;
    parms.set_poly_modulus_degree(16384);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(16384));
    performance_test(SEALContext::Create(parms));

    /*
    Comment out the following to run the biggest example.
    */
    // cout << endl;
    // parms.set_poly_modulus_degree(32768);
    // parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(32768));
    // performance_test(SEALContext::Create(parms));
}