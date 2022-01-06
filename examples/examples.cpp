#include <iostream>

#include "examples.h"

int main()
{
    std::cout << "start" << std::endl;

    /*
    In this example, we demonstrate performing simple computations (a polynomial
    evaluation) on encrypted integers using the BFV encryption scheme.

    The first task is to set up an instance of the EncryptionParameters class.
    It is critical to understand how the different parameters behave, how they
    affect the encryption scheme, performance, and the security level. There are
    three encryption parameters that are necessary to set:

        - poly_modulus_degree (degree of polynomial modulus);
        - coeff_modulus ([ciphertext] coefficient modulus);
        - plain_modulus (plaintext modulus; only for the BFV scheme).

    The BFV scheme cannot perform arbitrary computations on encrypted data.
    Instead, each ciphertext has a specific quantity called the `invariant noise
    budget' -- or `noise budget' for short -- measured in bits. The noise budget
    in a freshly encrypted ciphertext (initial noise budget) is determined by
    the encryption parameters. Homomorphic operations consume the noise budget
    at a rate also determined by the encryption parameters. In BFV the two basic
    operations allowed on encrypted data are additions and multiplications, of
    which additions can generally be thought of as being nearly free in terms of
    noise budget consumption compared to multiplications. Since noise budget
    consumption compounds in sequential multiplications, the most significant
    factor in choosing appropriate encryption parameters is the multiplicative
    depth of the arithmetic circuit that the user wants to evaluate on encrypted
    data. Once the noise budget of a ciphertext reaches zero it becomes too
    corrupted to be decrypted. Thus, it is essential to choose the parameters to
    be large enough to support the desired computation; otherwise the result is
    impossible to make sense of even with the secret key.
    */
    // Brakerski/Fan-Vercauteren scheme
    // BFV = 0x1,
    // Cheon-Kim-Kim-Song scheme
    // CKKS = 0x2
    void *parms;
    EncParams_Create1(0x1, &parms);

    /*
    The first parameter we set is the degree of the `polynomial modulus'. This
    must be a positive power of 2, representing the degree of a power-of-two
    cyclotomic polynomial; it is not necessary to understand what this means.

    Larger poly_modulus_degree makes ciphertext sizes larger and all operations
    slower, but enables more complicated encrypted computations. Recommended
    values are 1024, 2048, 4096, 8192, 16384, 32768, but it is also possible
    to go beyond this range.

    In this example we use a relatively small polynomial modulus. Anything
    smaller than this will enable only very restricted encrypted computations.
    */
    size_t poly_modulus_degree = 4096;
    EncParams_SetPolyModulusDegree(parms, poly_modulus_degree);
    // std::cout << "Polynomial Modulus degree set to " << poly_modulus_degree << std::endl;

    uint64_t degree;
    EncParams_GetPolyModulusDegree(parms, &degree);
    std::cout << "Polynomial Modulus degree set to " << degree << std::endl;

    /*
    Next we set the [ciphertext] `coefficient modulus' (coeff_modulus). This
    parameter is a large integer, which is a product of distinct prime numbers,
    each up to 60 bits in size. It is represented as a vector of these prime
    numbers, each represented by an instance of the SmallModulus class. The
    bit-length of coeff_modulus means the sum of the bit-lengths of its prime
    factors.

    A larger coeff_modulus implies a larger noise budget, hence more encrypted
    computation capabilities. However, an upper bound for the total bit-length
    of the coeff_modulus is determined by the poly_modulus_degree, as follows:

        +----------------------------------------------------+
        | poly_modulus_degree | max coeff_modulus bit-length |
        +---------------------+------------------------------+
        | 1024                | 27                           |
        | 2048                | 54                           |
        | 4096                | 109                          |
        | 8192                | 218                          |
        | 16384               | 438                          |
        | 32768               | 881                          |
        +---------------------+------------------------------+

    These numbers can also be found in native/src/seal/util/hestdparms.h encoded
    in the function SEAL_HE_STD_PARMS_128_TC, and can also be obtained from the
    function

        CoeffModulus::MaxBitCount(poly_modulus_degree).

    For example, if poly_modulus_degree is 4096, the coeff_modulus could consist
    of three 36-bit primes (108 bits).

    Microsoft SEAL comes with helper functions for selecting the coeff_modulus.
    For new users the easiest way is to simply use

        CoeffModulus::BFVDefault(poly_modulus_degree),

    which returns std::vector<SmallModulus> consisting of a generally good choice
    for the given poly_modulus_degree.
    */
    int sec_level = 128;
    //first retrieve the size
    int bit_count = 0;
    CoeffModulus_MaxBitCount(poly_modulus_degree, sec_level, &bit_count);
    std::cout << "bit count: " << bit_count << std::endl;
    uint64_t coeffs_length = 0;
    void *coeffs[15]; //this should be enough to hold pointers to 15 * 60 bits = 900 bits
    CoeffModulus_BFVDefault(poly_modulus_degree, sec_level, &coeffs_length, (void **)coeffs);
    std::cout << "coeffs length 1: " << coeffs_length << std::endl;
    // EncParams_GetCoeffModulus(parms, &coeffs_length, coeffs);
    // std::cout << "coeffs length 2: " << coeffs_length << std::endl;

    EncParams_SetCoeffModulus(parms, coeffs_length, coeffs);
    std::cout << "coeff modulus set at " << coeffs_length << "x" << (bit_count / 3) << " bits" << std::endl;

    /*
    The plaintext modulus can be any positive integer, even though here we take
    it to be a power of two. In fact, in many cases one might instead want it
    to be a prime number; we will see this in later examples. The plaintext
    modulus determines the size of the plaintext data type and the consumption
    of noise budget in multiplications. Thus, it is essential to try to keep the
    plaintext data type as small as possible for best performance. The noise
    budget in a freshly encrypted ciphertext is

        ~ log2(coeff_modulus/plain_modulus) (bits)

    and the noise budget consumption in a homomorphic multiplication is of the
    form log2(plain_modulus) + (other terms).

    The plaintext modulus is specific to the BFV scheme, and cannot be set when
    using the CKKS scheme.
    */
    EncParams_SetPlainModulus2(parms, 1024);

    /*
    Now that all parameters are set, we are ready to construct a SEALContext
    object. This is a heavy class that checks the validity and properties of the
    parameters we just set.
    */
    // auto context = SEALContext::Create(parms);
    //expand_mod_chain Determines whether the modulus switching chain should be created
    bool expand_mod_chain = 1;
    void *context;
    SEALContext_Create(parms, expand_mod_chain, sec_level, &context);
    std::cout << "SEAL context created" << std::endl;

    /*
    The encryption schemes in Microsoft SEAL are public key encryption schemes.
    For users unfamiliar with this terminology, a public key encryption scheme
    has a separate public key for encrypting data, and a separate secret key for
    decrypting data. This way multiple parties can encrypt data using the same
    shared public key, but only the proper recipient of the data can decrypt it
    with the secret key.

    We are now ready to generate the secret and public keys. For this purpose
    we need an instance of the KeyGenerator class. Constructing a KeyGenerator
    automatically generates the public and secret key, which can immediately be
    read to local variables.
    */
    // KeyGenerator keygen(context);
    // PublicKey public_key = keygen.public_key();
    // SecretKey secret_key = keygen.secret_key();
    void *key_generator;
    KeyGenerator_Create1(context, &key_generator);

    void *public_key;
    KeyGenerator_PublicKey(key_generator, &public_key);

    void *secret_key;
    KeyGenerator_SecretKey(key_generator, &secret_key);

    std::cout << "generated public and private keys" << std::endl;

    /*
    `Relinearization' is an operation that reduces the size of a ciphertext after
    multiplication back to the initial size, 2. Thus, relinearizing one or both
    input ciphertexts before the next multiplication can have a huge positive
    impact on both noise growth and performance, even though relinearization has
    a significant computational cost itself. It is only possible to relinearize
    size 3 ciphertexts down to size 2, so often the user would want to relinearize
    after each multiplication to keep the ciphertext sizes at 2.

    Relinearization requires special `relinearization keys', which can be thought
    of as a kind of public key. Relinearization keys can easily be created with
    the KeyGenerator.

    Relinearization is used similarly in both the BFV and the CKKS schemes, but
    in this example we continue using BFV. We repeat our computation from before,
    but this time relinearize after every multiplication.

    We use KeyGenerator::relin_keys() to create relinearization keys.
    */
    void *relin_keys;
    KeyGenerator_RelinKeys(key_generator, false, &relin_keys);

    /*
    To be able to encrypt we need to construct an instance of Encryptor. Note
    that the Encryptor only requires the public key, as expected.
    */
    // Encryptor encryptor(context, public_key);
    void *encryptor;
    Encryptor_Create(context, public_key, secret_key, &encryptor);

    /*
    Computations on the ciphertexts are performed with the Evaluator class. In
    a real use-case the Evaluator would not be constructed by the same party
    that holds the secret key.
    */
    // Evaluator evaluator(context);
    void *evaluator;
    Evaluator_Create(context, &evaluator);

    /*
    We will of course want to decrypt our results to verify that everything worked,
    so we need to also construct an instance of Decryptor. Note that the Decryptor
    requires the secret key.
    */
    // Decryptor decryptor(context, secret_key);
    void *decryptor;
    Decryptor_Create(context, secret_key, &decryptor);

    std::cout << "set-up phase completed" << std::endl;

    /*
    Plaintexts in the BFV scheme are polynomials of degree less than the degree
    of the polynomial modulus, and coefficients integers modulo the plaintext
    modulus. For readers with background in ring theory, the plaintext space is
    the polynomial quotient ring Z_T[X]/(X^N + 1), where N is poly_modulus_degree
    and T is plain_modulus.

    To get started, we create a plaintext containing the constant 6. For the
    plaintext element we use a constructor that takes the desired polynomial as
    a string with coefficients represented as hexadecimal numbers.
    */
    uint64_t value = 6;
    void *memory_pool;
    // MemoryPoolHandle_Create1(&memory_pool);
    MemoryManager_GetPool2(&memory_pool);
    void *plain_text;
    Plaintext_Create1(memory_pool, &plain_text);
    Plaintext_Set3(plain_text, value);

    /*
    We then encrypt the plaintext, producing a ciphertext.
    */
    void *cipher_text;
    Ciphertext_Create1(memory_pool, &cipher_text);
    Encryptor_Encrypt(encryptor, plain_text, cipher_text, memory_pool);

    /*
   Check the decryption of the cipher text
   */
    void *plain_text_verify;
    Plaintext_Create1(memory_pool, &plain_text_verify);
    Decryptor_Decrypt(decryptor, cipher_text, plain_text_verify);
    uint64_t coeff_verify;
    Plaintext_CoeffAt(plain_text_verify, 0, &coeff_verify);
    Plaintext_Destroy(plain_text_verify);
    std::cout << "clear text original: " << value << ", decrypted: " << coeff_verify << std::endl;

    /**
     * Clean Uo
     */
    Ciphertext_Destroy(cipher_text);
    Plaintext_Destroy(plain_text);
    MemoryPoolHandle_Destroy(memory_pool);
    Decryptor_Destroy(decryptor);
    Evaluator_Destroy(evaluator);
    Encryptor_Destroy(encryptor);
    KeyGenerator_Destroy(key_generator);
    SEALContext_Destroy(context);
    EncParams_Destroy(parms);
}