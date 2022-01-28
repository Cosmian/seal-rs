use std::time::Instant;

use anyhow::Result;
use rand::{thread_rng, Rng};
use tracing::debug;

use super::*;

#[test]
/// See 'fn mul_plain' in 'evaluator.rs'
fn test_transparent() -> Result<()> {
    let params = Params::create(SCHEME_CKKS)?;
    params.set_poly_modulus_degree(8192)?;
    let mut bits_sizes = vec![60, 30, 30, 30, 60]; // sum is 140
    params.set_coeff_modulus_ckks(&mut bits_sizes)?;
    let context = Context::create(params, 128u8, true)?;

    let scale = 2.0_f64.powi(40);
    // Key Generation
    let key_generator = KeyGenerator::create(&context)?;
    let secret_key = key_generator.secret_key()?;
    let public_key = key_generator.public_key()?;
    // encryption
    let encryptor = Encryptor::create(&context, &public_key, &secret_key)?;

    // Encoder
    let mut ckks_encoder = CKKSEncoder::create(&context)?;
    let slot_count = ckks_encoder.slot_count()?;

    let price_opt = 127;
    let mut price_input = vec![0.0_f64; slot_count];
    price_input[price_opt] = 1.0;

    let price_opt_plain = ckks_encoder.encode(&mut price_input, &scale)?;
    let price_opt_encrypted = encryptor.encrypt(&price_opt_plain)?;
    let evaluator = Evaluator::create(&context)?;

    let mut kwh_cost = vec![0.0];
    kwh_cost.resize(slot_count, 0.0);
    let kwh_cost_plain = ckks_encoder.encode(&mut kwh_cost, &scale)?;

    // must failed due to transparency
    let enc_cost = evaluator.mul_plain(&price_opt_encrypted, &kwh_cost_plain);
    assert_eq!(
        enc_cost.err().unwrap().to_string(),
        "Transparent output: plaintext must be non zero"
    );
    Ok(())
}

#[test]
/// See https://github.com/microsoft/SEAL/blob/master/native/examples/4_ckks_basics.cpp
fn test_ckks_valoconso() -> Result<()> {
    let params = Params::create(SCHEME_CKKS)?;
    params.set_poly_modulus_degree(8192)?;
    //assert_eq!(8192 * 2, params.get_poly_modulus_degree()?);
    // nb mul + 2
    let mut bits_sizes = vec![60, 30, 30, 30, 60]; // sum is 140
    params.set_coeff_modulus_ckks(&mut bits_sizes)?;
    let context = Context::create(params, 128u8, true)?;
    let primes = context.get_coeff_modulus()?;
    debug!("{:?}", primes);
    let p_0 = primes[3] as f64;
    let p_1 = primes[2] as f64;
    let p_2 = primes[1] as f64;

    let scale = 2.0_f64.powi(40);
    // Key Generation
    let key_generator = KeyGenerator::create(&context)?;
    let public_key = key_generator.public_key()?;
    let secret_key = key_generator.secret_key()?;
    let relinearization_keys = key_generator.relinearization_keys()?;
    let galois_keys = key_generator.galois_keys()?;
    // encryption // decryption
    let encryptor = Encryptor::create(&context, &public_key, &secret_key)?;
    let decryptor = Decryptor::create(&context, &secret_key)?;

    // Encoder
    let mut ckks_encoder = CKKSEncoder::create(&context)?;
    let slot_count = ckks_encoder.slot_count()?;
    debug!("Number of slots: {}", slot_count);

    //***
    // Provider Side
    //***
    let subscr_opt = 15;
    let mut subscr_input = vec![0.0_f64; slot_count];
    subscr_input[subscr_opt] = 1.0;

    let price_opt = 127;
    let mut price_input = vec![0.0_f64; slot_count];
    price_input[price_opt] = 1.0;

    // let mut conso = vec![
    //     1.998, 2.998, 3.998, 4.998, 5.998, 6.998, 7.998, 8.998, 9.998, 10.998,
    // 11.998, 12.998,     13.998, 14.998, 15.998, 16.998, 17.998, 18.998,
    // 19.998, 20.998, 21.998, 22.998, 23.998,     24.998, 25.998, 26.998,
    // 27.998, 28.998, 29.998, 30.998, 31.998, ];
    // use max_value to test overflow
    let mut conso = vec![
        99.999, 99.999, 99.999, 99.999, 99.999, 99.999, 99.999, 99.999, 99.999, 99.999, 99.999,
        99.999, 99.999, 99.999, 99.999, 99.999, 99.999, 99.999, 99.999, 99.999, 99.999, 99.999,
        99.999, 99.999, 99.999, 99.999, 99.999, 99.999, 99.999, 99.999, 99.999,
    ];
    conso.resize(slot_count, 0.0);

    let subscr_opt_plain = ckks_encoder.encode(&mut subscr_input, &p_0)?;
    let subscr_opt_encrypted = encryptor.encrypt(&subscr_opt_plain)?;

    let price_opt_plain = ckks_encoder.encode(&mut price_input, &p_0)?;
    let price_opt_encrypted = encryptor.encrypt(&price_opt_plain)?;

    let conso_plain = ckks_encoder.encode(&mut conso, &p_1)?;
    let conso_encrypted = encryptor.encrypt(&conso_plain)?;

    //***
    // EDF Side
    //***
    // Operations on cipher text - create an evaluator
    let evaluator = Evaluator::create(&context)?;

    let mut subscr_fee = vec![
        11.11_f64, 22.22, 33.33, 44.44, 55.55, 66.66, 77.77, 88.88, 1.11, 2.22, 3.33, 4.44, 5.55,
        6.66, 7.77, 99.99,
    ];
    subscr_fee.resize(slot_count, 0.0);
    let subscr_fee_plain = ckks_encoder.encode(&mut subscr_fee, &scale)?;

    let mut kwh_cost = vec![
        0.1_f64, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.10, 0.11, 0.12, 0.13, 0.14, 0.15, 0.16,
        0.17, 0.18, 0.19, 0.20, 0.21, 0.22, 0.23, 0.24, 0.25, 0.26, 0.27, 0.28, 0.29, 0.30, 0.31,
        0.32, 0.33, 0.34, 0.35, 0.36, 0.37, 0.38, 0.39, 0.40, 0.41, 0.42, 0.43, 0.44, 0.45, 0.46,
        0.47, 0.48, 0.49, 0.50, 0.51, 0.52, 0.53, 0.54, 0.55, 0.56, 0.57, 0.58, 0.59, 0.60, 0.61,
        0.62, 0.63, 0.64, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.10, 0.11, 0.12, 0.13,
        0.14, 0.15, 0.16, 0.17, 0.18, 0.19, 0.20, 0.21, 0.22, 0.23, 0.24, 0.25, 0.26, 0.27, 0.28,
        0.29, 0.30, 0.31, 0.32, 0.33, 0.34, 0.35, 0.36, 0.37, 0.38, 0.39, 0.40, 0.41, 0.42, 0.43,
        0.44, 0.45, 0.46, 0.47, 0.48, 0.49, 0.50, 0.51, 0.52, 0.53, 0.54, 0.55, 0.56, 0.57, 0.58,
        0.59, 0.60, 0.61, 0.62, 0.63, 0.9999,
    ];
    kwh_cost.resize(slot_count, 0.0);
    let kwh_cost_plain = ckks_encoder.encode(&mut kwh_cost, &scale)?;

    //****
    // For Mul Add
    // Step 0 to Init the accumulator
    debug!("Compute kwh_cost[price_opt] * conso per day:");
    debug!("-- Compute kwh_cost[price_opt]:");
    let mut enc_cost = evaluator.mul_plain(&price_opt_encrypted, &kwh_cost_plain)?;
    enc_cost = evaluator.relinearize(&enc_cost, &relinearization_keys)?;
    enc_cost = evaluator.rescale_to_next(&enc_cost)?;
    debug!("-- sum in first cell");
    let mut step = (slot_count >> 1) as i32;
    while step > 0 {
        let enc_rot = evaluator.rotate(&enc_cost, step, &galois_keys)?;
        enc_cost = evaluator.add(&enc_cost, &enc_rot)?;
        step >>= 1;
    }
    // mul without rescale
    let conso_day = evaluator.mod_switch_to_next(&conso_encrypted)?;
    let mut enc_cost_day = evaluator.mul(&conso_day, &enc_cost)?;
    // Loop
    for day in 1..31 {
        // LUT computation
        debug!("-- Compute kwh_cost[price_opt]:");
        let mut enc_cost = evaluator.mul_plain(&price_opt_encrypted, &kwh_cost_plain)?;
        enc_cost = evaluator.relinearize(&enc_cost, &relinearization_keys)?;
        enc_cost = evaluator.rescale_to_next(&enc_cost)?;
        debug!("-- sum in first cell");
        let mut step = (slot_count >> 1) as i32;
        while step > 0 {
            let enc_rot = evaluator.rotate(&enc_cost, step, &galois_keys)?;
            enc_cost = evaluator.add(&enc_cost, &enc_rot)?;
            step >>= 1;
        }
        // Conso rotate mul
        let conso_day = evaluator.mod_switch_to_next(&conso_encrypted)?;
        let conso_day_curr = evaluator.rotate(&conso_day, day as i32, &galois_keys)?;
        // mul without rescale
        let enc_cost_curr = evaluator.mul(&conso_day_curr, &enc_cost)?;
        // Add
        enc_cost_day = evaluator.add(&enc_cost_day, &enc_cost_curr)?;
    }
    enc_cost_day = evaluator.rescale_to_next(&enc_cost_day)?;

    //kwh_cost[price_opt] : scale = S.P_0/P_0 (= S) / Level 2
    //conso: Scale = P_1 (no rescale, only mod_switch) / Level 1
    //kwh_cost[price_opt] * conso : Scale = S * P_1 / Level 2

    debug!("Compute subscr_fee[subscr_opt]:");
    let mut enc_subscr = evaluator.mul_plain(&subscr_opt_encrypted, &subscr_fee_plain)?;
    debug!("debug {}", enc_subscr.scale()?.log2());
    enc_subscr = evaluator.relinearize(&enc_subscr, &relinearization_keys)?;
    enc_subscr = evaluator.rescale_to_next(&enc_subscr)?;
    debug!("debug {}", enc_subscr.scale()?.log2());
    debug!("sum in first cell");
    let mut step = (slot_count >> 1) as i32;
    while step > 0 {
        let enc_rot = evaluator.rotate(&enc_subscr, step, &galois_keys)?;
        enc_subscr = evaluator.add(&enc_subscr, &enc_rot)?;
        step >>= 1;
    }
    //subscr_fee[subscr_opt] : scale = S.P_0/P_0 (= S) / Level 2
    // enc_cost_day : scale = (S*P_1)/P_1 (=S) / Level 3
    debug!(
        "{} vs {}",
        enc_cost_day.scale()?.log2(),
        enc_subscr.scale()?.log2()
    );
    //enc_cost_day.set_scale(&scale)?;
    //enc_cost_day = evaluator.relinearize(&enc_cost_day, &relinearization_keys)?;
    let enc_subscr = evaluator.mod_switch_to_next(&enc_subscr)?;
    //enc_subscr.set_scale(&scale)?;

    debug!(
        "{} vs {}",
        enc_cost_day.scale()?.log2(),
        enc_subscr.scale()?.log2()
    );
    debug!("Compute kwh_cost[price_opt] * conso per day + subscription_fee:");
    let final_val = evaluator.add(&enc_cost_day, &enc_subscr)?;

    let mut selector = vec![0.0_f64; slot_count];
    selector[0] = 1.0;
    let selector_plain = ckks_encoder.encode(&mut selector, &p_2)?;
    let mut parms = final_val.parms_id()?;
    let selector_plain = evaluator.mod_switch_to_plain_text(&selector_plain, &mut parms)?;
    let final_val = evaluator.mul_plain(&final_val, &selector_plain)?;
    let final_val = evaluator.relinearize(&final_val, &relinearization_keys)?;
    let final_val = evaluator.rescale_to_next(&final_val)?;

    let plain_result = decryptor.decrypt(&enc_cost)?;
    let result = ckks_encoder.decode(&plain_result)?;
    //debug!("result: {:?}", result);
    debug!(
        "kwh_cost[price_opt]: {} vs {}",
        result[0], kwh_cost[price_opt]
    );

    let plain_result = decryptor.decrypt(&enc_subscr)?;
    let result = ckks_encoder.decode(&plain_result)?;
    //debug!("result: {:?}", result);
    debug!(
        "subscr_fee[subscr_opt]: {} vs {}",
        result[0], subscr_fee[subscr_opt]
    );

    let mut total = 0.0;
    for conso_item in conso.iter().take(31) {
        total += kwh_cost[price_opt] * conso_item;
    }
    let plain_result = decryptor.decrypt(&enc_cost_day)?;
    let result = ckks_encoder.decode(&plain_result)?;
    //debug!("result: {:?}", result);
    debug!("total: {} vs {}", result[0], total);

    let plain_result = decryptor.decrypt(&final_val)?;
    let result = ckks_encoder.decode(&plain_result)?;
    //debug!("result: {:?}", result);
    debug!(
        "total + subscr_fee[subscr_opt]: {} vs {}",
        result[0],
        total + subscr_fee[subscr_opt]
    );
    Ok(())
}

#[test]
fn test_bgv_simple() -> Result<()> {
    let params = Params::create(SCHEME_BFV)?;
    let security_level = 128u8;
    params.set_poly_modulus_degree(4096)?;
    assert_eq!(4096, params.get_poly_modulus_degree()?);
    params.set_coeff_modulus(params.bfv_default(security_level)?)?;
    params.set_plain_modulus(1024)?;
    let context = Context::create(params, security_level, true)?;
    // Key Generation
    let key_generator = KeyGenerator::create(&context)?;
    let public_key = key_generator.public_key()?;
    let secret_key = key_generator.secret_key()?;
    let relinearization_keys = key_generator.relinearization_keys()?;
    // encryption // decryption
    let encryptor = Encryptor::create(&context, &public_key, &secret_key)?;
    let decryptor = Decryptor::create(&context, &secret_key)?;
    // create a constant plain text in the thread local memory pool
    let value_a = 6u64;
    let plain_text_a = Plaintext::create_constant(value_a)?;
    let cipher_text_a = encryptor.encrypt(&plain_text_a)?;
    let value_b = 7u64;
    let plain_text_b = Plaintext::create_constant(value_b)?;
    let cipher_text_b = encryptor.encrypt(&plain_text_b)?;
    // check the encryption
    let recovered_a = decryptor.decrypt(&cipher_text_a)?;
    assert_eq!(value_a, recovered_a.coeff_at(0)?);
    let recovered_b = decryptor.decrypt(&cipher_text_b)?;
    assert_eq!(value_b, recovered_b.coeff_at(0)?);
    //
    // Operations on cipher text - create an evaluator
    let evaluator = Evaluator::create(&context)?;
    // test addition of cipher texts
    let ct_a_plus_b = evaluator.add(&cipher_text_a, &cipher_text_b)?;
    assert_eq!(
        value_a + value_b,
        decryptor.decrypt(&ct_a_plus_b)?.coeff_at(0)?
    );
    // test addition with plain
    let ct_a_plus_plain_b = evaluator.add_plain(&cipher_text_a, &plain_text_b)?;
    assert_eq!(
        value_a + value_b,
        decryptor.decrypt(&ct_a_plus_plain_b)?.coeff_at(0)?
    );
    // test multiplication of cipher texts
    let ct_a_mul_b = evaluator.mul(&cipher_text_a, &cipher_text_b)?;
    assert_eq!(
        value_a * value_b,
        decryptor.decrypt(&ct_a_mul_b)?.coeff_at(0)?
    );
    // test multiplication with plain
    let ct_a_mul_plain_b = evaluator.mul_plain(&cipher_text_a, &plain_text_b)?;
    assert_eq!(
        value_a * value_b,
        decryptor.decrypt(&ct_a_mul_plain_b)?.coeff_at(0)?
    );
    // test relinearization
    let ct_a_mul_b_relin = evaluator.relinearize(
        &evaluator.mul(&cipher_text_a, &cipher_text_b)?,
        &relinearization_keys,
    )?;
    assert_eq!(
        value_a * value_b,
        decryptor.decrypt(&ct_a_mul_b_relin)?.coeff_at(0)?
    );

    //done
    Ok(())
}

#[test]
fn test_bgv_batch_encoder() -> Result<()> {
    let params = Params::create(SCHEME_BFV)?;
    let security_level = 128u8;
    let poly_modulus_degree = 4096usize;
    params.set_poly_modulus_degree(poly_modulus_degree)?;
    assert_eq!(poly_modulus_degree, params.get_poly_modulus_degree()?);
    params.set_coeff_modulus(params.bfv_default(security_level)?)?;
    // create a modulus for batching
    let plain_modulus = SmallModulus::for_batching(poly_modulus_degree, 20)?.value()?;
    params.set_plain_modulus(plain_modulus)?;
    debug!("Plain Modulus: {}", plain_modulus);
    let context = Context::create(params, security_level, true)?;
    // Key Generation
    let key_generator = KeyGenerator::create(&context)?;
    let public_key = key_generator.public_key()?;
    let secret_key = key_generator.secret_key()?;
    let relinearization_keys = key_generator.relinearization_keys()?;
    // Batch Encoding
    let batch_encoder = BatchEncoder::create(&context)?;
    let slots = batch_encoder.slot_count()?;
    let row_size = slots / 2;
    debug!("Row size (= 1/2 slot count): {}", row_size);
    // we now have a matrix of 2 rows of row_size columns
    let mut matrix_a: Vec<u64> = Vec::with_capacity(row_size * 2);
    for row in 0..2 {
        for col in 0..row_size {
            matrix_a.push((row * row_size + col) as u64);
        }
    }
    let plain_text_a = batch_encoder.encode(&mut matrix_a)?;
    // check that the plain text decodes properly
    let v = batch_encoder.decode(&plain_text_a)?;
    assert_eq!(matrix_a, v);
    // encode a second plain text
    let mut matrix_b: Vec<u64> = Vec::with_capacity(row_size * 2);
    for row in 0..2 {
        for col in 0..row_size {
            matrix_b.push((row_size * 2 - (row * row_size + col)) as u64);
        }
    }
    let plain_text_b = batch_encoder.encode(&mut matrix_b)?;
    // encode a third plain text
    let mut matrix_c: Vec<u64> = Vec::with_capacity(row_size * 2);
    for row in 0..2 {
        for col in 0..row_size {
            matrix_c.push((row * row_size + col) as u64);
        }
    }
    let plain_text_c = batch_encoder.encode(&mut matrix_c)?;
    // encryption
    let encryptor = Encryptor::create(&context, &public_key, &secret_key)?;
    let cipher_text_a = encryptor.encrypt(&plain_text_a)?;
    // let cipher_text_b = encryptor.encrypt(&plain_text_b)?;
    let cipher_text_c = encryptor.encrypt(&plain_text_c)?;
    // evaluation
    let evaluator = Evaluator::create(&context)?;
    // let cipher_text = evaluator.add(&cipher_text_a, &cipher_text_b)?;
    let cipher_text = evaluator.add_plain(&cipher_text_a, &plain_text_b)?;
    let cipher_text = evaluator.mul(&cipher_text, &cipher_text_c)?;
    let cipher_text = evaluator.relinearize(&cipher_text, &relinearization_keys)?;
    // decipher
    let decryptor = Decryptor::create(&context, &secret_key)?;
    let recovered_plain_text = decryptor.decrypt(&cipher_text)?;
    let w = batch_encoder.decode(&recovered_plain_text)?;
    // debug!("vector: {:?}", &w);
    for (j, ct) in w.iter().enumerate() {
        assert_eq!(
            (slots * j) as u64 % plain_modulus,
            *ct,
            "failed at i = {}",
            j
        );
    }
    Ok(())
}

#[test]
/// See https://github.com/microsoft/SEAL/blob/master/native/examples/2_encoders.cpp
fn test_ckks_simple() -> Result<()> {
    let params = Params::create(SCHEME_CKKS)?;
    params.set_poly_modulus_degree(8192)?;
    assert_eq!(8192, params.get_poly_modulus_degree()?);
    let mut bits_sizes = vec![40, 40, 40, 40, 40];
    params.set_coeff_modulus_ckks(&mut bits_sizes)?;

    // Context
    let context = Context::create(params, 128u8, true)?;

    // Key Generation
    let key_generator = KeyGenerator::create(&context)?;
    let public_key = key_generator.public_key()?;
    let secret_key = key_generator.secret_key()?;
    let relinearization_keys = key_generator.relinearization_keys()?;

    // encryption // decryption
    let encryptor = Encryptor::create(&context, &public_key, &secret_key)?;
    let decryptor = Decryptor::create(&context, &secret_key)?;

    let evaluator = Evaluator::create(&context)?;
    let mut ckks_encoder = CKKSEncoder::create(&context)?;

    let mut input = [0.0, 1.1, 2.2, 3.3];
    let scale = 2.0_f64.powi(30);
    let plain = ckks_encoder.encode(&mut input, &scale)?;
    let _output = ckks_encoder.decode(&plain)?;
    // debug!("Output decoded: {:?}", _output);

    let encrypted = encryptor.encrypt(&plain)?;

    let encrypted = evaluator.square(&encrypted)?;
    let encrypted = evaluator.relinearize(&encrypted, &relinearization_keys)?;

    let plain = decryptor.decrypt(&encrypted)?;
    let output = ckks_encoder.decode(&plain)?;
    // debug!("Output decrypted and decoded: {:?}", output);

    let expected = [0.0, 1.21, 4.84, 10.89];
    let epsilon = 0.0001;
    for (e, o) in expected.iter().zip(output.iter()) {
        assert!((*e - *o).abs() < epsilon);
    }
    Ok(())
}

#[test]
fn test_ckks_sum() -> Result<()> {
    let params = Params::create(SCHEME_CKKS)?;
    params.set_poly_modulus_degree(8192)?;
    assert_eq!(8192, params.get_poly_modulus_degree()?);
    let mut bits_sizes = vec![40, 40, 40, 40, 40];
    params.set_coeff_modulus_ckks(&mut bits_sizes)?;

    // Context
    let context = Context::create(params, 128u8, true)?;

    // Key Generation
    let key_generator = KeyGenerator::create(&context)?;
    let public_key = key_generator.public_key()?;
    let secret_key = key_generator.secret_key()?;
    let relinearization_keys = key_generator.relinearization_keys()?;
    let galois_keys = key_generator.galois_keys()?;

    // encryption // decryption
    let encryptor = Encryptor::create(&context, &public_key, &secret_key)?;
    let decryptor = Decryptor::create(&context, &secret_key)?;
    let evaluator = Evaluator::create(&context)?;
    let mut ckks_encoder = CKKSEncoder::create(&context)?;

    let mut input = [1.0, 2.0, 3.0, 4.0];
    debug!("Input: {:?}", &input);
    let scale = 2.0_f64.powi(40);
    let plain = ckks_encoder.encode(&mut input, &scale)?;
    let _output = ckks_encoder.decode(&plain)?;
    // debug!("Output decoded: {:?}", _output);

    let encrypted_initial = encryptor.encrypt(&plain)?;
    let mut previous = encrypted_initial;
    let max_rotations = input.len() / 2;
    debug!("Computation over {} elements", max_rotations);
    for index in (1..=max_rotations).rev() {
        let encrypted = evaluator.rotate(&previous, index as i32, &galois_keys)?;
        // Debug decrypt
        let plain = decryptor.decrypt(&encrypted)?;
        let output = ckks_encoder.decode(&plain)?;
        debug!("After rotate: {:?}", &output[..4]);
        //
        let encrypted = evaluator.relinearize(&encrypted, &relinearization_keys)?;
        previous = evaluator.add(&encrypted, &previous)?;
        // Debug decrypt
        let plain = decryptor.decrypt(&previous)?;
        let output = ckks_encoder.decode(&plain)?;
        debug!("After add: {:?}", &output[..4]);
        //
    }
    // Doing rotation, don't forget the internal vector is bigger than 4 elements,
    // that's why only the first element matters, are we are sure it has the correct
    // sum.
    let plain = decryptor.decrypt(&previous)?;
    let output = ckks_encoder.decode(&plain)?;
    debug!("expected: {}", (1..=4).sum::<i32>());
    debug!("Output decrypted and decoded: {:?}", &output[..4]);
    let sum = output[0];
    debug!("Sum of input: {:?}", &sum);
    assert!((sum.round() - 10.0_f64).abs() < f64::EPSILON);
    Ok(())
}

#[test]
fn test_ckks_blinded_sum_fast() -> Result<()> {
    ckks_blinded_sum(4, true)?;
    ckks_blinded_sum(100, true)?;
    ckks_blinded_sum(250, true)?;
    // ckks_blinded_sum(500, true)?;
    Ok(())
}

#[test]
#[ignore]
// Real tests are ignored for CI, because they are too slow
fn test_ckks_blinded_sum_real() -> Result<()> {
    ckks_blinded_sum(4, false)?;
    ckks_blinded_sum(100, false)?;
    ckks_blinded_sum(250, false)?;
    // ckks_blinded_sum(500, false)?;
    Ok(())
}

fn ckks_blinded_sum(limit: usize, fast: bool) -> Result<()> {
    let params = Params::create(SCHEME_CKKS)?;
    let poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree)?;
    assert_eq!(poly_modulus_degree, params.get_poly_modulus_degree()?);
    let mut bits_sizes = vec![40, 40, 40, 40, 40];
    params.set_coeff_modulus_ckks(&mut bits_sizes)?;
    let scale = 2.0_f64.powi(40);

    // Context
    let context = Context::create(params, 128u8, true)?;

    // Key Generation
    let key_generator = KeyGenerator::create(&context)?;
    let public_key = key_generator.public_key()?;
    let secret_key = key_generator.secret_key()?;
    let relinearization_keys = key_generator.relinearization_keys()?;
    let galois_keys = key_generator.galois_keys()?;

    // encryption // decryption
    let encryptor = Encryptor::create(&context, &public_key, &secret_key)?;
    let decryptor = Decryptor::create(&context, &secret_key)?;
    let evaluator = Evaluator::create(&context)?;
    let mut ckks_encoder = CKKSEncoder::create(&context)?;

    let max_vector_length = if fast {
        // in fast mode, we set to the size of actual data, but it is not convenient
        // out of test case, because we may reveal input data size
        limit
    } else {
        // underlying vector size used in Ciphertext can be calculated
        // to not reveal size of actual data, we do computation over whole vector
        poly_modulus_degree / 2
    };

    // Vector of zeros to do the sum
    let mut zeros = vec![0.0_f64; max_vector_length];
    let plain_zeros = ckks_encoder.encode(&mut zeros, &scale)?;
    let mut encrypted_zeros = encryptor.encrypt(&plain_zeros)?;

    // [0]=1.0, [1]=2.0...
    let mut input = vec![0.0_f64; max_vector_length];
    // for i in 0..limit {
    for (i, item) in input.iter_mut().enumerate().take(limit) {
        *item = 1.0_f64 + (i as f64);
    }
    debug!("Input: {:?}", &input[..limit]);
    // encrypt
    let plain = ckks_encoder.encode(&mut input, &scale)?;
    let encrypted_input = encryptor.encrypt(&plain)?;
    for index in 0..max_vector_length {
        let encrypted = evaluator.rotate(&encrypted_input, index as i32, &galois_keys)?;
        let encrypted = evaluator.relinearize(&encrypted, &relinearization_keys)?;
        encrypted_zeros = evaluator.add(&encrypted, &encrypted_zeros)?;
    }
    let plain = decryptor.decrypt(&encrypted_zeros)?;
    let output = ckks_encoder.decode(&plain)?;
    let expected = (1..=limit).sum::<usize>() as f64;
    debug!("expected: {}", expected);
    debug!("Output decrypted and decoded: {:?}...", &output[..5]);
    let sum = output[0];
    debug!("Sum of input: {:?}", &sum);
    assert!((sum.round() - expected).abs() < f64::EPSILON);
    Ok(())
}

#[test]
/// See https://github.com/microsoft/SEAL/blob/master/native/examples/4_ckks_basics.cpp
fn test_ckks_polynomial() -> Result<()> {
    let params = Params::create(SCHEME_CKKS)?;
    params.set_poly_modulus_degree(8192)?;
    assert_eq!(8192, params.get_poly_modulus_degree()?);
    let mut bits_sizes = vec![60, 40, 40, 60];
    params.set_coeff_modulus_ckks(&mut bits_sizes)?;

    // We choose the initial scale to be 2^40. At the last level, this leaves us
    // 60-40=20 bits of precision before the decimal point, and enough (roughly
    // 10-20 bits) of precision after the decimal point. Since our intermediate
    // primes are 40 bits (in fact, they are very close to 2^40), we can achieve
    // scale stabilization as described above.
    let scale = 2.0_f64.powi(40);

    let context = Context::create(params, 128u8, true)?;
    // Key Generation
    let key_generator = KeyGenerator::create(&context)?;
    let public_key = key_generator.public_key()?;
    let secret_key = key_generator.secret_key()?;
    let relinearization_keys = key_generator.relinearization_keys()?;
    // encryption // decryption
    let encryptor = Encryptor::create(&context, &public_key, &secret_key)?;
    let decryptor = Decryptor::create(&context, &secret_key)?;

    // Encoder
    let mut ckks_encoder = CKKSEncoder::create(&context)?;
    let slot_count = ckks_encoder.slot_count()?;
    debug!("Number of slots: {}", slot_count);
    let mut input: Vec<f64> = Vec::with_capacity(slot_count);
    let mut curr_point = 0.0;
    let step_size = 1.0 / f64::from((slot_count as u32) - 1);
    for _ in 0..slot_count {
        input.push(curr_point);
        curr_point += step_size;
    }
    debug!("Evaluating polynomial PI*x^3 + 0.4x + 1 ...");

    // We create plaintexts for PI, 0.4, and 1 using an overload of
    // CKKSEncoder::encode that encodes the given floating-point value to every
    // slot in the vector.
    let value_a = std::f64::consts::PI;
    let plain_coeff3 = ckks_encoder.encode_value(&value_a, &scale)?;
    let value_b = 0.4;
    let plain_coeff1 = ckks_encoder.encode_value(&value_b, &scale)?;
    let value_c = 1.0;
    let plain_coeff0 = ckks_encoder.encode_value(&value_c, &scale)?;

    let x_plain = ckks_encoder.encode(&mut input, &scale)?;
    let x1_encrypted = encryptor.encrypt(&x_plain)?;

    // Operations on cipher text - create an evaluator
    let evaluator = Evaluator::create(&context)?;

    // To compute x^3 we first compute x^2 and relinearize. However, the scale has
    // now grown to 2^80.
    debug!("Compute x^2 and relinearize:");
    let x3_encrypted = evaluator.square(&x1_encrypted)?;
    let x3_encrypted = evaluator.relinearize(&x3_encrypted, &relinearization_keys)?;
    debug!(
        "    + Scale of x^2 before rescale: {} bits",
        x3_encrypted.scale()?.log2()
    );

    // Now rescale; in addition to a modulus switch, the scale is reduced down by
    // a factor equal to the prime that was switched away (40-bit prime). Hence, the
    // new scale should be close to 2^40. Note, however, that the scale is not equal
    // to 2^40: this is because the 40-bit prime is only close to 2^40.
    debug!("Rescale x^2.");
    let x3_encrypted = evaluator.rescale_to_next(&x3_encrypted)?;
    debug!(
        "    + Scale of x^2 after rescale: {} bits",
        x3_encrypted.scale()?.log2()
    );

    // Now x3_encrypted is at a different level than x1_encrypted, which prevents us
    // from multiplying them to compute x^3. We could simply switch x1_encrypted to
    // the next parameters in the modulus switching chain. However, since we still
    // need to multiply the x^3 term with PI (plain_coeff3), we instead compute PI*x
    // first and multiply that with x^2 to obtain PI*x^3. To this end, we compute
    // PI*x and rescale it back from scale 2^80 to something close to 2^40.
    debug!("Compute and rescale PI*x.");
    let x1_encrypted_coeff3 = evaluator.mul_plain(&x1_encrypted, &plain_coeff3)?;
    debug!(
        "    + Scale of PI*x before rescale: {} bits",
        x1_encrypted_coeff3.scale()?.log2()
    );
    let x1_encrypted_coeff3 = evaluator.rescale_to_next(&x1_encrypted_coeff3)?;
    debug!(
        "    + Scale of PI*x after rescale: {} bits",
        x1_encrypted_coeff3.scale()?.log2()
    );

    // Since x3_encrypted and x1_encrypted_coeff3 have the same exact scale and use
    // the same encryption parameters, we can multiply them together. We write the
    // result to x3_encrypted, relinearize, and rescale. Note that again the scale
    // is something close to 2^40, but not exactly 2^40 due to yet another scaling
    // by a prime. We are down to the last level in the modulus switching chain.
    debug!("Compute, relinearize, and rescale (PI*x)*x^2.");
    let x3_encrypted = evaluator.mul(&x3_encrypted, &x1_encrypted_coeff3)?;
    let x3_encrypted = evaluator.relinearize(&x3_encrypted, &relinearization_keys)?;
    debug!(
        "    + Scale of PI*x^3 before rescale: {} bits",
        x3_encrypted.scale()?.log2()
    );
    let x3_encrypted = evaluator.rescale_to_next(&x3_encrypted)?;
    debug!(
        "    + Scale of PI*x^3 after rescale: {} bits",
        x3_encrypted.scale()?.log2()
    );

    // Next we compute the degree one term. All this requires is one multiply_plain
    // with plain_coeff1. We overwrite x1_encrypted with the result.
    debug!("Compute and rescale 0.4*x.");
    let x1_encrypted = evaluator.mul_plain(&x1_encrypted, &plain_coeff1)?;
    debug!(
        "    + Scale of 0.4*x before rescale: {} bits",
        x1_encrypted.scale()?.log2()
    );
    let x1_encrypted = evaluator.rescale_to_next(&x1_encrypted)?;
    debug!(
        "    + Scale of 0.4*x after rescale: {} bits",
        x1_encrypted.scale()?.log2()
    );

    // Now we would hope to compute the sum of all three terms. However, there is
    // a serious problem: the encryption parameters used by all three terms are
    // different due to modulus switching from rescaling.
    // Encrypted addition and subtraction require that the scales of the inputs are
    // the same, and also that the encryption parameters (parms_id) match. If there
    // is a mismatch, Evaluator will throw an exception.
    debug!("Parameters used by all three terms are different.");

    // Although the scales of all three terms are approximately 2^40, their exact
    // values are different, hence they cannot be added together
    debug!("The exact scales of all three terms are different:");
    x3_encrypted.set_scale(&scale)?;
    x1_encrypted.set_scale(&scale)?;

    // Mismatching encryption params: use modulus switching (no rescaling)
    // CKKS supports modulus switching just like the BFV scheme, allowing us to
    // switch away parts of the coefficient modulus when it is simply not
    // needed.
    debug!("Normalize encryption parameters to the lowest level.");
    let mut parms_id = x3_encrypted.parms_id()?;
    let x1_encrypted = evaluator.mod_switch_to(&x1_encrypted, &mut parms_id)?;
    let plain_coeff0 = evaluator.mod_switch_to_plain_text(&plain_coeff0, &mut parms_id)?;

    // All three ciphertexts are now compatible and can be added
    debug!("Compute PI*x^3 + 0.4*x + 1.");

    let encrypted_result = evaluator.add(&x3_encrypted, &x1_encrypted)?;
    let encrypted_result = evaluator.add_plain(&encrypted_result, &plain_coeff0)?;

    // First print the true result
    debug!("Decrypt and decode PI*x^3 + 0.4x + 1.");
    let mut true_result: Vec<f64> = Vec::with_capacity(input.len());
    for x in input {
        true_result.push((value_a * x * x + value_b) * x + value_c);
    }
    // debug!("    + Expected result:\n{:?}", true_result);

    // Decrypt, decode, and print the result
    let plain_result = decryptor.decrypt(&encrypted_result)?;
    let result = ckks_encoder.decode(&plain_result)?;
    // debug!("    + Computed result ...... Correct.\n{:?}", &result);
    let epsilon = 0.000001;
    for (expected, result) in true_result.iter().zip(result.iter()) {
        // debug!("{}   -   {}", expected, result);
        assert!((expected - result).abs() / (expected.abs() + result.abs()) < epsilon);
    }
    Ok(())
}

#[test]
fn test_serialization() -> Result<()> {
    let params = Params::create(SCHEME_BFV)?;
    let security_level = 128u8;
    params.set_poly_modulus_degree(4096)?;
    assert_eq!(4096, params.get_poly_modulus_degree()?);
    params.set_coeff_modulus(params.bfv_default(security_level)?)?;
    params.set_plain_modulus(1024)?;
    let context = Context::create(params, security_level, true)?;
    // Key Generation
    let key_generator = KeyGenerator::create(&context)?;
    let public_key = key_generator.public_key()?;
    let secret_key = key_generator.secret_key()?;
    let relinearization_keys = key_generator.relinearization_keys()?;
    let mut saved_relin_keys = relinearization_keys.save()?;
    // encryption // decryption
    let encryptor = Encryptor::create(&context, &public_key, &secret_key)?;
    let decryptor = Decryptor::create(&context, &secret_key)?;
    // create a constant plain text in te thread local memory pool
    let value_a = 6u64;
    let plain_text_a = Plaintext::create_constant(value_a)?;
    let cipher_text_a = encryptor.encrypt(&plain_text_a)?;
    let mut saved_cipher_text_a = cipher_text_a.save()?;
    let value_b = 7u64;
    let plain_text_b = Plaintext::create_constant(value_b)?;
    let cipher_text_b = encryptor.encrypt(&plain_text_b)?;
    let mut saved_plain_text_b = plain_text_b.save()?;
    let mut saved_cipher_text_b = cipher_text_b.save()?;
    //
    // Everything below is recreated from serialized elements
    //
    // Recreate the context
    let params = Params::create(SCHEME_BFV)?;
    let security_level = 128u8;
    params.set_poly_modulus_degree(4096)?;
    assert_eq!(4096, params.get_poly_modulus_degree()?);
    params.set_coeff_modulus(params.bfv_default(security_level)?)?;
    params.set_plain_modulus(1024)?;
    let recovered_context = Context::create(params, security_level, true)?;
    // Operations on cipher text - create an evaluator
    let evaluator = Evaluator::create(&recovered_context)?;
    // reload the cipher texts
    let recovered_cipher_text_a = Ciphertext::load(&recovered_context, &mut saved_cipher_text_a)?;
    let recovered_plain_text_b = Plaintext::load(&recovered_context, &mut saved_plain_text_b)?;
    let recovered_cipher_text_b = Ciphertext::load(&recovered_context, &mut saved_cipher_text_b)?;
    // test multiplication with plain
    let ct_a_mul_plain_b =
        evaluator.mul_plain(&recovered_cipher_text_a, &recovered_plain_text_b)?;
    assert_eq!(
        value_a * value_b,
        decryptor.decrypt(&ct_a_mul_plain_b)?.coeff_at(0)?
    );
    // recover the relinearization keys
    let recovered_relinearization_keys =
        RelinearizationKeys::load(&recovered_context, &mut saved_relin_keys)?;
    // test relinearization
    let ct_a_mul_b_relin = evaluator.relinearize(
        &evaluator.mul(&recovered_cipher_text_a, &recovered_cipher_text_b)?,
        &recovered_relinearization_keys,
    )?;
    assert_eq!(
        value_a * value_b,
        decryptor.decrypt(&ct_a_mul_b_relin)?.coeff_at(0)?
    );

    //done
    Ok(())
}

#[test]
#[ignore]
fn test_noise_budget() -> Result<()> {
    // create a modulus for batching
    let security_level = 128u8;
    debug!("|--------|------------|------|------|---------|------|------|---------|------|");
    debug!("| degree |    modulus | bits | m.p. | µs/slot |  ms  | mul. | µs/slot |  ms  |");
    for bits_size in 22u8..30u8 {
        debug!("|--------|------------|------|------|---------|------|------|---------|------|");
        for degree_index in 2..4 {
            let poly_modulus_degree = 4096usize * (1usize << degree_index);
            print!("|{:>7} |", poly_modulus_degree);
            let slots = poly_modulus_degree;
            let plain_modulus = match SmallModulus::for_batching(poly_modulus_degree, bits_size) {
                Ok(sm) => sm.value()?,
                Err(_) => {
                    debug!(" FAILURE creating the modulus-------|------|------|---------|------|");
                    continue;
                }
            };
            print!("{:>11} |{:>5} |", plain_modulus, bits_size);
            let mut vector: Vec<u64> = Vec::with_capacity(slots);
            for _col in 0..slots {
                vector.push(thread_rng().gen::<u64>() % plain_modulus);
            }

            let params = Params::create(SCHEME_BFV)?;
            params.set_poly_modulus_degree(poly_modulus_degree)?;
            assert_eq!(poly_modulus_degree, params.get_poly_modulus_degree()?);
            params.set_coeff_modulus(params.bfv_default(security_level)?)?;
            params.set_plain_modulus(plain_modulus)?;
            let context = Context::create(params, security_level, true)?;

            // Key Generation
            let key_generator = KeyGenerator::create(&context)?;
            let public_key = key_generator.public_key()?;
            let secret_key = key_generator.secret_key()?;
            let relinearization_keys = key_generator.relinearization_keys()?;

            // Batch Encoding
            let batch_encoder = BatchEncoder::create(&context)?;
            assert_eq!(slots, batch_encoder.slot_count()?);
            let encryptor = Encryptor::create(&context, &public_key, &secret_key)?;
            let decryptor = Decryptor::create(&context, &secret_key)?;

            // check that the plain text decodes properly and create the sliding vector
            let plain_text = batch_encoder.encode(&mut vector)?;
            let v = batch_encoder.decode(&plain_text)?;
            assert_eq!(vector, v);

            let original_cipher_text = encryptor.encrypt(&plain_text)?;

            // perform multiplications
            let evaluator = Evaluator::create(&context)?;
            let loops = 5usize;
            let mut mul_plain_round = 1usize;
            let mut mul_plain_nanos = 0u128;
            let mut mul_round = 1usize;
            let mut mul_nanos = 0u128;
            for _l in 0..loops {
                let mut mul_plain_cipher_text = original_cipher_text.clone()?;
                let mut mul_cipher_text = original_cipher_text.clone()?;
                loop {
                    let mul_plain_now = Instant::now();
                    mul_plain_cipher_text =
                        evaluator.mul_plain(&mul_plain_cipher_text, &plain_text)?; //&original_cipher_text)?;
                    mul_plain_cipher_text =
                        evaluator.relinearize(&mul_plain_cipher_text, &relinearization_keys)?;
                    let mul_plain_noise_budget =
                        decryptor.invariant_noise_budget(&mul_plain_cipher_text)?;
                    if mul_plain_noise_budget > 0 {
                        mul_plain_nanos += mul_plain_now.elapsed().as_nanos();
                        mul_plain_round += 1;
                    }
                    //
                    let mul_now = Instant::now();
                    mul_cipher_text = evaluator.mul(&mul_cipher_text, &original_cipher_text)?; //&original_cipher_text)?;
                    mul_cipher_text =
                        evaluator.relinearize(&mul_cipher_text, &relinearization_keys)?;
                    let mul_noise_budget = decryptor.invariant_noise_budget(&mul_cipher_text)?;
                    if mul_noise_budget > 0 {
                        mul_nanos += mul_now.elapsed().as_nanos();
                        mul_round += 1;
                    }
                    if mul_noise_budget <= 0 && mul_plain_noise_budget <= 0 {
                        break;
                    }
                }
            }
            print!(
                "  {:>2}  |{:>8} |{:>5} |",
                mul_plain_round / loops,
                mul_plain_nanos / (mul_plain_round as u128) / (slots as u128) / 1_000,
                mul_plain_nanos / (mul_plain_round as u128) / 1_000_000,
            );
            debug!(
                "  {:>2}  |{:>8} |{:>5} |",
                mul_round / loops,
                mul_nanos / (mul_round as u128) / (slots as u128) / 1_000,
                mul_nanos / (mul_round as u128) / 1_000_000,
            );
        }
    }
    debug!("|--------|------------|------|------|---------|------|------|---------|------|");
    Ok(())
}

#[test]
fn test_memory_pool() -> Result<()> {
    Plaintext::create_in_pool(MemoryPoolHandle::to_thread_local_pool()?)?;
    Ok(())
}

#[test]
fn test_set_params_bfv() -> Result<()> {
    let security_level = 128u8;
    let poly_modulus_degree = 8192 * 2;
    let params = Params::create(SCHEME_BFV)?;
    params.set_poly_modulus_degree(poly_modulus_degree)?;
    assert_eq!(poly_modulus_degree, params.get_poly_modulus_degree()?);
    params.set_coeff_modulus(params.bfv_default(security_level)?)?;
    Ok(())
}

#[test]
fn test_set_params_ckks() -> Result<()> {
    let poly_modulus_degree = 8192 * 2;
    let params = Params::create(SCHEME_CKKS)?;
    params.set_poly_modulus_degree(8192 * 2)?;
    assert_eq!(poly_modulus_degree, params.get_poly_modulus_degree()?);
    let mut bits_sizes = vec![60, 30, 30, 30, 60]; // sum is 140
    params.set_coeff_modulus_ckks(&mut bits_sizes)?;
    Ok(())
}

#[test]
fn test_mod_switch_to_next() -> Result<()> {
    let security_level = 128u8;
    debug!("|-------|-------||-------|----------||-------|----------||------|");
    debug!("| deg.  |  bits || noise | size(kb) || noise | size(kb) || gain |");
    debug!("|-------|-------||-------|----------||-------|----------||------|");
    for bits_size in 23..30u8 {
        for d in 1..3usize {
            let poly_modulus_degree = 8192 * d;
            let plain_modulus =
                SmallModulus::for_batching(poly_modulus_degree, bits_size)?.value()?;

            let params = Params::create(SCHEME_BFV)?;
            params.set_poly_modulus_degree(poly_modulus_degree)?;
            params.set_coeff_modulus(params.bfv_default(security_level)?)?;
            params.set_plain_modulus(plain_modulus)?;
            let context = Context::create(params, security_level, true)?;

            // Key Generation
            let key_generator = KeyGenerator::create(&context)?;
            let public_key = key_generator.public_key()?;
            let secret_key = key_generator.secret_key()?;
            let relinearization_keys = key_generator.relinearization_keys()?;

            // Batch Encoding
            let batch_encoder = BatchEncoder::create(&context)?;
            let encryptor = Encryptor::create(&context, &public_key, &secret_key)?;
            let decryptor = Decryptor::create(&context, &secret_key)?;

            // check that the plain text decodes properly and create the sliding vector
            let v: u64 = 1;
            let mut vector = vec![v; poly_modulus_degree];
            let plain_text = batch_encoder.encode(&mut vector)?;
            let v = batch_encoder.decode(&plain_text)?;
            assert_eq!(vector, v);

            let evaluator = Evaluator::create(&context)?;
            let original_cipher_text = encryptor.encrypt(&plain_text)?;
            let mut ct = original_cipher_text.clone()?;
            loop {
                // WARNING: if this crate moves to using anyhow, we expose UB here in release
                // mode!
                let mut result = evaluator.mul(&original_cipher_text, &ct)?;
                result = evaluator.relinearize(&result, &relinearization_keys)?;
                let remaining_noise_budget = decryptor.invariant_noise_budget(&result)?;
                if remaining_noise_budget <= 0 {
                    let noise_budget = decryptor.invariant_noise_budget(&ct)?;
                    let compressed_size = ct.save()?.len() / 1024;
                    let ct = evaluator.compact_size(&ct)?;
                    let new_noise_budget = decryptor.invariant_noise_budget(&ct)?;
                    let new_compressed_size = ct.save()?.len() / 1024;
                    debug!(
                        "| {:>5} | {:>5} || {:>5} | {:>8} || {:>5} | {:>8} || {:>3}% | ",
                        poly_modulus_degree,
                        bits_size,
                        noise_budget,
                        compressed_size,
                        new_noise_budget,
                        new_compressed_size,
                        100 - new_compressed_size * 100 / compressed_size
                    );
                    // check that we can still decrypt
                    let pt = decryptor.decrypt(&ct)?;
                    let recovered = batch_encoder.decode(&pt)?;
                    assert_eq!(&vector, &(recovered));
                    break;
                } else {
                    ct = result;
                }
            }
        }
        debug!("|-------|-------||-------|----------||-------|----------||------|");
    }
    Ok(())
}
