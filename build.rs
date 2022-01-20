use std::{
    fs::{write, File},
    io::{BufRead, BufReader},
};

fn main() {
    // write wrapper.h
    let mut s = String::new();
    s += "#include \"stdint.h\"\n";
    s += &process_header("seal/native/src/seal/c/batchencoder.h");
    s += &process_header("seal/native/src/seal/c/ciphertext.h");
    s += &process_header("seal/native/src/seal/c/ckksencoder.h");
    s += &process_header("seal/native/src/seal/c/contextdata.h");
    s += &process_header("seal/native/src/seal/c/decryptor.h");
    s += &process_header("seal/native/src/seal/c/encryptionparameterqualifiers.h");
    s += &process_header("seal/native/src/seal/c/encryptionparameters.h");
    s += &process_header("seal/native/src/seal/c/encryptor.h");
    s += &process_header("seal/native/src/seal/c/evaluator.h");
    s += &process_header("seal/native/src/seal/c/galoiskeys.h");
    s += &process_header("seal/native/src/seal/c/keygenerator.h");
    s += &process_header("seal/native/src/seal/c/kswitchkeys.h");
    s += &process_header("seal/native/src/seal/c/memorymanager.h");
    s += &process_header("seal/native/src/seal/c/memorypoolhandle.h");
    s += &process_header("seal/native/src/seal/c/modulus.h");
    s += &process_header("seal/native/src/seal/c/plaintext.h");
    s += &process_header("seal/native/src/seal/c/publickey.h");
    s += &process_header("seal/native/src/seal/c/relinkeys.h");
    s += &process_header("seal/native/src/seal/c/sealcontext.h");
    s += &process_header("seal/native/src/seal/c/secretkey.h");
    s += &process_header("seal/native/src/seal/c/serialization.h");
    s += &process_header("seal/native/src/seal/c/stdafx.h");
    s += &process_header("seal/native/src/seal/c/targetver.h");
    s += &process_header("seal/native/src/seal/c/utilities.h");
    s += &process_header("seal/native/src/seal/c/valcheck.h");
    write("seal/native/src/seal/c/wrapper.h", s).unwrap();

    // generate our FFI code for the C API
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("seal/native/src/seal/c/wrapper.h")
        .clang_arg("-I.")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings for seal net");
    bindings
        .write_to_file(out_path.join("seal_bindings.rs"))
        .expect("Couldn't write bindings for SEAL!");

    /* build seal */

    let dst = cmake::Config::new("seal")
        .define("SEAL_BUILD_SEAL_C", "ON")
        .build();

    // link the SEALC lib
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=sealc");

}

fn process_header(header_file: &str) -> String {
    let file = File::open(header_file).unwrap();
    let mut reader = BufReader::new(file);
    let mut s = String::new();
    loop {
        let mut buf = String::new();
        let len = reader.read_line(&mut buf).unwrap();
        if len == 0 {
            return s;
        }
        if buf.contains("SEAL_C_FUNC") {
            // the definition may be on multiple lines
            loop {
                if buf.trim().ends_with(");") {
                    break;
                }
                reader.read_line(&mut buf).unwrap();
            }
            buf = buf.replace("SEAL_C_FUNC", "long");
            buf = buf.replace("bool ", "int ");
            s += &buf;
        }
    }
}
