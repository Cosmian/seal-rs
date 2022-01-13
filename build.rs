use std::{
    env,
    fs::{write, File},
    io::{BufRead, BufReader},
};

fn main() {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let _dir = env::var("CARGO_MANIFEST_DIR").unwrap();

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

    /* build sealc */

    let mut build = cc::Build::new();
    build.cpp(true).pic(true).flag("-std=c++17").flag("-O3");

    for source in include!("sources_c.rs").iter() {
        build.file(format!("seal/native/src/seal/c/{}", source));
    }

    build.include("seal/thirdparty/msgsl-src/include");
    build.include("seal/thirdparty/zstd-src/lib");
    build.include("seal/thirdparty/zstd-src/lib/common");
    build.include("seal");
    build.include(".");
    build.compile("sealcnative");

    /* build seal */

    let mut build = cc::Build::new();
    build.cpp(true).pic(true).flag("-std=c++17").flag("-O3");

    for source in include!("sources.rs").iter() {
        build.file(format!("seal/native/src/seal/{}", source));
    }

    build.include(".");
    build.include("seal/thirdparty/msgsl-src/include");
    build.include("seal/thirdparty/zstd-src/lib/");
    build.include("seal/thirdparty/zstd-src/lib/common");

    for source in include!("sources_util.rs").iter() {
        build.file(format!("seal/native/src/seal/util/{}", source));
    }

    build.compile("seal-3.7.2");

    match os.as_str() {
        "macos" => println!("cargo:rustc-link-lib=dylib=c++"),
        _ => println!("cargo:rustc-link-lib=dylib=stdc++"),
    };

    println!("cargo:rustc-link-search=all=seal/lib");
    println!("cargo:rustc-link-lib=dylib=z");
    println!("cargo:rustc-link-lib=static=zstd");
}

fn process_header(header_file: &str) -> String {
    // println!("Processing header of {}", header_file);
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
            // #define SEAL_C_FUNC SEAL_C_DECOR HRESULT SEAL_C_CALL
            buf = buf.replace("SEAL_C_FUNC", "long");
            buf = buf.replace("bool ", "int ");
            s += &buf;
        }
    }
}
