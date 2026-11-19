//! Makes a self-signed certificate for LOCAL TESTING ONLY.
//!
//! Run it with:  cargo run --example gen_cert
//!
//! Browsers will warn about it, because no trusted authority signed it.
//! A public website needs a real certificate (for example from Let's Encrypt).

use std::path::Path;

fn main() {
    let names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(names).expect("could not make a certificate");

    let dir = Path::new("certs");
    std::fs::create_dir_all(dir).expect("could not create the certs folder");
    std::fs::write(dir.join("dev-cert.pem"), cert.pem()).expect("could not write the certificate");
    std::fs::write(dir.join("dev-key.pem"), key_pair.serialize_pem())
        .expect("could not write the private key");

    println!("Wrote certs/dev-cert.pem and certs/dev-key.pem");
    println!("Valid for: localhost, 127.0.0.1 and ::1");
    println!("Keep dev-key.pem private. Never commit it, and never use it on a real site.");
}