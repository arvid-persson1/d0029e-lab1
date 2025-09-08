use std::{
    env::args,
    io::Write,
    process::{Command, Stdio, exit},
};

const PLAIN1: &str = "This message is 30 bytes long.";
const PLAIN2: &str = "Here is a text of same length.";
// NOTE: "8889", not "8899".
const KEY: &str = "00112233445566778889aabbccddeeff";

// This should be done through a dedicated encryption/decryption
// library, but here's keeping it simple.
fn cipher(iv: &str, plain: &str) -> Vec<u8> {
    let mut child = Command::new("openssl")
        .args(["enc", "-aes-128-cfb", "-K", KEY, "-iv", iv])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(plain.as_bytes())
        .unwrap();

    child.wait_with_output().unwrap().stdout
}

fn main() {
    let iv = args().nth(1).unwrap();

    let cipher1 = cipher(&iv, PLAIN1);
    let cipher2 = cipher(&iv, PLAIN2);

    let plain2_reconstructed = {
        let key_reconstructed = PLAIN1.bytes().zip(cipher1).map(|(a, b)| a ^ b);
        let bytes = key_reconstructed
            .zip(cipher2)
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>();
        String::from_utf8_lossy(&bytes).into_owned()
    };

    if plain2_reconstructed == PLAIN2 {
        println!("Success");
    } else {
        eprintln!("Failure\nraw: {PLAIN2}\nrec: {plain2_reconstructed}");
        exit(1);
    }
}
