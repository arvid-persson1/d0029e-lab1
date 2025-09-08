use hex::{decode, encode};
use std::{
    io::{Write, stdin, stdout},
    iter::repeat_n,
    process::exit,
};

const CANDIDATES: &[&str] = &["Yes", "No"];
const BLOCK_SIZE: u8 = 128 / 8;

fn prompt(msg: &str) -> Vec<u8> {
    print!("{msg}");
    stdout().flush().unwrap();

    // Allocating a new string every time is unnecessary.
    // It should at least be initialized with the appropriate capacity.
    let mut buf = String::new();
    stdin().read_line(&mut buf).unwrap();
    decode(buf.trim_end()).unwrap()
}

fn main() {
    let cipher_target = prompt("Bob's ciphertext: ");
    let mut iv_last = prompt("Last IV: ");

    for candidate in CANDIDATES {
        let iv_next = prompt("Next IV: ");

        let guess = {
            let pad = BLOCK_SIZE - candidate.len() as u8 % BLOCK_SIZE;
            let g = candidate
                .bytes()
                .chain(repeat_n(pad, pad as usize))
                .zip(iv_last)
                .map(|(a, b)| a ^ b)
                .zip(&iv_next)
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>();
            encode(g)
        };
        println!("Try:\n{guess}");

        let cipher = prompt("Your ciphertext: ");
        if cipher == cipher_target {
            println!("Success: \"{candidate}\"");
            exit(0);
        } else {
            println!("No match");
            iv_last = iv_next;
        }
    }

    eprintln!("Failure");
    exit(1);
}
