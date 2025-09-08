#text(2em)[D0029E Lab 1 - Group Green M 3]

Members:
- Arvid Persson
- Joel Andersson
- Rasmus Engström

#set heading(
  numbering: (..n) => {
    let number = n.pos().map(str).join(".")
    [Task #number]
  },
  supplement: [],
)

=

The goal is to encrypt a BMP file with a few different ciphers and
view the image to see if we could make out any relevant data. The BMP
format simply encodes the image as row-major matrix of pixels.
Hypothetically, for us to be able to visually make out anything
useful from the encrypted image, the cipher would have to:
+ Work on reasonably small blocks. Then pixels would only be
  "scrambled" very locally: Edges might be visible. Most ciphers
  discussed in the course material should fall into this category.
+ Not be too "chaotic". Assuming RGB color formatting, red is for
  instance represented as `ff0000`. If this tendency of many ones in
  one area and many zeroes in another persists after encryption, we
  might be able to make out color, or at least differentiate between
  colors. This would apply to a simple rotation-based cipher.
Alternatively, if the cipher is predictable and always encrypts an
identical block in the same way, we could make out rough patterns,
but miss finer details. Otherwise, the image would likely appear as
random noise.

As the used variant of the BMP format has a fixed 54-byte header, we
first extracted those bytes from the unencrypted (valid) file for
later use:

```sh
head -c 54 pic_original.bmp > header_bmp
```

We chose the following ciphers, making sure to include both ECB and
CBC modes:

+ `aes-128-ecb`
+ `aes-128-cbc`
+ `des-ede-cbc`

We chose the sample key and IVs from the instructions. We processed
the image with the following commands:

```sh
openssl enc -aes-128-ecb -e -K 00112233445566778889aabbccddeeff
    -in pic_original.bmp | tail -c +55 | cat header_bmp -
    > pic_aes-128-ecb.bmp
openssl enc -aes-128-cbc -e -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in pic_original.bmp | tail -c +55
    | cat header_bmp - > pic_aes-128-cbc.bmp
# Two key variant chosen as that allows us to reuse the same key.
openssl enc -des-ede-cbc -e -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in pic_original.bmp | tail -c +55
    | cat header_bmp - > pic_des-ede-cbc.bmp
```

After encrypting with each cipher, we viewed them with an image
viewer. The results are shown in @task1-fig. We make the following observations:
- The cipher does not affect the results, as AES CBC and DES CBC
  produce similar results.
- The mode *does* affect the results, as AES CBC and AES ECB produce
  opposite results.
- Our above hypotheses are correct: We can't make out color, only
  shape.

#figure(
  image("images/task1.png"),
  caption: [
    The image and some encrypted variants, as shown in the VM. Top
    left: The original image, top right: AES ECB mode, bottom left:
    AES CBC mode, bottom right: DES two key ECB mode.
  ],
) <task1-fig>

=

==

To test which modes use padding, we encrypt an empty file:

```sh
openssl enc -aes-128-ecb -e -K 00112233445566778889aabbccddeeff
    -in /dev/null | wc -c
>>> 16
openssl enc -aes-128-cbc -e -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in /dev/null | wc -c
>>> 16
openssl enc -aes-128-cfb -e -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in /dev/null | wc -c
>>> 0
openssl enc -aes-128-ofb -e -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in /dev/null | wc -c
>>> 0
```

We see that the ECB and CBC modes need padding, while CFB and OFB do
not. This is because CFB and OFB are stream ciphers, meaning they can
operate bitwise, while ECB and CBC are block ciphers and need a full
block at a time.

==

To inspect the padding, we create a few files of known lengths, and
verify:

```sh
echo -n "12345"            | tee b5  | wc -c
>>> 5
echo -n "1234567890"       | tee b10 | wc -c
>>> 10
echo -n "1234567890abcdef" | tee b16 | wc -c
>>> 16
```

Now encrypting the files:

```sh
openssl enc -aes-128-cbc -e -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in b5  | tee b5_enc  | wc -c
>>> 16
openssl enc -aes-128-cbc -e -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in b10 | tee b10_enc | wc -c
>>> 16
openssl enc -aes-128-cbc -e -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in b16 | tee b16_enc | wc -c
>>> 32
```

To check the content of the padding, we decrypt the files, passing
the `-nopad` flag to avoid padding being trimmed:

```sh
openssl enc -aes-128-cbc -d -nopad
    -K 00112233445566778889aabbccddeeff -iv 0102030405060708
    -in b5_enc | hexdump
>>> 0000000 3231 3433 0b35 0b0b 0b0b 0b0b 0b0b 0b0b
>>> 0000010
openssl enc -aes-128-cbc -d -nopad
    -K 00112233445566778889aabbccddeeff -iv 0102030405060708
    -in b10_enc | hexdump
>>> 0000000 3231 3433 3635 3837 3039 0606 0606 0606
>>> 0000010
openssl enc -aes-128-cbc -d -nopad
    -K 00112233445566778889aabbccddeeff -iv 0102030405060708
    -in b16_enc | hexdump
>>> 0000000 3231 3433 3635 3837 3039 6261 6463 6665
>>> 0000010 1010 1010 1010 1010 1010 1010 1010 1010
>>> 0000020
```

We find that PKCS\#5 standard is used for padding. For a cipher using
block size $B$ (bytes) and a file of size $S$, the padding will
consist of $B - mod(S, B)$ bytes containing that same value. For
`b5`, for instance, this value is $16 - mod(5, 16) = 11$, or `0x0b`.
We do indeed see 11 trailing `0b` bytes, respecting endianness.

=

There are two reasonable outcomes:
+ A small chunk around the corrupted byte is garbage, as only the
  containing block was affected.
+ Everything following the block containing the corrupted byte is
  garbage, as the initial garbage data was used as input further on
  in the decryption.
From our understanding, there should not be any forward-feeding in
the decryption stages, so we expect the former. We should *not* see
the entire file being garbage, as the 55th byte should be beyond the
first block, and our cipher should at most process one block at a
time. 

The provided `words.txt` file is well over 1000 bytes. Encrypting it,
flipping a bit in the 55th byte, then decrypting it and inspecting
the relevant part:

```sh
openssl enc -aes-128-ecb -e -K 00112233445566778889aabbccddeeff
    -in words.txt -out words_ecb
openssl enc -aes-128-cbc -e -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in words.txt -out words_cbc
openssl enc -aes-128-cfb -e -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in words.txt -out words_cfb
openssl enc -aes-128-ofb -e -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in words.txt -out words_ofb
# Flipping last bit of 55th byte through GUI.
bless words_ecb
bless words_cbc
bless words_cfb
bless words_ofb
openssl enc -aes-128-ecb -d -K 00112233445566778889aabbccddeeff
    -in words_ecb | head -21 | tail -4
>>> AAbbaba
>>> a����T겷�dn��one
>>> abandon
>>> abase
openssl enc -aes-128-cbc -d -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in words_cbc -out words_cbc.txt
    | head -21 | tail -4
>>> Ababa
>>> aB���K�V���M��one
>>> `bandon
>>> abase
openssl enc -aes-128-cfb -d -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in words_cfb -out words_cfb.txt
    | head -21 | tail -4
>>> Ababa
>>> aback
>>>      abacus
>>> abal :�^.R&U��Chեe
>>> abash
openssl enc -aes-128-ofb -d -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in words_ofb -out words_ofb.txt
    | head -21 | tail -4
>>> Ababa
>>> aback
>>>      abacus
>>> abalone
>>> abandon
```

We find that the first hypothesis was indeed correct.

=

==

We create a file and encrypt it using the same cipher, but changing
the key and/or IV (output omitted):

```sh
echo -n "This message is 30 bytes long." > msg.txt
openssl enc -aes-128-ofb -e -K 00112233445566778889aabbccddeeff
    -iv 0102030405060708 -in msg.txt | hexdump -C
openssl enc -aes-128-ofb -e -K ffeeddccbbaa98887766554433221100
    -iv 0102030405060708 -in msg.txt | hexdump -C
openssl enc -aes-128-ofb -e -K 00112233445566778889aabbccddeeff
    -iv 1234567812345678 -in msg.txt | hexdump -C
openssl enc -aes-128-ofb -e -K ffeeddccbbaa98887766554433221100
    -iv 1234567812345678 -in msg.txt | hexdump -C
```

No pattern is immediately obvious, neither through inspecting the
text nor the bytes. This is of course because XOR and similar bitwise
operations are not entirely intuitive to humans, especially when
looking at text. However, the theory tells us that this system is
susceptible to a chosen-plaintext attack. Rather than manual
processing, this is automated in @chosen-plain.

== <chosen-plain>

Following the procedure described in _Computer & Internet Security: A
Hands-on Approach_ section 21.5.1, we show the vulnerability by
finding unknown plaintext given only its ciphertext, a previous pair
of plaintext-ciphertext, and the knowledge that the IV is constant.
This was done using the script included in @same_iv:

```sh
same_iv "1234567812345678"
>>> Success
```

Unlike OFB, CFB dynamically updates the IV based on the plaintext.
This means that in the general case with different inputs, the IV of
two runs will differ after the first block, and as such we can only
decrypt the first block using this method. In our case, one block is
128 bits, or 16 bytes. Modifying the script to use CFB (replacing the
`-aes-128-ofb` flag with `-aes-128-cfb`), we confirm this:

```sh
same_iv "1234567812345678"
>>> Failure
>>> raw: Here is a text of same length.
>>> rec: Here is a text o�_�`[�b�x�
M��
```

Furthermore, this tells us we should be able to decode the $n$:th
block if all $n - 1$ preceding blocks happen to be identical. We can
confirm this by changing the second message to lead with the same 16
bytes:

```rust
// "This message is 30 bytes long."
   "This message is f same length."
// "Here is a text of same length."
```

Then again running the script:

```sh
same_iv "1234567812345678"
>>> Success
```

==

Following the procedure described in _Computer & Internet Security: A
Hands-on Approach_ section 21.5.2, we show the vulnerability by
finding unknown plaintext given only a set of possible options, the
stream of IVs, and access to ciphertext generated from any plaintext.
This was done using the script included in @predictable_iv (running
two terminals; outputs aligned):

#grid(
  columns: (1fr, 1fr),
  column-gutter: 5%,
  ```
  $ docker compose build
  $ docker compose up &
  $ nc 10.9.0.80 3000
  Bob's secret message is either "Yes" or "No", without quotations.
  Bob's ciphertex: 258cb46e278330a30813f6c70a58aa17
  The IV used    : a5c3d838fd6a2f41b5363fb6ac341dd9

  Next IV        : 823d299dfd6a2f41b5363fb6ac341dd9

  Your plaintext : 7e9b82a80d0d0d0d0d0d0d0d0d0d0d0d
  Your ciphertext: 258cb46e278330a30813f6c70a58aa17

  Next IV        : 87b911c4fd6a2f41b5363fb6ac341dd9
  Your plaintext : 
  ```,
  ```




  $ predictable_iv
  Bob's ciphertext:
  258cb46e278330a30813f6c70a58aa17
  Last IV:
  a5c3d838fd6a2f41b5363fb6ac341dd9

  Next IV:
  823d299dfd6a2f41b5363fb6ac341dd9

  Try:
  7e9b82a80d0d0d0d0d0d0d0d0d0d0d0d
  Your ciphertext:
  258cb46e278330a30813f6c70a58aa17
  Success: "Yes"
  ```,
)

We see that Bob sent "Yes".

// WARN: doesn't handle subsections, or appendices beyond "Z".
#counter(heading).update(0)
#set heading(
  numbering: (..n) => {
    let a = "A".to-unicode()
    let offset = n.pos().first()
    [Appendix #str.from-unicode(a + offset - 1)]
  },
  supplement: []
)
#pagebreak()

= `same_iv` <same_iv>

Below is the Rust script used to demonstrate a chosen-plaintext
attack. Note that it is only tested on a Linux machine, and highly
system-dependent as it spawns processes. To run it, compile it and
pass the IV as a command line argument to the binary.

```rs
use std::{
    env::args,
    io::Write,
    process::{Command, Stdio, exit},
};

// 30 bytes means one full block and one non-full.
const PLAIN1: &str = "This message is 30 bytes long.";
const PLAIN2: &str = "Here is a text of same length.";
// NOTE: "8889", not "8899", as was it written in the instructions'
// example.
const KEY: &str = "00112233445566778889aabbccddeeff";

// It might be easier to use a dedicated cipher library instead of
// calling out to shell commands, but this keeps it simple and uses
// the tools provided for the lab.
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

    // This is the important part. Here, we construct `PLAIN2`
    // referencing only `PLAIN1`, `cipher1` and `cipher2`. This being
    // possible is the vulnerability.
    let plain2_reconstructed = {
        let key_reconstructed = PLAIN1
            .bytes()
            .zip(cipher1)
            .map(|(a, b)| a ^ b);
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
```

= `predictable_iv` <predictable_iv>

Below is the Rust script used to demonstrate a known-plaintext
attack. Note that it is only tested on a Linux machine, and highly
system-dependent as it spawns processes. It also depends on the `hex`
crate. To run it, compile it and follow the prompts.

```rs
use hex::{decode, encode};
use std::{io::stdin, iter::repeat_n, process::exit};

const CANDIDATES: &[&str] = &["Yes", "No"];
const BLOCK_SIZE: u8 = 128 / 8;

fn prompt(msg: &str) -> Vec<u8> {
    println!("{msg}");
    // Allocating a new string every time is unnecessary. It should
    // at least be initialized with the appropriate capacity.
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
            // PKCS#5 padding.
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
        println!("Try {guess}");

        let cipher = prompt("Your ciphertext:");
        if cipher == cipher_target {
            println!("Success: \"{candidate}\"");
            exit(0);
        } else {
            println!("No match");
            iv_last = iv_next;
        }
    }

    // Candidates exhausted.
    eprintln!("Failure");
    exit(1);
}
```
