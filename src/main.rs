extern crate x25519_dalek;
extern crate rand;
extern crate base32;

use x25519_dalek::generate_secret;
use x25519_dalek::generate_public;
use rand::OsRng;

fn main() {
    let mut alice_csprng = OsRng::new().unwrap();
    let     alice_secret = generate_secret(&mut alice_csprng);
    let     alice_public = generate_public(&alice_secret);

    let b32_secret = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &alice_secret);
    let b32_public = base32::encode(base32::Alphabet::RFC4648 { padding: false }, alice_public.as_bytes());

    println!("secret: {:?}", b32_secret);
    println!("public: {:?}", b32_public);
}
