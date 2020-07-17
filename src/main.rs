extern crate x25519_dalek;
extern crate rand;
extern crate base32;

use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;

fn main() {
    let mut alice_csprng = rand::thread_rng();
    let     alice_secret = EphemeralSecret::new(&mut alice_csprng);
    let     alice_public = PublicKey::from(&alice_secret);

    let alice_secret = alice_secret.diffie_hellman(&alice_public);

    let b32_secret = base32::encode(base32::Alphabet::RFC4648 { padding: false }, alice_secret.as_bytes());
    let b32_public = base32::encode(base32::Alphabet::RFC4648 { padding: false }, alice_public.as_bytes());

    println!("secret: {:?}", b32_secret);
    println!("public: {:?}", b32_public);
}
