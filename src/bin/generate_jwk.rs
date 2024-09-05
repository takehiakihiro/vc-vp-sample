use josekit::jwk::alg::ed::EdKeyPair;
use josekit::jws::{EdDSA, JwsHeader};
use josekit::jwt::{self, JwtPayload};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    const HOLDER_PRIVATE_KEY: &str = "holder_private_key_ed25519.pem";

    // ======================= Holder part =======================
    let private_pem_file_content = std::fs::read(HOLDER_PRIVATE_KEY)?;
    let key_pair = EdKeyPair::from_pem(private_pem_file_content.clone())?;
    let jwk = key_pair.to_jwk_public_key();
    let pubkey_jwk = serde_json::from_str(&jwk.to_string())?;

    // Create the JWT.
    // Creating JWTs is outside the scope of this library, josekit is used here as an example.
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    header.set_algorithm("EdDSA"); // EdDSA署名アルゴリズムの指定

    // Use the encoded object as a payload for the JWT.
    let mut payload = JwtPayload::new();
    let _ = payload.set_claim("jwk", pubkey_jwk);

    println!("header={}, payload={}", header, payload);

    let signer = EdDSA.signer_from_pem(private_pem_file_content)?;
    println!("loaded signer's private key");
    let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;

    println!("JWK's JWT={}", jwt);

    Ok(())
}
