// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use josekit::jws::{JwsHeader, EdDSA};
use josekit::jwk::alg::ed::EdKeyPair;
use josekit::jwt::{self, JwtPayload};
use sd_jwt_payload::{Disclosure, KeyBindingJwtClaims, SdJwt, SdObjectDecoder, SdObjectEncoder, Sha256Hasher, HEADER_TYP};
use serde_json::{Value, json};

fn main() -> Result<(), Box<dyn Error>> {
    const ISSUER_PRIVATE_KEY: &str = "issuer_private_key_ed25519.pem";
    const ISSUER_PUBLIC_KEY: &str = "issuer_public_key_ed25519.pem";
    const HOLDER_PRIVATE_KEY: &str = "holder_private_key_ed25519.pem";

    let private_pem_file_content = std::fs::read(HOLDER_PRIVATE_KEY)?;
    let key_pair = EdKeyPair::from_pem(private_pem_file_content)?;
    let jwk = key_pair.to_jwk_public_key();
    let pubkey_jwk = serde_json::from_str(&jwk.to_string())?;

    let mut object = json!({
    "account_name": "example_account",
    "ip_addresses": ["192.168.0.1", "192.168.0.2"],
    "dns_addresses": ["example.com", "example.org"],
    "route_networks": ["10.0.0.0/8", "172.16.0.0/12"],
    "group_name": "example_group"
  });

  if let Value::Object(ref mut map) = object {
    map.insert("cnf".to_string(), pubkey_jwk);
  }

  let mut encoder: SdObjectEncoder = object.try_into()?;
  let disclosures: Vec<Disclosure> = vec![
    encoder.conceal("/account_name", None)?,
    encoder.conceal("/ip_addresses", None)?,
    encoder.conceal("/dns_addresses", None)?,
    encoder.conceal("/route_networks", None)?,
    encoder.conceal("/group_name", None)?,
  ];

  encoder.add_decoys("", 2)?; // Add decoys to the top level.

  encoder.add_sd_alg_property();

  println!("encoded object: {}", serde_json::to_string_pretty(encoder.object()?)?);

  // Create the JWT.
  // Creating JWTs is outside the scope of this library, josekit is used here as an example.
  let mut header = JwsHeader::new();
  header.set_token_type(HEADER_TYP);

  // Use the encoded object as a payload for the JWT.
  let payload = JwtPayload::from_map(encoder.object()?.clone())?;
  let private_key = std::fs::read(ISSUER_PRIVATE_KEY).unwrap();
  let signer = EdDSA.signer_from_pem(private_key)?;
  println!("loaded signer's private key");
  let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;

  // Create an SD_JWT by collecting the disclosures and creating an `SdJwt` instance.
  let disclosures: Vec<String> = disclosures
    .into_iter()
    .map(|disclosure| disclosure.to_string())
    .collect();

  let nonce = "nonce".to_string();
  let audience = "el-server".to_string();
  let hasher = Sha256Hasher::new();
  let key_binding_jwt = KeyBindingJwtClaims::new(&hasher, jwt.clone(), disclosures.clone(), nonce, audience, 0);

  let holder_private_key = std::fs::read(HOLDER_PRIVATE_KEY).unwrap();
  let signer = EdDSA.signer_from_pem(holder_private_key)?;
  println!("loaded signer's private key");
  let mut header = JwsHeader::new();
  header.set_algorithm("EdDSA"); // EdDSA署名アルゴリズムの指定
  header.set_token_type("kb+jwt");
  let mut payload = JwtPayload::new();
  payload.set_audience([key_binding_jwt.aud.clone()].to_vec());
  let now = std::time::SystemTime::now();
  payload.set_issued_at(&now);
  payload.set_claim("nonce", Some(Value::String(key_binding_jwt.nonce)))?;
  payload.set_claim("sd_hash", Some(Value::String(key_binding_jwt.sd_hash)))?;
  let key_binding_jwt = jwt::encode_with_signer(&payload, &header, &signer)?;
  println!("kb-jwt: {:?}", key_binding_jwt);

  let sd_jwt: SdJwt = SdJwt::new(jwt, disclosures.clone(), Some(key_binding_jwt));
  let sd_jwt: String = sd_jwt.presentation();

  println!("sd_jwt: {:?}", sd_jwt);

  // Decoding the SD-JWT
  // Extract the payload from the JWT of the SD-JWT after verifying the signature.
  let sd_jwt: SdJwt = SdJwt::parse(&sd_jwt)?;
  let public_key = std::fs::read(ISSUER_PUBLIC_KEY).unwrap();
  let verifier = EdDSA.verifier_from_pem(public_key)?;
  let (payload, _header) = jwt::decode_with_verifier(&sd_jwt.jwt, &verifier)?;

  // Decode the payload by providing the disclosures that were parsed from the SD-JWT.
  let decoder = SdObjectDecoder::new_with_sha256();
  let decoded = decoder.decode(payload.claims_set(), &sd_jwt.disclosures)?;
  println!("decoded object: {}", serde_json::to_string_pretty(&decoded)?);
  Ok(())
}
