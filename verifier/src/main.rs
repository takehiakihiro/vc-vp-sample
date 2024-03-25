use josekit::{jwk, jwt};
use josekit::{jws::EdDSA, Value};
use sd_jwt_payload::{KeyBindingJwtClaims, SdJwt, SdObjectDecoder, Sha256Hasher};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Holderの公開鍵をファイルから読み込み
    const ISSUER_PUBLIC_KEY: &str = "../issuer/issuer_public_key_ed25519.pem";

    // Holderから提出されたVP（署名付きJWTとして）
    let sd_jwt = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsInVzZSI6InNpZyIsImNydiI6IkVkMjU1MTkiLCJ4IjoidXFZYTk1WjdLSFRkWm1nSFE2Q0RRdy0zZ3cwRGxGU01Vb2kzc19BUWgwTSJ9fSwiX3NkIjpbIndlZ1prbEIzR1hEd1FyVC1ObmRtMGVkYVBxN0FtaHpUbVRHQ0dISmFBVTgiLCI4Y0ZRTzlaMXVSRnBQNDNFLXUyVkFXRVNpODFQbVB2empDYWxDLVNlODBjIiwiUDctRktvQ2ZSUzBmaWtidjM2QTB3NDhXcDdZRzcyLTBWNm5Wa2Y4Y1puYyIsIjJMSkpEeVU5c0wzbE1wRUtTRW9DZ25HMV9ET01BaUNYLWNRVFBTbFQydmMiLCJLNGFobFAyRXVaUGhIdFZiLXRrQ2FiZVBKVHJFaEZqZ2RuXzIwNGVraVlrIiwiaVhmRVpaU01xdC1RbkluWU5zc1ZpU18yUG1MSWI4elhBUkFQOWN6NzRMbyIsIjhOTFVacEJaVFZXcW01YjRqN0M5Z1RNbkEwMzNjSDh1dmtpWHRYWG1JRTQiLCJLQU9UWUtLT1VRWkRYbXdWVXZjVktJN0pMUWdBbXNHOWhQM19MVl96azM4IiwiS1Y2MTJFNUNLSmdNWHVoQXRzQTBZcDVDWEdKQ3RQdWU0Yi1leFFPcEFxQSJdLCJpc3MiOiJlbW90aW9ubGluay1pc3N1ZXIiLCJ2Y3QiOiJlbW90aW9ubGluayIsImF1ZCI6ImV4YW1wbGVfZ3JvdXBfZXhhbXBsZV9hY2NvdW50IiwiaWF0IjoxNzExMzUxOTUyLCJleHAiOjE3MTE5NTY3NTJ9.5sjdqdMcgpW0GX1oHYbeaffw6dWfzWjRk-BM1Q4EmDmTXcWX15lwEpl8AjsSWeBq3aAq6IvuEOsJm4SwN7Z4AQ~WyJyU2tjV2JwSmxFOE1fWlFJXy1DNzBQREhOY096SGdIRkw5MUJqd3NOIiwgImlwX2FkZHJlc3NlcyIsIFsiMTAuMjU0LjEwMC4yIiwiZmMwMDpmZjAwOjA6YTo6MTAwOjIiXV0~WyIwRDJ4VDBiTXNjNVpaRTlnNm4wQ0RfdzRPSGxvWVJuSC1UVWsxcFRPIiwgImRuc19hZGRyZXNzZXMiLCBbIjEwLjI1NC4xMC4xIiwiZmMwMDpmZjAwOjA6YTo6MTA6MSJdXQ~WyJWSFFKYXN1MElaSVViRWt3Q015clJlWGtieGpKV0NNWHRRUF9PSUZBIiwgImFjY291bnRfbmFtZSIsICJleGFtcGxlX2FjY291bnQiXQ~WyJXZG13eHo4Y014RFZWSEszVC1pQzVQMzd6M2lpRzNsOFdvUkNybXhHIiwgImdyb3VwX25hbWUiLCAiZXhhbXBsZV9ncm91cCJd~WyJjaTk4T2xyeVpkMWpCeDlYQWNRYTJhOExrWTBkcU9tYVh2dV92V2xXIiwgInJvdXRlX25ldHdvcmtzIiwgWyIxMC4yNTQuMC4wLzE2IiwiZmMwMDpmZjAwOjA6YTo6LzY0Il1d~eyJhbGciOiJFZERTQSIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOiJlbC1zZXJ2ZXIiLCJpYXQiOjE3MTEzNTIwNjksImV4cCI6MTcxMTM1NTY2OSwibm9uY2UiOiJub25jZSIsInNkX2hhc2giOiJhMEJQSGtfOUdaNE55WnA2OFVZZWtRRUpOdUxaQ2RvVkF3cDFmZlEwd2lJIn0.RvfdrOSdGHA5JwvKYoOw_eObJ_Mm8cDVdYCKECe1wNpOss8MaIaAjUSjlS9q0Ae7ajR1nAMexLvHPr9X1MO0Bg";

    // Decoding the SD-JWT
    // Extract the payload from the JWT of the SD-JWT after verifying the signature.
    let public_key = std::fs::read(ISSUER_PUBLIC_KEY).unwrap();
    let issuer_verifier = EdDSA.verifier_from_pem(public_key)?;

    let now = std::time::SystemTime::now();

    let sd_jwt: SdJwt = SdJwt::parse(&sd_jwt)?;

    // Holder の公開鍵を SD-JWT の cnf から取り出す
    let (sd_jwt_payload, sd_jwt_header) = jwt::decode_with_verifier(&sd_jwt.jwt, &issuer_verifier)?;
    println!("sd-jwt's header={:?}", sd_jwt_header.to_string());
    println!("sd-jwt's payload={:?}", sd_jwt_payload.to_string());

    // sd-jwt の header の typ が vc+sd-jwt であるかチェック
    match sd_jwt_header.token_type() {
        Some("vc+sd-jwt") => (),
        Some(_) => panic!("token type is not vc+sd-jwt!"),
        _ => panic!("token type is None!"),
    }

    // VP の exp が期限切れになっていないかチェック
    match sd_jwt_payload.expires_at() {
        Some(exp) => {
            if exp < now {
                panic!("kb-jwt's exp is expired!")
            }
        }
        _ => panic!("kb-jwt has no exp!"),
    }

    let holder_public_key_jwk = match sd_jwt_payload.claim("cnf") {
        Some(value) => {
            let jwk = match value.get(&"jwk") {
                Some(v) => v,
                _ => panic!("there is no jwk"),
            };
            let key_materials = if let Some(data) = jwk.as_object() {
                data
            } else {
                panic!("failed to as_object!");
            };
            jwk::Jwk::from_map(key_materials.clone())?
        }
        _ => panic!("there is no holder's public key!"),
    };
    let holder_verifier = EdDSA.verifier_from_jwk(&holder_public_key_jwk)?;

    let (kb_jwt_payload, kb_jwt_header) = match sd_jwt.key_binding_jwt {
        Some(key_binding_jwt) => jwt::decode_with_verifier(&key_binding_jwt, &holder_verifier)?,
        _ => panic!("key_binding_jwt is None"),
    };
    println!("kb-jwt's header={:?}", kb_jwt_header.to_string());
    println!("kb-jwt's payload={:?}", kb_jwt_payload.to_string());
    println!("");

    // kb-jwt の header の typ が kb+jwt であるかチェック
    match kb_jwt_header.token_type() {
        Some("kb+jwt") => (),
        Some(_) => panic!("token type is not kb+jwt!"),
        _ => panic!("token type is None!"),
    }

    // kb-jwt の sd_hash の値が一致するかチェック
    let hasher = Sha256Hasher::new();
    let key_binding_jwt = KeyBindingJwtClaims::new(
        &hasher,
        sd_jwt.jwt.clone(),
        sd_jwt.disclosures.clone(),
        "dummy".to_string(),
        "dummy".to_string(),
        0,
    );
    println!("sd_hash={}", key_binding_jwt.sd_hash);
    if let Some(Value::String(sd_hash)) = kb_jwt_payload.claim("sd_hash") {
        if &key_binding_jwt.sd_hash != sd_hash {
            panic!("sd_hash is not correct!");
        }
    } else {
        panic!("sd_hash is not correct!");
    }

    // kb-jwt の aud に el-server が含まれているかチェック
    match kb_jwt_payload.audience() {
        Some(aud) if aud.contains(&"el-server") => (),
        _ => panic!("audience is not contains el-server!"),
    }

    // VC の exp が期限切れになっていないかチェック
    match kb_jwt_payload.expires_at() {
        Some(exp) => {
            if exp < now {
                panic!("kb-jwt's exp is expired!")
            }
        }
        _ => panic!("kb-jwt has no exp!"),
    }

    // Decode the payload by providing the disclosures that were parsed from the SD-JWT.
    let decoder = SdObjectDecoder::new_with_sha256();
    let decoded = decoder.decode(sd_jwt_payload.claims_set(), &sd_jwt.disclosures)?;
    println!(
        "decoded object: {}",
        serde_json::to_string_pretty(&decoded)?
    );

    Ok(())
}
