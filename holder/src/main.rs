use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use josekit::jws::{EdDSA, JwsHeader};
use josekit::jwt::{self, JwtPayload};
use sd_jwt_payload::{KeyBindingJwtClaims, SdJwt, Sha256Hasher};
use serde_json::Value;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // 秘密鍵をファイルから読み込み
    const ISSUER_PUBLIC_KEY: &str = "../issuer/issuer_public_key_ed25519.pem";
    const HOLDER_PRIVATE_KEY: &str = "../issuer/holder_private_key_ed25519.pem";

    const VC: &str = "eyJ0eXAiOiJlbW90aW9ubGluaytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJjbmYiOnsia3R5IjoiT0tQIiwidXNlIjoic2lnIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJ1cVlhOTVaN0tIVGRabWdIUTZDRFF3LTNndzBEbEZTTVVvaTNzX0FRaDBNIn0sIl9zZCI6WyItWlRPRHR3UjFoNElvbUFZOW5YQjhibU1NZjhsZHpQMFFjWlg3Zl9pQ0c0IiwiUlctYVR0MjBuYm5JUTRIRWg1Q3U2XzlWV0xNcl85NHhjeFl4QnhORy0xWSIsIkNaZkJHOEJfWENJb3Y0M0daRTUwYVdoRkozNEl3ZWM3Y1BobmZLU3czdlkiLCJZQzhjeW8wb2EyUVNUSTBmQjg1TU9FbU1Oc2R5Q1dhUnN4V2dTSEp3ZGJnIiwiVmMxTWZ3Vl9sVm50dUE2ckVzSkVTd1VTZENid1Nwc0stQjhpZkUtRG1EbyIsIl9tRFNnN2ZuRmlSMkRVTGxtalhZQ1NpX0JRTldZclNrU0lMTzFPRkpGejgiLCJka1MwY1h5LTBJbV9BNnJuLTZkWUJhZDRGQ2FhTG12YUZJTEZaejR2aE1FIiwiTGUydUhXZ1ZjeXhDTXVlMmdtX2NRSHZQS2IxTThiS1ZyNzl3VmhZWjhxQSIsIklZd0t3RGpLd0hGT0lBRUJPNTRST29URmxGVFRFS3A5VUUwUVhFSWZ1QVkiXSwiYXVkIjoiZXhhbXBsZV9ncm91cF9leGFtcGxlX2FjY291bnQiLCJpYXQiOjE3MTA5OTk0NDAsImV4cCI6MTcxMTYwNDI0MH0.Xn8Ap7nOcfy5wCrAtpGe-6u7HdgGPOWKq9yqPmKQcCD1caQwCS7GevRL8kltiHuiSwKQR_5BNE9YPPc51glfDA~WyJfWmc0dDdReW9pb2dPV2Qwbk1wem10NFRzYlR4cnVSTkFaQTZPZGxyIiwgImlwX2FkZHJlc3NlcyIsIFsiMTAuMjU0LjEwMC4yIiwiZmMwMDpmZjAwOjA6YTo6MTAwOjIiXV0~WyJvYVhtZVdiZ1dTZjBfUy12VXJURXhOMTZXUURtM193VVkwalkxcVE0IiwgImFjY291bnRfbmFtZSIsICJleGFtcGxlX2FjY291bnQiXQ~WyJfWE9HMUVlbW1kbGlTaHdHMjdMQmtTSXdkTlVpZEZtaWpuaWlVTGdSIiwgImRuc19hZGRyZXNzZXMiLCBbIjEwLjI1NC4xMC4xIiwiZmMwMDpmZjAwOjA6YTo6MTA6MSJdXQ~WyJfMlZ3bzBYQzc3U0ZiNXF3cVlFbndJa3dmOWRLeUJVYmVlT0UtdnJWIiwgImdyb3VwX25hbWUiLCAiZXhhbXBsZV9ncm91cCJd~WyIzUGhDWW1JNzExeGkzdVQ4MmdjOHJyZVVnOEtyaVljWXZ1bzBhNmZJIiwgInJlYWxfbmFtZSIsICJ0YWtlaGlha2loaXJvIl0~WyJ4bFd6NFN3ZGo2N05BME1iN2x4alNqY1QwYWRWYXBzMGY1aVBYRmZHIiwgImNvbXBhbnkiLCAiZnJlZWJpdCJd~WyJldHpGbFRZZ1NSOUxVZW5hRkk1SEhHTTZ2TVZLYkVDSVE5Wmg4MnFsIiwgInJvdXRlX25ldHdvcmtzIiwgWyIxMC4yNTQuMC4wLzE2IiwiZmMwMDpmZjAwOjA6YTo6LzY0Il1d~";

    let sd_jwt: SdJwt = SdJwt::parse(&VC)?;

    let public_key = std::fs::read(ISSUER_PUBLIC_KEY).unwrap();
    let issuer_verifier = EdDSA.verifier_from_pem(public_key)?;
    let (payload, header) = jwt::decode_with_verifier(&sd_jwt.jwt, &issuer_verifier)?;
    println!("sd-jwt's header={:?}", header.to_string());
    println!("sd-jwt's payload={:?}", payload.to_string());
    println!("");

    // disclosures の中から、公開したいものを Base64url decode して中身を見て選別する
    let mut disclosures = Vec::new();

    for encoded_str in sd_jwt.disclosures {
        let mut buffer = Vec::<u8>::new();
        let check_strings = [
            "ip_addresses",
            "dns_addresses",
            "route_networks",
            "account_name",
            "group_name",
        ];

        // Base64urlデコードを試みる
        if URL_SAFE_NO_PAD
            .decode_vec(encoded_str.as_bytes(), &mut buffer)
            .is_ok()
        {
            // デコードされた文字列を取得
            if let Ok(decoded_str) = String::from_utf8(buffer) {
                // JSONとしてパース
                if let Ok(json) = serde_json::from_str::<Value>(&decoded_str) {
                    println!("checking decoded={:?}, encoded={}", json, encoded_str);
                    // JSONが配列形式であり、2番目の要素が指定した文字列のいずれかに一致するかチェック
                    if json.as_array().map_or(false, |arr| {
                        arr.get(1).map_or(false, |second_element| {
                            check_strings.contains(&second_element.as_str().unwrap_or(""))
                        })
                    }) {
                        // 条件を満たす場合、元のBase64urlエンコードされた文字列を保存
                        println!("MATCH! decoded={:?}, encoded={}", json, encoded_str);
                        disclosures.push(encoded_str.to_string());
                    }
                }
            }
        }
    }
    let nonce = "nonce".to_string();
    let audience = "el-server".to_string();
    let hasher = Sha256Hasher::new();
    let key_binding_jwt = KeyBindingJwtClaims::new(
        &hasher,
        sd_jwt.jwt.clone(),
        disclosures.clone(),
        nonce,
        audience,
        0,
    );

    let holder_private_key = std::fs::read(HOLDER_PRIVATE_KEY).unwrap();
    let signer = EdDSA.signer_from_pem(holder_private_key)?;
    let mut header = JwsHeader::new();
    header.set_algorithm("EdDSA"); // EdDSA署名アルゴリズムの指定
    header.set_token_type("kb+jwt");
    let mut payload = JwtPayload::new();
    payload.set_audience([key_binding_jwt.aud.clone()].to_vec());
    let now = std::time::SystemTime::now();
    payload.set_issued_at(&now);
    let expires_at = now + std::time::Duration::from_secs(60 * 60);
    payload.set_expires_at(&expires_at);
    payload.set_claim("nonce", Some(Value::String(key_binding_jwt.nonce)))?;
    payload.set_claim("sd_hash", Some(Value::String(key_binding_jwt.sd_hash)))?;
    let key_binding_jwt = jwt::encode_with_signer(&payload, &header, &signer)?;
    println!("kb-jwt: {:?}", key_binding_jwt);
    println!("");

    let sd_jwt: SdJwt = SdJwt::new(sd_jwt.jwt, disclosures.clone(), Some(key_binding_jwt));
    let sd_jwt: String = sd_jwt.presentation();

    println!("VP={:?}", sd_jwt);

    Ok(())
}
