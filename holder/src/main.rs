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

    const VC: &str = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsInVzZSI6InNpZyIsImNydiI6IkVkMjU1MTkiLCJ4IjoidXFZYTk1WjdLSFRkWm1nSFE2Q0RRdy0zZ3cwRGxGU01Vb2kzc19BUWgwTSJ9fSwiX3NkIjpbIndlZ1prbEIzR1hEd1FyVC1ObmRtMGVkYVBxN0FtaHpUbVRHQ0dISmFBVTgiLCI4Y0ZRTzlaMXVSRnBQNDNFLXUyVkFXRVNpODFQbVB2empDYWxDLVNlODBjIiwiUDctRktvQ2ZSUzBmaWtidjM2QTB3NDhXcDdZRzcyLTBWNm5Wa2Y4Y1puYyIsIjJMSkpEeVU5c0wzbE1wRUtTRW9DZ25HMV9ET01BaUNYLWNRVFBTbFQydmMiLCJLNGFobFAyRXVaUGhIdFZiLXRrQ2FiZVBKVHJFaEZqZ2RuXzIwNGVraVlrIiwiaVhmRVpaU01xdC1RbkluWU5zc1ZpU18yUG1MSWI4elhBUkFQOWN6NzRMbyIsIjhOTFVacEJaVFZXcW01YjRqN0M5Z1RNbkEwMzNjSDh1dmtpWHRYWG1JRTQiLCJLQU9UWUtLT1VRWkRYbXdWVXZjVktJN0pMUWdBbXNHOWhQM19MVl96azM4IiwiS1Y2MTJFNUNLSmdNWHVoQXRzQTBZcDVDWEdKQ3RQdWU0Yi1leFFPcEFxQSJdLCJpc3MiOiJlbW90aW9ubGluay1pc3N1ZXIiLCJ2Y3QiOiJlbW90aW9ubGluayIsImF1ZCI6ImV4YW1wbGVfZ3JvdXBfZXhhbXBsZV9hY2NvdW50IiwiaWF0IjoxNzExMzUxOTUyLCJleHAiOjE3MTE5NTY3NTJ9.5sjdqdMcgpW0GX1oHYbeaffw6dWfzWjRk-BM1Q4EmDmTXcWX15lwEpl8AjsSWeBq3aAq6IvuEOsJm4SwN7Z4AQ~WyJyU2tjV2JwSmxFOE1fWlFJXy1DNzBQREhOY096SGdIRkw5MUJqd3NOIiwgImlwX2FkZHJlc3NlcyIsIFsiMTAuMjU0LjEwMC4yIiwiZmMwMDpmZjAwOjA6YTo6MTAwOjIiXV0~WyI1dFljM0FkRkNFd19ZTm0zeU9lby1kYi1sS0JWVkVCZVpic3pWNFFPIiwgInJlYWxfbmFtZSIsICJ0YWtlaGlha2loaXJvIl0~WyIwRDJ4VDBiTXNjNVpaRTlnNm4wQ0RfdzRPSGxvWVJuSC1UVWsxcFRPIiwgImRuc19hZGRyZXNzZXMiLCBbIjEwLjI1NC4xMC4xIiwiZmMwMDpmZjAwOjA6YTo6MTA6MSJdXQ~WyJWSFFKYXN1MElaSVViRWt3Q015clJlWGtieGpKV0NNWHRRUF9PSUZBIiwgImFjY291bnRfbmFtZSIsICJleGFtcGxlX2FjY291bnQiXQ~WyJXZG13eHo4Y014RFZWSEszVC1pQzVQMzd6M2lpRzNsOFdvUkNybXhHIiwgImdyb3VwX25hbWUiLCAiZXhhbXBsZV9ncm91cCJd~WyJjaTk4T2xyeVpkMWpCeDlYQWNRYTJhOExrWTBkcU9tYVh2dV92V2xXIiwgInJvdXRlX25ldHdvcmtzIiwgWyIxMC4yNTQuMC4wLzE2IiwiZmMwMDpmZjAwOjA6YTo6LzY0Il1d~WyJtc1oxaEd5MzlmRVlyVnQwUS1jLXg2TnJCTFNnLVRLR29LOVRhV21MIiwgImNvbXBhbnkiLCAiZnJlZWJpdCJd~";

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
