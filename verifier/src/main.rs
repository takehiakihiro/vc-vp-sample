use josekit::jws::EdDSA;
use josekit::jwt;
use sd_jwt_payload::{SdJwt, SdObjectDecoder};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Holderの公開鍵をファイルから読み込み
    const ISSUER_PUBLIC_KEY: &str = "../issuer/issuer_public_key_ed25519.pem";
    const HOLDER_PUBLIC_KEY: &str = "../issuer/holder_public_key_ed25519.pem";

    // Holderから提出されたVP（署名付きJWTとして）
    let sd_jwt = "eyJ0eXAiOiJlbW90aW9ubGluaytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJjbmYiOnsia3R5IjoiT0tQIiwidXNlIjoic2lnIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJ1cVlhOTVaN0tIVGRabWdIUTZDRFF3LTNndzBEbEZTTVVvaTNzX0FRaDBNIn0sIl9zZCI6WyJMZmYzdU82QXhfZW9nYzlYWTNpVnRSeTEwT1h5RS1nQjdQc3BzNUlEVFJRIiwiRG8zOHlxQ3A1UUIyODFtdEQxdkpxanYyNmhTZThXSzFSTkFwc2k5TVFVcyIsIjgtREhnZ082VV9aOUR5NmtlVHNfM19fZU52T0RZdWphVHkyVTNNUUFNOTQiLCJfXzdqWHhzVWduY0JGNGk0Y2Q0UTlVMks5b3dVaE5vYlpfYk1FRzYtRUxJIiwiRjJQWWk2WFpVeW9WczN5QWNWaFJkZHZwaDBNSGt1dGlLWkZ1MVhXaHRHNCIsIlhQVHNMX2lzbmZ0R0dNZGc1WFZUbGozX0sxVm5GZS0ycXZXMmdhRTlzSFUiLCJWblg5SjUzUzlTWFlyTWF4ZzZqd2YzUlU0OFNBQ01VckRDanA5b1VnTXlRIiwiS2VlMDlsVzZJem4xYWsyRW5UdGFmeG44RV9wNHN4LU5STmtKQlRhTG1IbyIsIkx5MVRpd3FLazR3SURuNmczQlJsUHdZMjE0SkctX0JHdE1DNTJTRUtoaWsiXSwiYXVkIjoiZXhhbXBsZV9ncm91cF9leGFtcGxlX2FjY291bnQiLCJpYXQiOjE3MTA5OTM3NzgsImV4cCI6MTcxMTU5ODU3OH0.1UXlr9Dh8romq1phReUMkQBw0z5Jb2OJKhiqh6CjulwkDeH5o4YBFYP1Ya5SN6r4G48b9DXcs-cYDzWa9ef0Dg~WyJMZnp0VkJJNjdzMzQxdHN3V0NzcmE1c0NsRkNWM2hneHBsdDZfX0VXIiwgImFjY291bnRfbmFtZSIsICJleGFtcGxlX2FjY291bnQiXQ~WyJKdjNOQXpkaWdEeHJacXNCTUtzbUwxV0VtWXE4NkVMS21jWkpOMEFDIiwgImlwX2FkZHJlc3NlcyIsIFsiMTAuMjU0LjEwMC4yIiwiZmMwMDpmZjAwOjA6YTo6MTAwOjIiXV0~WyIzdXl0Y19CeW5qYVpVbHVqVHlXRU8tX2MyeGlQX0RnWnlXYmpQVEhKIiwgImRuc19hZGRyZXNzZXMiLCBbIjEwLjI1NC4xMC4xIiwiZmMwMDpmZjAwOjA6YTo6MTA6MSJdXQ~WyIyWEs0Mk9NUjRoS2hMRlZJQVRVSnJ0NjdIQVg4TUJhaUY2REFpNmg2IiwgInJvdXRlX25ldHdvcmtzIiwgWyIxMC4yNTQuMC4wLzE2IiwiZmMwMDpmZjAwOjA6YTo6LzY0Il1d~WyJMTWN0YUtZdmN0VlRIaG9ZSklSZ0U1bTQzZHhmMTRKcDNkMl9pcVltIiwgImdyb3VwX25hbWUiLCAiZXhhbXBsZV9ncm91cCJd~eyJhbGciOiJFZERTQSIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOiJlbC1zZXJ2ZXIiLCJpYXQiOjE3MTA5OTUwMDksIm5vbmNlIjoibm9uY2UiLCJzZF9oYXNoIjoieERXMDZUMDJjbkRBd1RHOUIydTNPOENSSUlTb2w5bS1lMC1YTGtPSjhvUSJ9.r0ofURdREE7hNcAXFW9dAPSFNNUs4th9t501h7Xy2kqU4tuLTZRohf1SnT1XG-N3Vw_b93fRpIn67WBjs7QmDQ";

    // Decoding the SD-JWT
    // Extract the payload from the JWT of the SD-JWT after verifying the signature.
    let public_key = std::fs::read(ISSUER_PUBLIC_KEY).unwrap();
    let issuer_verifier = EdDSA.verifier_from_pem(public_key)?;

    // TODO: Holder の公開鍵を SD-JWT の cnf から取り出す
    let public_key = std::fs::read(HOLDER_PUBLIC_KEY).unwrap();
    let holder_verifier = EdDSA.verifier_from_pem(public_key)?;

    let sd_jwt: SdJwt = SdJwt::parse(&sd_jwt)?;

    let (payload, header) = match sd_jwt.key_binding_jwt {
        Some(key_binding_jwt) => jwt::decode_with_verifier(&key_binding_jwt, &holder_verifier)?,
        _ => panic!("key_binding_jwt is None"),
    };
    println!("kb-jwt's header={:?}", header.to_string());
    println!("kb-jwt's payload={:?}", payload.to_string());
    println!("");

    // TODO: kb-jwt の header の typ が kb+jwt であるかチェック
    // TODO: kb-jwt の sd_hash の値が一致するかチェック
    // TODO: kb-jwt の aud が el-server であるかチェック
    // TODO: VC/VP の 両方の exp が期限切れになっていないかチェック

    let (payload, header) = jwt::decode_with_verifier(&sd_jwt.jwt, &issuer_verifier)?;
    println!("sd-jwt's header={:?}", header.to_string());
    println!("sd-jwt's payload={:?}", payload.to_string());

    // Decode the payload by providing the disclosures that were parsed from the SD-JWT.
    let decoder = SdObjectDecoder::new_with_sha256();
    let decoded = decoder.decode(payload.claims_set(), &sd_jwt.disclosures)?;
    println!(
        "decoded object: {}",
        serde_json::to_string_pretty(&decoded)?
    );

    Ok(())
}
