use josekit::jws::EdDSA;
use josekit::jwt;
use sd_jwt_payload::{SdJwt, SdObjectDecoder};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Holderの公開鍵をファイルから読み込み
    const ISSUER_PUBLIC_KEY: &str = "../issuer/issuer_public_key_ed25519.pem";
    const HOLDER_PUBLIC_KEY: &str = "../issuer/holder_public_key_ed25519.pem";

    // Holderから提出されたVP（署名付きJWTとして）
    let sd_jwt = "eyJ0eXAiOiJlbW90aW9ubGluaytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJjbmYiOnsia3R5IjoiT0tQIiwidXNlIjoic2lnIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJ1cVlhOTVaN0tIVGRabWdIUTZDRFF3LTNndzBEbEZTTVVvaTNzX0FRaDBNIn0sIl9zZCI6WyItWlRPRHR3UjFoNElvbUFZOW5YQjhibU1NZjhsZHpQMFFjWlg3Zl9pQ0c0IiwiUlctYVR0MjBuYm5JUTRIRWg1Q3U2XzlWV0xNcl85NHhjeFl4QnhORy0xWSIsIkNaZkJHOEJfWENJb3Y0M0daRTUwYVdoRkozNEl3ZWM3Y1BobmZLU3czdlkiLCJZQzhjeW8wb2EyUVNUSTBmQjg1TU9FbU1Oc2R5Q1dhUnN4V2dTSEp3ZGJnIiwiVmMxTWZ3Vl9sVm50dUE2ckVzSkVTd1VTZENid1Nwc0stQjhpZkUtRG1EbyIsIl9tRFNnN2ZuRmlSMkRVTGxtalhZQ1NpX0JRTldZclNrU0lMTzFPRkpGejgiLCJka1MwY1h5LTBJbV9BNnJuLTZkWUJhZDRGQ2FhTG12YUZJTEZaejR2aE1FIiwiTGUydUhXZ1ZjeXhDTXVlMmdtX2NRSHZQS2IxTThiS1ZyNzl3VmhZWjhxQSIsIklZd0t3RGpLd0hGT0lBRUJPNTRST29URmxGVFRFS3A5VUUwUVhFSWZ1QVkiXSwiYXVkIjoiZXhhbXBsZV9ncm91cF9leGFtcGxlX2FjY291bnQiLCJpYXQiOjE3MTA5OTk0NDAsImV4cCI6MTcxMTYwNDI0MH0.Xn8Ap7nOcfy5wCrAtpGe-6u7HdgGPOWKq9yqPmKQcCD1caQwCS7GevRL8kltiHuiSwKQR_5BNE9YPPc51glfDA~WyJfWmc0dDdReW9pb2dPV2Qwbk1wem10NFRzYlR4cnVSTkFaQTZPZGxyIiwgImlwX2FkZHJlc3NlcyIsIFsiMTAuMjU0LjEwMC4yIiwiZmMwMDpmZjAwOjA6YTo6MTAwOjIiXV0~WyJvYVhtZVdiZ1dTZjBfUy12VXJURXhOMTZXUURtM193VVkwalkxcVE0IiwgImFjY291bnRfbmFtZSIsICJleGFtcGxlX2FjY291bnQiXQ~WyJfWE9HMUVlbW1kbGlTaHdHMjdMQmtTSXdkTlVpZEZtaWpuaWlVTGdSIiwgImRuc19hZGRyZXNzZXMiLCBbIjEwLjI1NC4xMC4xIiwiZmMwMDpmZjAwOjA6YTo6MTA6MSJdXQ~WyJfMlZ3bzBYQzc3U0ZiNXF3cVlFbndJa3dmOWRLeUJVYmVlT0UtdnJWIiwgImdyb3VwX25hbWUiLCAiZXhhbXBsZV9ncm91cCJd~WyJldHpGbFRZZ1NSOUxVZW5hRkk1SEhHTTZ2TVZLYkVDSVE5Wmg4MnFsIiwgInJvdXRlX25ldHdvcmtzIiwgWyIxMC4yNTQuMC4wLzE2IiwiZmMwMDpmZjAwOjA6YTo6LzY0Il1d~eyJhbGciOiJFZERTQSIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOiJlbC1zZXJ2ZXIiLCJpYXQiOjE3MTEwMDQ1MzYsIm5vbmNlIjoibm9uY2UiLCJzZF9oYXNoIjoiQ01uemd3VGVaRS1oUl9wYll2b21reXZHWmdXaWp4UTM0WlJHVlVtci16dyJ9.1VTxByZqk6Ojwrz05Dsc77VCmRWhIoJ4ZGHP3p0rZ2YwgCKkuM2kZGno6gffXDg-18c-zMVHoS3wSCzykk6LBA";

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
