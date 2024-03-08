use sd_jwt_rs::holder::SDJWTHolder;
use sd_jwt_rs::issuer::SDJWTIssuer;
use sd_jwt_rs::verifier::SDJWTVerifier;
use sd_jwt_rs::issuer::ClaimsForSelectiveDisclosureStrategy;
use serde_json;
use std::fs;


fn demo() {
    let issuer_key = fs::read("../issuer/issuer_private_key.pem")?;
    let holder_key = fs::read("../holder/holder_private_key.pem")?;

    let mut issuer = SDJWTIssuer::new(issuer_key, None);
    println!("issuer={:?}", issuer);

    // 現在時刻
    let now = Utc::now();
    let exp = match TimeDelta::try_days(1) {
        Some(one_day) => {
            (now + one_day).timestamp()
        }
        None => {
            println!("Error occurred");
            now.timestamp() + 10
        }
    };
    let now = now.timestamp();

    // VPのペイロード（患者IDのみを含む）
    let claims = serde_json::json!({
        "sub": "1234567890",  // 患者ID
        "address": "1234 Main St",
        "iss": "VCVPSampleIssuer",  // Issuerを識別するための情報
        "iat": now,  // 発行時刻
        "exp": exp,  // 有効期限を1週間後に設定
    });
    println!("claims={:?}", claims);

    let sd_jwt = issuer.issue_sd_jwt(claims, ClaimsForSelectiveDisclosureStrategy::AllLevels, holder_key, add_decoy, SDJWTSerializationFormat::Compact).unwrap();
    println!("sd_jwt={:?}", sd_jwt);

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    println!("holder={:?}", holder);
    let presentation = holder.create_presentation(claims_to_disclosure, None, None, None, None).unwrap();
    println!("presentation={:?}", presentation);

    let verified_claims = SDJWTVerifier::new(presentation, cb_to_resolve_issuer_key, None, None, SDJWTSerializationFormat::Compact).unwrap()
                            .verified_claims;
    println!("verified_claims={:?}", verified_claims);
}

fn main() {
    demo();
}
