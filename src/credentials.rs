use std::{borrow::Cow, ops::DerefMut};

use anyhow::Context as _;
use axum::{http::StatusCode, Extension, Json};
use iref::UriBuf;
use serde::{Deserialize, Serialize};
use ssi::{
    claims::{
        data_integrity::{AnySignatureOptions, CryptographicSuite, CryptosuiteString},
        vc::{
            syntax::{MaybeIdentifiedTypedObject, NonEmptyObject},
            v1::ToJwtClaims,
            AnyJsonCredential, AnySpecializedJsonCredential,
        },
        JsonCredentialOrJws, SignatureEnvironment, SignatureError, VerificationParameters,
    },
    dids::{DIDResolver, VerificationMethodDIDResolver, DID},
    json_ld::syntax::Context,
    prelude::*,
    status::{
        any::{AnyEntrySet, AnyStatusMap},
        bitstring_status_list::{
            BitstringStatusList, BitstringStatusListEntry, SizedStatusList, StatusPurpose,
            StatusSize, BITSTRING_STATUS_LIST_ENTRY_TYPE,
        },
        client::StatusMapProvider,
        StatusMapEntry,
    },
    verification_methods::{
        AnyMethod, GenericVerificationMethod, MaybeJwkVerificationMethod, ReferenceOrOwned,
        VerificationMethodResolver,
    },
};
use static_iref::iri;
use tracing::{debug, warn};

use crate::{
    config::Config,
    dids::{AnyDidMethod, CustomVerificationMethodResolver},
    error::Error,
    keys::KeyMapSigner,
    utils::{
        self, Check, CustomErrorJson, JWTOrLDPOptions, ProofFormat, VerificationOptions,
        VerificationResult,
    },
    KeyMap,
};

#[derive(Deserialize, Debug)]
pub struct IssueRequest {
    pub credential: AnyJsonCredential,
    pub options: JWTOrLDPOptions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueResponse {
    pub verifiable_credential: JsonCredentialOrJws,
}

#[axum::debug_handler]
pub async fn issue(
    Extension(config): Extension<Config>,
    Extension(keys): Extension<KeyMap>,
    CustomErrorJson(mut req): CustomErrorJson<IssueRequest>,
) -> Result<(StatusCode, Json<IssueResponse>), Error> {
    debug!("{req:?}");

    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let resolver = CustomVerificationMethodResolver {
        did_resolver: resolver,
        keys: keys.clone(),
    };

    let issuer = match req.credential {
        AnySpecializedJsonCredential::V1(ref vc) => vc.issuer.clone(),
        AnySpecializedJsonCredential::V2(ref vc) => {
            for subject in vc.credential_subjects.clone() {
                if NonEmptyObject::try_from_object(subject).is_err() {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "Empty credential subject".to_string(),
                    ))?;
                }
            }
            vc.issuer.clone()
        }
    };

    // Find an appropriate verification method.
    let public_jwk = match &req.options.ldp_options.input_options.verification_method {
        Some(method) => {
            let method = resolver
                .resolve_verification_method(Some(issuer.id().as_iri()), Some(method.borrowed()))
                .await
                .context("Could not resolve VM")?;
            method
                .try_to_jwk()
                .context("Could not get any verification method for issuer DID")?
                .into_owned()
        }
        None => {
            if let Ok(did) = DID::new(issuer.id()) {
                let output = resolver
                    .did_resolver
                    .resolve(did)
                    .await
                    .context("Could not fetch issuer DID document")?;

                let method = output
                    .document
                    .into_document()
                    .into_any_verification_method()
                    .context("Could not get any verification method for issuer DID document")?;

                req.options.ldp_options.input_options.verification_method =
                    Some(ReferenceOrOwned::Reference(method.id.clone().into_iri()));

                let method = Cow::<AnyMethod>::Owned(
                    AnyMethod::try_from(GenericVerificationMethod::from(method))
                        .context("Could not convert VM")?,
                );
                method
                    .try_to_jwk()
                    .context("Could not get any verification method for issuer DID")?
                    .into_owned()
            } else {
                req.options.ldp_options.input_options.verification_method = Some(
                    ReferenceOrOwned::Reference(issuer.id().to_owned().into_iri()),
                );
                keys.keys().find(|_| true).unwrap().clone()
            }
        }
    };

    if req.options.ldp_options.type_ == Some("DataIntegrityProof".to_string()) {
        if req.options.ldp_options.cryptosuite.is_none() {
            req.options.ldp_options.cryptosuite = Some(
                CryptosuiteString::new(
                    utils::pick_from_jwk(&public_jwk).context("Could not pick cryptosuite")?,
                )
                .context("Could not validate cryptosuite string")?,
            )
        }
        if let AnySpecializedJsonCredential::V1(ref vc) = req.credential {
            if !vc
                .context
                .contains_iri(iri!("https://w3id.org/security/data-integrity/v1"))
                && !vc
                    .context
                    .contains_iri(iri!("https://w3id.org/security/data-integrity/v2"))
            {
                let di_context = iri!("https://w3id.org/security/data-integrity/v2").into();
                req.options.ldp_options.input_options.context =
                    match req.options.ldp_options.input_options.context {
                        None => Some(Context::one(di_context)),
                        Some(Context::One(c)) => Some(Context::Many(vec![c, di_context])),
                        Some(Context::Many(mut c)) => {
                            c.push(di_context);
                            Some(Context::Many(c))
                        }
                    };
            }
        }
    }

    match req.credential {
        AnySpecializedJsonCredential::V1(ref mut vc) => {
            if vc.issuance_date.is_none() {
                vc.issuance_date = Some(DateTime::now_ms());
            }
        }
        AnySpecializedJsonCredential::V2(ref mut vc) => {
            if let Some(status_entry) = vc.extra_properties.get_mut("statusEntry") {
                // Temporary fix for invalid data
                let status_entry_object = status_entry
                    .as_object_mut()
                    .context("statusEntry not an object")?;
                //if let Ok(Some(index)) = status_entry_object.get_unique("statusListIndex") {
                //    if index.is_boolean() {
                //        status_entry_object.insert("statusListIndex".into(), "1".into());
                //    }
                //}
                status_entry_object.insert("statusPurpose".into(), "revocation".into());
                let deserialized: Result<BitstringStatusListEntry, _> =
                    serde_json::from_str(&status_entry.to_string());
                match deserialized {
                    Ok(_) => {}
                    Err(e) => {
                        debug!("Invalid credential status: {e}");
                        return Err((
                            StatusCode::BAD_REQUEST,
                            format!("Invalid credential status: {e}"),
                        ))?;
                    }
                }
            }
            let status_list_url: UriBuf = config
                .issuer
                .base_url
                .join("statuslist")
                .context("Could not join status list URL")?
                .to_string()
                .parse()
                .context("Could not parse status list URL")?;
            let status: MaybeIdentifiedTypedObject = serde_json::from_value(serde_json::json!({
                "type": BITSTRING_STATUS_LIST_ENTRY_TYPE,
                "statusPurpose": "revocation",
                "statusListIndex": "1",
                "statusListCredential": status_list_url
            }))
            .unwrap();
            vc.credential_status = vec![status];
        }
    }

    let res = match req.options.proof_format {
        ProofFormat::Jwt => JsonCredentialOrJws::Jws(
            if let AnySpecializedJsonCredential::V1(vc) = req.credential {
                vc.to_jwt_claims()
                    .context("Could not convert VC to JWT claims")?
                    .sign(&public_jwk)
                    .await
                    .context("Could not sign JWT VC")?
                    .as_str()
                    .parse()
                    .unwrap()
            } else {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Credential has to be VCDM v1 to be converted to JWT".to_string(),
                ))?;
            },
        ),
        ProofFormat::Ldp => {
            let suite = req
                .options
                .ldp_options
                .select_suite(&public_jwk)
                .context("Could not select suite from JWK")?;

            let signer = KeyMapSigner(keys).into_local();
            let mut signature_options: AnySignatureOptions = Default::default();
            signature_options.mandatory_pointers = req
                .options
                .ldp_options
                .mandatory_pointers
                .unwrap_or_default();
            let mut vc = match suite
                .sign_with(
                    SignatureEnvironment::default(),
                    req.credential,
                    resolver,
                    signer,
                    req.options.ldp_options.input_options,
                    signature_options,
                )
                .await
            {
                Ok(vc) => vc,
                Err(SignatureError::Other(e)) => {
                    return Err((StatusCode::BAD_REQUEST, format!("Failed to sign VC: {e}")))?
                }
                Err(e) => Err(e).context("Failed to sign VC")?,
            };

            for proof in vc.proofs.iter_mut() {
                if let Some(proof_context) = proof.context.clone() {
                    match vc.claims {
                        AnySpecializedJsonCredential::V1(ref mut vc) => {
                            vc.context.extend(proof_context);
                        }
                        AnySpecializedJsonCredential::V2(ref mut vc) => {
                            vc.context.extend(proof_context);
                        }
                    }
                    proof.context = None;
                }
            }

            JsonCredentialOrJws::Credential(vc)
        }
    };
    debug!("{res:?}");
    Ok((
        StatusCode::CREATED,
        Json(IssueResponse {
            verifiable_credential: res,
        }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    pub verifiable_credential: JsonCredentialOrJws,

    #[serde(default)]
    pub options: VerificationOptions,
}

pub async fn verify(
    CustomErrorJson(req): CustomErrorJson<VerifyRequest>,
) -> Result<Json<VerificationResult>, Error> {
    let resolver = AnyDidMethod::default().into_vm_resolver();
    let verifier = VerificationParameters::from_resolver(&resolver);
    let res = match (req.options.proof_format, req.verifiable_credential) {
        (Some(ProofFormat::Ldp) | None, JsonCredentialOrJws::Credential(vc)) => {
            if vc.proofs.is_empty() {
                return Err((StatusCode::BAD_REQUEST, "No proof in VC".to_string()))?;
            }
            let mut res = match vc.verify(&verifier).await {
                Ok(Ok(())) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec![],
                },
                Ok(Err(err)) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec![err.to_string()],
                },
                Err(err) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec![err.to_string()],
                },
            };
            for proof in vc.proofs {
                if let Some(ref challenge) = req.options.challenge {
                    if Some(challenge.clone()) != proof.challenge {
                        res.errors.insert(0, "Invalid challenge".into());
                    }
                }
                if let Some(ref domain) = req.options.domain {
                    if !proof.domains.contains(domain) {
                        res.errors.insert(0, "Invalid domain".into());
                    }
                }
                if let Some(ref proof_purpose) = req.options.expected_proof_purpose {
                    if proof_purpose != &proof.proof_purpose {
                        res.errors.insert(0, "Invalid proof purpose".into());
                    }
                }
            }
            res
        }
        (Some(ProofFormat::Jwt) | None, JsonCredentialOrJws::Jws(vc_jwt)) => {
            // TODO: only the JWS is verified this way. We must also validate the inner VC.
            match vc_jwt.verify(&verifier).await {
                Ok(Ok(())) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec![],
                },
                Ok(Err(err)) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec![err.to_string()],
                },
                Err(err) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec![err.to_string()],
                },
            }
        }
        (Some(proof_format), vc) => {
            let err_msg = format!(
                "Credential/proof format mismatch. Proof format: {}, credential format: {}",
                proof_format,
                match vc {
                    JsonCredentialOrJws::Jws(_) => "JWT".to_string(),
                    JsonCredentialOrJws::Credential(_) => "LDP".to_string(),
                }
            );
            return Err((StatusCode::BAD_REQUEST, err_msg).into());
        }
    };
    if !res.errors.is_empty() {
        return Err((StatusCode::BAD_REQUEST, format!("{:?}", res.errors)).into());
    }
    Ok(Json(res))
}

#[cfg(test)]
mod test {
    use figment::{
        providers::{Format, Toml},
        Figment,
    };
    use serde_json::json;
    use test_log::test;

    use crate::test::default_keys;

    use super::*;

    fn config() -> crate::config::Config {
        Figment::new()
            .merge(Toml::string(include_str!("../defaults.toml")).nested())
            .select("test")
            .extract()
            .expect("Unable to load config")
    }

    #[test(tokio::test)]
    async fn issue_di_ed25519() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "urn:uuid:040d4921-4756-447b-99ad-8d4978420e91",
            "type": [
              "VerifiableCredential"
            ],
            "issuer": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD",
            "credentialSubject": {
              "id": "did:key:z6MktKwz7Ge1Yxzr4JHavN33wiwa8y81QdcMRLXQsrH9T53b"
            }
          },
          "options": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022"
          }
        }))
        .unwrap();

        let _ = issue(Extension(config()), Extension(keys), CustomErrorJson(req))
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    async fn issue_p256() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "urn:uuid:040d4921-4756-447b-99ad-8d4978420e91",
            "type": [
              "VerifiableCredential"
            ],
            "issuer": "did:key:zDnaej4NHTz2DtpMByubtLGzZfEjYor4ffJWLuW2eJ4KkZ3r2",
            "credentialSubject": {
              "id": "did:key:z6MktKwz7Ge1Yxzr4JHavN33wiwa8y81QdcMRLXQsrH9T53b"
            }
          },
          "options": {
            "type": "DataIntegrityProof"
          }
        }))
        .unwrap();

        let _ = issue(Extension(config()), Extension(keys), CustomErrorJson(req))
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    async fn issue_ed25519() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "urn:uuid:040d4921-4756-447b-99ad-8d4978420e91",
            "type": [
              "VerifiableCredential"
            ],
            "issuer": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD",
            "credentialSubject": {
              "id": "did:key:z6MktKwz7Ge1Yxzr4JHavN33wiwa8y81QdcMRLXQsrH9T53b"
            }
          },
          "options": {
            "type": "Ed25519Signature2020"
          }
        }))
        .unwrap();

        let _ = issue(Extension(config()), Extension(keys), CustomErrorJson(req))
            .await
            .unwrap();
    }

    #[test]
    fn deserialize_body_issuer_test_suite() {
        let _: IssueRequest = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1"
            ],
            "type": [
              "VerifiableCredential"
            ],
            "credentialSubject": {
              "id": "did:key:z6MkhTNL7i2etLerDK8Acz5t528giE5KA4p75T6ka1E1D74r"
            },
            "issuanceDate": "2024-06-01T09:09:48Z",
            "id": "urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f",
            "issuer": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD"
          },
          "options": {
            "type": "Ed25519Signature2020"
          }
        }
        ))
        .unwrap();
    }

    #[test(tokio::test)]
    async fn verify_valid_vc_verifier_test_suite() {
        let req = serde_json::from_value(json!({
          "verifiableCredential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "id": "urn:uuid:0c71c76a-5dca-4537-a86d-7851b8f85c25",
            "type": [
              "VerifiableCredential"
            ],
            "credentialSubject": {
              "id": "did:key:z6MkhTNL7i2etLerDK8Acz5t528giE5KA4p75T6ka1E1D74r"
            },
            "issuer": "did:key:z6MkgND5U5Kedizov5nxeh2ZCVUTDRSmAfbNqPhzCq8b72Ra",
            "issuanceDate": "2024-06-01T09:34:12.834Z",
            "proof": {
              "type": "Ed25519Signature2020",
              "proofPurpose": "assertionMethod",
              "proofValue": "zB6pd365FSMVZbkn51nhEtLCyuxLj5qGFaZi6uv1dweLUiR1qvCqM1cqaAFMgjyB5ZATvU2brPDn6z6XwxoFyeHD",
              "verificationMethod": "did:key:z6MkgND5U5Kedizov5nxeh2ZCVUTDRSmAfbNqPhzCq8b72Ra#z6MkgND5U5Kedizov5nxeh2ZCVUTDRSmAfbNqPhzCq8b72Ra",
              "created": "2024-06-01T09:34:12.834Z"
            }
          },
          "options": {
            "checks": [
              "proof"
            ]
          }
        })).unwrap();
        let _ = verify(CustomErrorJson(req)).await.unwrap();
    }

    #[test(tokio::test)]
    async fn issue_valid_di_eddsa_test_suite() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "urn:uuid:991721d2-2336-4979-aa10-1709061b7261",
            "type": [
              "VerifiableCredential"
            ],
            "issuer": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD",
            "issuanceDate": "2020-03-16T22:37:26.544Z",
            "credentialSubject": {
              "id": "did:key:z6MktKwz7Ge1Yxzr4JHavN33wiwa8y81QdcMRLXQsrH9T53b"
            }
          },
          "options": {
            "type": "DataIntegrityProof"
          }
        }))
        .unwrap();
        let _ = issue(Extension(config()), Extension(keys), CustomErrorJson(req))
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    async fn issue_vcdm2_did_example() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/ns/credentials/v2"
            ],
            "type": [
              "VerifiableCredential"
            ],
            "issuer": "did:example:issuer",
            "credentialSubject": {
              "id": "did:example:subject"
            }
          },
          "options": {
            "type": "Ed25519Signature2020"
          }
        }))
        .unwrap();
        let _ = issue(Extension(config()), Extension(keys), CustomErrorJson(req))
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    async fn issue_vcdm2_did_example_evidence() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              {
                "DocumentVerification2018": "https://example.org/examples#DocumentVerification2018"
              }
            ],
            "type": [
              "VerifiableCredential"
            ],
            "issuer": "did:example:issuer",
            "credentialSubject": {
              "id": "did:example:subject"
            },
            "evidence": [
              {
                "type": "DocumentVerification2018"
              },
              {
                "type": "DocumentVerification2018"
              }
            ]
          },
          "options": {
            "type": "Ed25519Signature2020"
          }
        }))
        .unwrap();
        let _ = issue(Extension(config()), Extension(keys), CustomErrorJson(req))
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    async fn issue_vcdm2_validuntil() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/ns/credentials/v2"
            ],
            "type": [
              "VerifiableCredential"
            ],
            "issuer": "did:example:issuer",
            "validFrom": "2023-02-26T01:19:19Z",
            "validUntil": "2023-02-26T01:19:20Z",
            "credentialSubject": {
              "id": "did:example:subject"
            }
          },
          "options": {
            "type": "Ed25519Signature2020"
          }
        }))
        .unwrap();
        let _ = issue(Extension(config()), Extension(keys), CustomErrorJson(req))
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    async fn issue_vcdm2_non_did_issuer() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/ns/credentials/v2"
            ],
            "type": [
              "VerifiableCredential"
            ],
            "issuer": "https://some-url/issuer/foo",
            "credentialSubject": {
              "id": "did:example:subject"
            }
          },
          "options": {
            "type": "Ed25519Signature2020"
          }
        }))
        .unwrap();
        let _ = issue(Extension(config()), Extension(keys), CustomErrorJson(req))
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    async fn issue_vcdm2_unmapped_type() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              {"@vocab": null}
            ],
            "type": [
              "VerifiableCredential",
              "ExampleTestCredential"
            ],
            "issuer": "did:example:issuer",
            "credentialSubject": {
              "id": "did:example:subject"
            }
          },
          "options": {
             "type": "Ed25519Signature2020"
           }
        }))
        .unwrap();
        let res = issue(Extension(config()), Extension(keys), CustomErrorJson(req)).await;
        assert!(res.is_err());
    }

    #[test(tokio::test)]
    async fn verify_valid_vc_ecdsa_p256() {
        let req = serde_json::from_value(json!({
          "verifiableCredential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              {
                "@protected": true,
                "DriverLicenseCredential": "urn:example:DriverLicenseCredential",
                "DriverLicense": {
                  "@id": "urn:example:DriverLicense",
                  "@context": {
                    "@protected": true,
                    "id": "@id",
                    "type": "@type",
                    "documentIdentifier": "urn:example:documentIdentifier",
                    "dateOfBirth": "urn:example:dateOfBirth",
                    "expirationDate": "urn:example:expiration",
                    "issuingAuthority": "urn:example:issuingAuthority"
                  }
                },
                "driverLicense": {
                  "@id": "urn:example:driverLicense",
                  "@type": "@id"
                }
              },
              "https://w3id.org/security/data-integrity/v2"
            ],
            "id": "urn:uuid:36245ee9-9074-4b05-a777-febff2e69757",
            "type": [
              "VerifiableCredential",
              "DriverLicenseCredential"
            ],
            "credentialSubject": {
              "id": "urn:uuid:1a0e4ef5-091f-4060-842e-18e519ab9440",
              "driverLicense": {
                "type": "DriverLicense",
                "documentIdentifier": "T21387yc328c7y32h23f23",
                "dateOfBirth": "01-01-1990",
                "expirationDate": "01-01-2030",
                "issuingAuthority": "VA"
              }
            },
            "issuer": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
            "issuanceDate": "2024-07-03T10:31:54Z",
            "proof": {
              "type": "DataIntegrityProof",
              "created": "2024-07-03T10:31:54Z",
              "verificationMethod": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
              "cryptosuite": "ecdsa-rdfc-2019",
              "proofPurpose": "assertionMethod",
              "proofValue": "zWWuXUjmHd9ZWwATq8ZcjyFxSjEHubzBGrNopWyVRdrnpnb9YQ9K8b4KC7T3sBKg2yz4QUZ2oT3ecizYRkqjMEg2"
            }
          },
          "options": {
            "checks": [
              "proof"
            ]
          }
        })).unwrap();
        let _ = verify(CustomErrorJson(req)).await.unwrap();
    }

    #[ignore = "https://github.com/w3c/vc-di-ecdsa-test-suite/issues/86"]
    #[test(tokio::test)]
    async fn verify_valid_vc_ecdsa_p384() {
        let req = serde_json::from_value(json!({
          "verifiableCredential": {
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              {
                "@protected": true,
                "DriverLicenseCredential": "urn:example:DriverLicenseCredential",
                "DriverLicense": {
                  "@id": "urn:example:DriverLicense",
                  "@context": {
                    "@protected": true,
                    "id": "@id",
                    "type": "@type",
                    "documentIdentifier": "urn:example:documentIdentifier",
                    "dateOfBirth": "urn:example:dateOfBirth",
                    "expirationDate": "urn:example:expiration",
                    "issuingAuthority": "urn:example:issuingAuthority"
                  }
                },
                "driverLicense": {
                  "@id": "urn:example:driverLicense",
                  "@type": "@id"
                }
              }
            ],
            "id": "urn:uuid:36245ee9-9074-4b05-a777-febff2e69757",
            "type": [
              "VerifiableCredential",
              "DriverLicenseCredential"
            ],
            "credentialSubject": {
              "id": "urn:uuid:1a0e4ef5-091f-4060-842e-18e519ab9440",
              "driverLicense": {
                "type": "DriverLicense",
                "documentIdentifier": "T21387yc328c7y32h23f23",
                "dateOfBirth": "01-01-1990",
                "expirationDate": "01-01-2030",
                "issuingAuthority": "VA"
              }
            },
            "issuer": "did:key:z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ",
            "proof": {
              "type": "DataIntegrityProof",
              "created": "2024-07-03T13:50:33Z",
              "verificationMethod": "did:key:z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ#z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ",
              "cryptosuite": "ecdsa-rdfc-2019",
              "proofPurpose": "assertionMethod",
              "proofValue": "z2EtWvK6tYMLdHs3Yw3yPUS8YK2ajrboDX3G7eLwMm2nz4GBy3arnEDGQXJd4EFWjQo1VZMYv8G7iFR9sgCwKZGC2evpwgxy4pRVeSx7uYUnh6ZUydmKBgoGu7oMRydGRLwdG"
            }
          },
          "options": {
            "checks": [
              "proof"
            ]
          }
        })).unwrap();
        let _ = verify(CustomErrorJson(req)).await.unwrap();
    }

    #[test(tokio::test)]
    async fn issue_di_bbs_2023() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "urn:uuid:5e1c02ab-2676-4e84-a95c-36845c11a462",
            "type": [
              "VerifiableCredential"
            ],
            "issuer": "did:key:zUC7Ker8jsi8tkhwz9CN1MdmunYbgXg4B7iTWJoPFiPty3ZrFg8j3a5bBX1hozUZxck8C73UunuWBZBy7PtYDCe9XYqGjWzXRqyLFqxWGo5nGArAvndYVqSQJhULMJFq5KKgW2X",
            "issuanceDate": "2020-03-16T22:37:26.544Z",
            "credentialSubject": {
              "id": "did:key:z6MktKwz7Ge1Yxzr4JHavN33wiwa8y81QdcMRLXQsrH9T53b"
            }
          },
          "options": {
            "type": "DataIntegrityProof"
          }
        }))
        .unwrap();
        let _ = issue(Extension(config()), Extension(keys), CustomErrorJson(req))
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    async fn issue_bbs_2023_v1() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              {
                "@protected": true,
                "DriverLicenseCredential": "urn:example:DriverLicenseCredential",
                "DriverLicense": {
                  "@id": "urn:example:DriverLicense",
                  "@context": {
                    "@protected": true,
                    "id": "@id",
                    "type": "@type",
                    "documentIdentifier": "urn:example:documentIdentifier",
                    "dateOfBirth": "urn:example:dateOfBirth",
                    "expirationDate": "urn:example:expiration",
                    "issuingAuthority": "urn:example:issuingAuthority"
                  }
                },
                "driverLicense": {
                  "@id": "urn:example:driverLicense",
                  "@type": "@id"
                }
              }
            ],
            "id": "urn:uuid:b5026734-8318-4eba-8fe3-773e93404c82",
            "type": [
              "VerifiableCredential",
              "DriverLicenseCredential"
            ],
            "credentialSubject": {
              "id": "urn:uuid:1a0e4ef5-091f-4060-842e-18e519ab9440",
              "driverLicense": {
                "type": "DriverLicense",
                "documentIdentifier": "T21387yc328c7y32h23f23",
                "dateOfBirth": "01-01-1990",
                "expirationDate": "01-01-2030",
                "issuingAuthority": "VA"
              }
            },
            "issuer": "did:key:zUC7Ker8jsi8tkhwz9CN1MdmunYbgXg4B7iTWJoPFiPty3ZrFg8j3a5bBX1hozUZxck8C73UunuWBZBy7PtYDCe9XYqGjWzXRqyLFqxWGo5nGArAvndYVqSQJhULMJFq5KKgW2X",
            "issuanceDate": "2024-07-10T07:56:45Z"
          },
          "options": {
            "type": "DataIntegrityProof",
            "mandatoryPointers": [
              "/issuanceDate",
              "/issuer"
            ]
          }
        }))
        .unwrap();
        let _ = issue(Extension(config()), Extension(keys), CustomErrorJson(req))
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    async fn issue_bbs_2023_v2() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              {
                "@protected": true,
                "DriverLicenseCredential": "urn:example:DriverLicenseCredential",
                "DriverLicense": {
                  "@id": "urn:example:DriverLicense",
                  "@context": {
                    "@protected": true,
                    "id": "@id",
                    "type": "@type",
                    "documentIdentifier": "urn:example:documentIdentifier",
                    "dateOfBirth": "urn:example:dateOfBirth",
                    "expirationDate": "urn:example:expiration",
                    "issuingAuthority": "urn:example:issuingAuthority"
                  }
                },
                "driverLicense": {
                  "@id": "urn:example:driverLicense",
                  "@type": "@id"
                }
              }
            ],
            "id": "urn:uuid:17d1a3b5-10b2-4d23-accf-568903439d88",
            "type": [
              "VerifiableCredential",
              "DriverLicenseCredential"
            ],
            "credentialSubject": {
              "id": "urn:uuid:1a0e4ef5-091f-4060-842e-18e519ab9440",
              "driverLicense": {
                "type": "DriverLicense",
                "documentIdentifier": "T21387yc328c7y32h23f23",
                "dateOfBirth": "01-01-1990",
                "expirationDate": "01-01-2030",
                "issuingAuthority": "VA"
              }
            },
            "issuer": "did:key:zUC7Ker8jsi8tkhwz9CN1MdmunYbgXg4B7iTWJoPFiPty3ZrFg8j3a5bBX1hozUZxck8C73UunuWBZBy7PtYDCe9XYqGjWzXRqyLFqxWGo5nGArAvndYVqSQJhULMJFq5KKgW2X"
          },
          "options": {
            "type": "DataIntegrityProof",
            "mandatoryPointers": [
              "/issuer"
            ]
          }
        }))
        .unwrap();
        let _ = issue(Extension(config()), Extension(keys), CustomErrorJson(req))
            .await
            .unwrap();
    }

    #[ignore = "invalid base signature"]
    #[test(tokio::test)]
    async fn verify_valid_vc_bbs_vcdm1() {
        let req = serde_json::from_value(json!({
          "verifiableCredential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              {
                "@protected": true,
                "DriverLicenseCredential": "urn:example:DriverLicenseCredential",
                "DriverLicense": {
                  "@id": "urn:example:DriverLicense",
                  "@context": {
                    "@protected": true,
                    "id": "@id",
                    "type": "@type",
                    "documentIdentifier": "urn:example:documentIdentifier",
                    "dateOfBirth": "urn:example:dateOfBirth",
                    "expirationDate": "urn:example:expiration",
                    "issuingAuthority": "urn:example:issuingAuthority"
                  }
                },
                "driverLicense": {
                  "@id": "urn:example:driverLicense",
                  "@type": "@id"
                }
              },
              "https://w3id.org/security/data-integrity/v2"
            ],
            "id": "urn:uuid:36245ee9-9074-4b05-a777-febff2e69757",
            "type": [
              "VerifiableCredential",
              "DriverLicenseCredential"
            ],
            "issuanceDate": "2024-07-10T10:09:41Z",
            "issuer": "did:key:zUC7GMwWWkA5UMTx7Gg6sabmpchWgq8p1xGhUXwBiDytY8BgD6eq5AmxNgjwDbAz8Rq6VFBLdNjvXR4ydEdwDEN9L4vGFfLkxs8UsU3wQj9HQGjQb7LHWdRNJv3J1kGoA3BvnBv",
            "credentialSubject": {
              "id": "urn:uuid:1a0e4ef5-091f-4060-842e-18e519ab9440"
            },
            "proof": {
              "type": "DataIntegrityProof",
              "verificationMethod": "did:key:zUC7GMwWWkA5UMTx7Gg6sabmpchWgq8p1xGhUXwBiDytY8BgD6eq5AmxNgjwDbAz8Rq6VFBLdNjvXR4ydEdwDEN9L4vGFfLkxs8UsU3wQj9HQGjQb7LHWdRNJv3J1kGoA3BvnBv#zUC7GMwWWkA5UMTx7Gg6sabmpchWgq8p1xGhUXwBiDytY8BgD6eq5AmxNgjwDbAz8Rq6VFBLdNjvXR4ydEdwDEN9L4vGFfLkxs8UsU3wQj9HQGjQb7LHWdRNJv3J1kGoA3BvnBv",
              "cryptosuite": "bbs-2023",
              "proofPurpose": "assertionMethod",
              "proofValue": "u2V0DhVkB0LUpE2PKToB5TMetM0aElIAa9QtJemJdhfJen3xZPLKWDOIWcWVdxDKPf8FhiulFbZRl29H5zndmbZqtDfVQqk5Jfn35V7uTJuD4ceFRaOcG9g84UmBbKMR1d9jsZRLow6MUxzj6hRPS-qjpESmcBrnJeaiC5JE-uUndGz-8Th6NO6KgCGGCFKM7VrkQuPzmZ2t7LfX_mY9iTFS0olHsgg3tCXgKzUAJ1HgdeugRC3jYGE750IjrEbkzd_UdQcMvpFDLPKli1NlLcWw32SEqVahJNy292b1ALOMLr-WkggdKMorTy3x4iI9P4SBqDHUc8mXP4GorHjoASu_N2IPu00aUyMnaZsqe9lZYVHeri1ZRTQoBn76VRiEm8MuxiahA8t18y2OPjTcrK_VS6r6EyrM5o6WIJJKOyWYsNhsCC8WfgO3ZMALk8qT1TVI9xIojajddUbRwzZJXroDsd9eULLHP92lAIiDX_NB3D5okxHvGV4Kq8uPDHBC5Hrp-QgMgkCxPdOchJTXpQrmrfzzvictRzmtOlM1bC-I8ox0AYNPjlWW4dMIhyIRFVNiXDtten3IZn4ks6cxZrjecUt4pnQMG9wlQBKQsKD9ruMFLxQ2yoIQAAQMEgQFA"
            }
          },
          "options": {
            "checks": [
              "proof"
            ]
          }
        })).unwrap();
        let _ = verify(CustomErrorJson(req)).await.unwrap();
    }

    #[ignore = "invalid base signature"]
    #[test(tokio::test)]
    async fn verify_valid_vc_bbs_vcdm2() {
        let req = serde_json::from_value(json!({
          "verifiableCredential": {
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              {
                "@protected": true,
                "DriverLicenseCredential": "urn:example:DriverLicenseCredential",
                "DriverLicense": {
                  "@id": "urn:example:DriverLicense",
                  "@context": {
                    "@protected": true,
                    "id": "@id",
                    "type": "@type",
                    "documentIdentifier": "urn:example:documentIdentifier",
                    "dateOfBirth": "urn:example:dateOfBirth",
                    "expirationDate": "urn:example:expiration",
                    "issuingAuthority": "urn:example:issuingAuthority"
                  }
                },
                "driverLicense": {
                  "@id": "urn:example:driverLicense",
                  "@type": "@id"
                }
              }
            ],
            "id": "urn:uuid:36245ee9-9074-4b05-a777-febff2e69757",
            "type": [
              "VerifiableCredential",
              "DriverLicenseCredential"
            ],
            "issuer": "did:key:zUC7GMwWWkA5UMTx7Gg6sabmpchWgq8p1xGhUXwBiDytY8BgD6eq5AmxNgjwDbAz8Rq6VFBLdNjvXR4ydEdwDEN9L4vGFfLkxs8UsU3wQj9HQGjQb7LHWdRNJv3J1kGoA3BvnBv",
            "credentialSubject": {
              "id": "urn:uuid:1a0e4ef5-091f-4060-842e-18e519ab9440"
            },
            "proof": {
              "type": "DataIntegrityProof",
              "verificationMethod": "did:key:zUC7GMwWWkA5UMTx7Gg6sabmpchWgq8p1xGhUXwBiDytY8BgD6eq5AmxNgjwDbAz8Rq6VFBLdNjvXR4ydEdwDEN9L4vGFfLkxs8UsU3wQj9HQGjQb7LHWdRNJv3J1kGoA3BvnBv#zUC7GMwWWkA5UMTx7Gg6sabmpchWgq8p1xGhUXwBiDytY8BgD6eq5AmxNgjwDbAz8Rq6VFBLdNjvXR4ydEdwDEN9L4vGFfLkxs8UsU3wQj9HQGjQb7LHWdRNJv3J1kGoA3BvnBv",
              "cryptosuite": "bbs-2023",
              "proofPurpose": "assertionMethod",
              "proofValue": "u2V0DhVkB0IJyYIncBMaPosH1b9kY0_xRWfjSV9jyEcx3d4t09UjsIsRHbOcPZnzmaMP3k4EB2Y_sgAtREipv8ZEMwNPl4kyS8QaVViB7PakDCspJWO-SSbbE5qKXn22E1hJCNnulrLVVjsBmEEsCfX1Aso-AZALeeXtXlimQxEPyzggF82qbEyM9LAcs6iBi2Sf4gWVu_CuxxVzBT93on9gL27aUV5LEh2tTCCpKkimtf5RGqhDaFwsoXHrutPcwzwjH6pjsjqHIT4AXeOl7YFmWRqOPsNA5GBtbarU9OV2oZ3l5bY1gXXtF5cgGKAJheXJmiqcTykdH6UYVNT9EtJs6qIArypvYny4Bzc9hVHvgCyXQRhMXYS_muUOjZlb5mwy0alCogEagq-xaCH-WtHM_T_TsyHwf_P-eE94R6OL2D7hU-tr6J2JMYt380hBeTgbk5KbvzjXSK99LzL4On3sEA33QzgoEa6jqYsnTofcYh60zCsVqZGIAYS9vhL92O2W_9qriGULkdmbJXmuv2_GPI7G5tzItkXeMZofTvFXdZT_lYgHWNjXv5YHubaiLEaLeo124XhL_eI-RJmXJGlnDrIPydMxRscf0djJ_jND60jVnOmcnoIMAAQOBAUA"
            }
          },
          "options": {
            "checks": [
              "proof"
            ]
          }
        })).unwrap();
        let _ = verify(CustomErrorJson(req)).await.unwrap();
    }
}
