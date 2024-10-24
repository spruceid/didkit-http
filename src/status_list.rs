use anyhow::Context as _;
use axum::{Extension, Json};
use iref::UriBuf;
use ssi::{
    claims::{data_integrity::AnySignatureOptions, SignatureEnvironment},
    dids::{DIDKey, VerificationMethodDIDResolver},
    jwk::Params,
    prelude::{AnyMethod, AnySuite, CryptographicSuite, DataIntegrity, ProofOptions},
    status::bitstring_status_list::{
        BitstringStatusList, BitstringStatusListCredential, SizedBitString, StatusPurpose,
        StatusSize, TimeToLive,
    },
    verification_methods::ReferenceOrOwned,
};
use tracing::debug;

use crate::{
    config::Config,
    dids::{AnyDidMethod, CustomVerificationMethodResolver},
    error::Error,
    keys::{KeyMap, KeyMapSigner},
    utils::LDPOptions,
};

#[axum::debug_handler]
pub async fn status_list(
    Extension(config): Extension<Config>,
    Extension(keys): Extension<KeyMap>,
) -> Result<Json<DataIntegrity<BitstringStatusListCredential, AnySuite>>, Error> {
    let status_list_url: UriBuf = config
        .issuer
        .base_url
        .join("statuslist")
        .context("Could not join status list URL")?
        .to_string()
        .parse()
        .context("Could not parse status list URL")?;
    let status_list = BitstringStatusList::new(
        Some(status_list_url.clone()),
        StatusPurpose::Revocation,
        SizedBitString::new(StatusSize::default()).encode(),
        TimeToLive::default(),
    );

    let mut vc = BitstringStatusListCredential::new(Some(status_list_url), status_list);

    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let resolver = CustomVerificationMethodResolver {
        did_resolver: resolver,
        keys: keys.clone(),
    };
    let public_jwk = keys
        .keys()
        .find(|key| matches!(key.params, Params::OKP(_)))
        .unwrap();
    let issuer_did = DIDKey::generate(public_jwk).context("Could not generate DID")?;
    let issuer_vm = DIDKey::generate_url(public_jwk).context("Could not generate VM")?;
    vc.other_properties = vec![(
        "issuer".to_string(),
        serde_json::Value::String(issuer_did.to_string()),
    )]
    .into_iter()
    .collect();
    let proof_options = ProofOptions {
        verification_method: Some(ReferenceOrOwned::Reference(issuer_vm.to_owned().into_iri())),
        ..Default::default()
    };
    let ldp_options = LDPOptions {
        type_: Some("Ed25519Signature2020".to_string()),
        cryptosuite: None,
        mandatory_pointers: None,
        input_options: proof_options,
    };
    let suite = ldp_options
        .select_suite(public_jwk)
        .context("Could not select suite from JWK")?;

    let signer = KeyMapSigner(keys).into_local();
    let vc = suite
        .sign_with(
            SignatureEnvironment::default(),
            vc,
            resolver,
            signer,
            ldp_options.input_options,
            AnySignatureOptions::default(),
        )
        .await
        .context("Failed to sign VC")?;
    debug!(
        "Signed status list: {}",
        serde_json::to_string(&vc).unwrap()
    );
    Ok(Json(vc))
}
