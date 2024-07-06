use std::borrow::Cow;

use ssi::{
    dids::{
        did,
        document::representation::MediaType,
        resolution::{self, Output},
        DIDResolver, StaticDIDResolver, VerificationMethodDIDResolver, DID,
    },
    jwk::Params,
    verification_methods::{
        AnyMethod, Ed25519VerificationKey2020, ReferenceOrOwnedRef, ResolutionOptions,
        VerificationMethodResolutionError, VerificationMethodResolver,
    },
};

use crate::keys::KeyMap;

const DOG_JSON_ISSUER: &str = include_str!("../tests/did-issuer-dog.json");
const DOC_JSON_ISSUER: &str = include_str!("../tests/did-example-issuer.json");
const DOC_JSON_OTHERISSUER: &str = include_str!("../tests/did-example-other-issuer.json");
const DOC_JSON_SUBJECT: &str = include_str!("../tests/did-example-subject.json");

#[derive(Default, Clone)]
pub struct AnyDidMethod {
    any_did_method: ssi::dids::AnyDidMethod,
    example: ExampleDIDResolver,
    dog: DogDIDResolver,
}

impl DIDResolver for AnyDidMethod {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        match did.method_name() {
            "example" => self.example.resolve_representation(did, options).await,
            "issuer" => self.dog.resolve_representation(did, options).await,
            _ => {
                self.any_did_method
                    .resolve_representation(did, options)
                    .await
            }
        }
    }
}

/// Most VCDM v2 tests use did:example
#[derive(Clone)]
struct ExampleDIDResolver(StaticDIDResolver);

impl ExampleDIDResolver {
    pub fn new() -> Self {
        let mut r = StaticDIDResolver::new();
        r.insert(
            did!("did:example:issuer").to_owned(),
            Output::from_content(
                DOC_JSON_ISSUER.as_bytes().to_vec(),
                Some(MediaType::JsonLd.into()),
            ),
        );
        r.insert(
            did!("did:example:other-issuer").to_owned(),
            Output::from_content(
                DOC_JSON_OTHERISSUER.as_bytes().to_vec(),
                Some(MediaType::JsonLd.into()),
            ),
        );
        r.insert(
            did!("did:example:subject").to_owned(),
            Output::from_content(
                DOC_JSON_SUBJECT.as_bytes().to_vec(),
                Some(MediaType::JsonLd.into()),
            ),
        );
        Self(r)
    }
}

impl Default for ExampleDIDResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DIDResolver for ExampleDIDResolver {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        self.0.resolve_representation(did, options).await
    }
}

/// Some VCDM v2 tests use did:issuer:dog...
#[derive(Clone)]
struct DogDIDResolver(StaticDIDResolver);

impl DogDIDResolver {
    pub fn new() -> Self {
        let mut r = StaticDIDResolver::new();
        r.insert(
            did!("did:issuer:dog").to_owned(),
            Output::from_content(
                DOG_JSON_ISSUER.as_bytes().to_vec(),
                Some(MediaType::JsonLd.into()),
            ),
        );
        Self(r)
    }
}

impl Default for DogDIDResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DIDResolver for DogDIDResolver {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        self.0.resolve_representation(did, options).await
    }
}

#[derive(Default)]
pub struct CustomVerificationMethodResolver {
    pub did_resolver: VerificationMethodDIDResolver<AnyDidMethod, AnyMethod>,
    pub keys: KeyMap,
}

impl VerificationMethodResolver for CustomVerificationMethodResolver {
    type Method = AnyMethod;

    async fn resolve_verification_method_with(
        &self,
        issuer: Option<&iref::Iri>,
        method: Option<ReferenceOrOwnedRef<'_, AnyMethod>>,
        options: ResolutionOptions,
    ) -> Result<Cow<AnyMethod>, VerificationMethodResolutionError> {
        match method {
            Some(method) => {
                if method.id().scheme().as_str() == "did" {
                    self.did_resolver
                        .resolve_verification_method_with(issuer, Some(method), options)
                        .await
                } else {
                    // Not a DID scheme.
                    // Some VCDM v2 tests use a non-DID issuer URI
                    let ed25519_key = self
                        .keys
                        .keys()
                        .find_map(|j| match &j.params {
                            Params::OKP(p) => {
                                if p.curve == "Ed25519" {
                                    Some(p.try_into().unwrap())
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        })
                        .unwrap();
                    let key = AnyMethod::Ed25519VerificationKey2020(
                        Ed25519VerificationKey2020::from_public_key(
                            method.id().to_owned(),
                            method.id().as_uri().unwrap().to_owned(),
                            ed25519_key,
                        ),
                    );
                    Ok(Cow::Owned(key))
                }
            }
            None => Err(VerificationMethodResolutionError::MissingVerificationMethod),
        }
    }
}
