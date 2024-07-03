use ssi::dids::{
    did,
    document::representation::MediaType,
    resolution::{self, Output},
    DIDResolver, StaticDIDResolver, DID,
};

const DOC_JSON_ISSUER: &str = include_str!("../tests/did-example-issuer.json");
const DOC_JSON_OTHERISSUER: &str = include_str!("../tests/did-example-other-issuer.json");
const DOC_JSON_SUBJECT: &str = include_str!("../tests/did-example-subject.json");

#[derive(Default, Clone)]
pub struct AnyDidMethod {
    any_did_method: ssi::dids::AnyDidMethod,
    example: ExampleDIDResolver,
}

impl DIDResolver for AnyDidMethod {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        match did.method_name() {
            "example" => self.example.resolve_representation(did, options).await,
            _ => {
                self.any_did_method
                    .resolve_representation(did, options)
                    .await
            }
        }
    }
}

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
