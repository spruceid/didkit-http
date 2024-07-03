use std::collections::HashMap;

use ssi::{
    verification_methods::{LocalSigner, MaybeJwkVerificationMethod, Signer},
    JWK,
};

pub type KeyMap = HashMap<JWK, JWK>;

pub struct KeyMapSigner(pub KeyMap);

impl KeyMapSigner {
    pub fn into_local(self) -> LocalSigner<Self> {
        LocalSigner(self)
    }
}

impl<M: MaybeJwkVerificationMethod> Signer<M> for KeyMapSigner {
    type MessageSigner = JWK;

    async fn for_method(&self, method: std::borrow::Cow<'_, M>) -> Option<Self::MessageSigner> {
        let public_jwk = method.try_to_jwk()?;
        self.0.get(&public_jwk).cloned()
    }
}
