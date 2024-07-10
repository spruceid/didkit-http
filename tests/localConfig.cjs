module.exports = {
  settings: {
    // don't test live implementations
    enableInteropTests: false,
    testAllImplementations: false
  },
  implementations: [{
    "name": "Spruce",
    "implementation": "Spruce",
    "issuers": [{
      "id": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD",
      "endpoint": "https://127.0.0.1:9000/credentials/issue",
      "options": {
        "type": "Ed25519Signature2020"
      },
      "supports": {
        "vc": ['1.1', '2.0']
      },
      "tags": ["vc-api", "Ed25519Signature2020", "JWT", "vc2.0"]
    }, {
      "id": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD",
      "endpoint": "https://127.0.0.1:9000/credentials/issue",
      "options": {
        "type": "DataIntegrityProof"
      },
      "supports": {
        "vc": ['1.1', '2.0']
      },
      "tags": ["vc-api", "eddsa-rdfc-2022", "eddsa-jcs-2022", "JWT", "vc2.0"]
    }, {
      "id": "did:key:zDnaeqRNmCGRy8f4RgNSoj9YiwG697iWB7htXNX89G8Nu3Hxo",
      "endpoint": "https://127.0.0.1:9000/credentials/issue",
      "options": {
        "type": "DataIntegrityProof"
      },
      "supports": {
        "vc": ['1.1', '2.0']
      },
      "supportedEcdsaKeyTypes": ["P-256"],
      "tags": ["vc-api", "ecdsa-rdfc-2019", "JWT", "vc2.0"]
    }, {
      "id": "did:key:z82LkvutaARmY8poLhUnMCAhFbts88q4yDBmkqwRFYbxpFvmE1nbGUGLKf9fD66LGUbXDce",
      "endpoint": "https://127.0.0.1:9000/credentials/issue",
      "options": {
        "type": "DataIntegrityProof"
      },
      "supports": {
        "vc": ['1.1', '2.0']
      },
      "supportedEcdsaKeyTypes": ["P-384"],
      "tags": ["vc-api", "ecdsa-rdfc-2019", "JWT", "vc2.0"]
    }, {
      "id": "did:key:zUC7Ker8jsi8tkhwz9CN1MdmunYbgXg4B7iTWJoPFiPty3ZrFg8j3a5bBX1hozUZxck8C73UunuWBZBy7PtYDCe9XYqGjWzXRqyLFqxWGo5nGArAvndYVqSQJhULMJFq5KKgW2X",
      "endpoint": "https://127.0.0.1:9000/credentials/issue",
      "options": {
        "type": "DataIntegrityProof"
      },
      "supports": {
        "vc": ['1.1', '2.0']
      },
      "tags": ["vc-api", "bbs-2023", "JWT", "vc2.0"]
    }],
    "verifiers": [{
      "id": "https://spruceid.com",
      "endpoint": "https://127.0.0.1:9000/credentials/verify",
      "supports": {
        "vc": ['1.1', '2.0']
      },
      "supportedEcdsaKeyTypes": ["P-256", "P-384"],
      "tags": ["vc-api", "Ed25519Signature2020", "JWT", "ecdsa-rdfc-2019", "eddsa-rdfc-2022", "eddsa-jcs-2022", "bbs-2023", "vc2.0"]
    }],
    "vpVerifiers": [{
      "id": "https://spruceid.com",
      "endpoint": "https://127.0.0.1:9000/presentations/verify",
      "supports": {
        "vc": ['1.1', '2.0']
      },
      "supportedEcdsaKeyTypes": ["P-256", "P-384"],
      "tags": ["vc-api", "Ed25519Signature2020", "JWT", "ecdsa-rdfc-2019", "eddsa-rdfc-2022", "eddsa-jcs-2022", "bbs-2023", "vc2.0"]
    }],
    "didResolvers": [{
      "id": "https://spruceid.com",
      "endpoint": "https://127.0.0.1:9000/identifiers",
      "tags": ["did-key"]
    }]
  }]
};
