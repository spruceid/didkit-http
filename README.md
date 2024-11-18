# DIDKit HTTP

Implementation of the [Verifiable Credentials API](https://w3c-ccg.github.io/vc-api/)
using DIDKit.

## Usage

The Docker image is available at
https://github.com/spruceid/didkit/pkgs/container/didkit-http.

### Configuration

Refer to the [defaults configuration file](./defaults.toml).

To provide overrides you can either:
- use a configuration file named `didkit-http.toml` which follows the structure
  as the defaults files; or
- use environment variables, which are prefixed with `DIDKIT_HTTP_` and follow
  the same names, with a separating `_` between sections.

## Security Considerations

Spruce does not use DIDKit HTTP in any production environments except with a reverse proxy, and does not recommend them for production use-cases without a holistic review of security levels.  The following is not an exhaustive list, but should be considered in any such review.

### Authorization

DIDKit HTTP does not implement any endpoint authorization or access control. Any client can request a signature/proof creation from the server's key(s) using the issue credential/presentation endpoints. To limit access to some or all of DIDKit HTTP's endpoints, a deployment should place DIDKit HTTP behind a reverse proxy with appropriate settings.

### Denial of Service

DIDKit HTTP does not implement complete protection against resource exhaustion. Clients may be able to overwhelm the server with excessively slow and/or concurrent requests. To protect against resource exhaustion, deployments should use a reverse proxy with rate limiting, load balancing across multiple DIDKit HTTP instances, and/or other protections.

[did-http]: https://w3c-ccg.github.io/did-resolution/#bindings-https
[vc-api]: https://w3c-ccg.github.io/vc-api/
[vc-http-api-0.0.1]: https://github.com/w3c-ccg/vc-api/pull/72
[did-resolution-https-binding]: https://w3c-ccg.github.io/did-resolution/#bindings-https

## Funding

This work is funded in part by the U.S. Department of Homeland Security's Science and Technology Directorate under contract 70RSAT24T00000011 (Open-Source and Privacy-Preserving Digital Credentialing Infrastructure).
Through this contract, SpruceID’s open-source libraries will be used to build privacy-preserving digital credential wallets and verifier capabilities to support standards while ensuring safe usage and interoperability across sectors like finance, healthcare, and various cross-border applications.
To learn more about this work, [read more here](https://spruceid.com/customer-highlight/dhs-highlight) . 
