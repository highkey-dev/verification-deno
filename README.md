# Credential Verification Service

implementation of Webauthn credential verification for the Deno runtime.

supports the following:
- attestation checks on credential
- Challenge verification (TODO)
- Webauthn operation checks
- credential verification against signatures

## Current issues
- verification of credentials against signed message with signature always fails. currently investigating encoding problems with `attestation` response.

## Running locally
**note** Deno version 1.27 or greater is required
```bash
deno run src/index.action.ts
```

## bundling locally

```bash
deno bundle src/index.action.ts <path-to-output-file-location>
```