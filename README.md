# Credential Verification Service

Implementation of Webauthn credential verification for the Deno runtime.

## Current issues
- verification of credentials against signed message with signature always fails. currently investigating encoding problems with `attestation` response.

## Running locally
**note** Deno version 1.27 or greater is required
```bash
deno run src/app/local.ts
```

## bundling locally

```bash
deno bundle src/index.action.ts <path-to-output-file-location>
```

## Minifying
```bash
esbuild --minify <path-to-bundle> --outfile=bundle.min.js
```
**note** Currently using lit's pkp explorer to upload minified contents to Cloud Flair's ipfs gateways