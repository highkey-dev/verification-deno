import * as crypto from "https://deno.land/std@0.173.0/node/crypto.ts";
import {Buffer} from "https://deno.land/std@0.162.0/node/buffer.ts";
import * as CBOR from "https://deno.land/x/cbor@v1.4.1/index.js";
import * as uuid from "https://deno.land/std@0.72.0/uuid/mod.ts";
import {unparse} from '../lib/uuid-parse.js';

//Function logic copied from Microsoft demo implementation: https://github.com/MicrosoftEdge/webauthnsample/blob/master/fido.js
//Decrypt the authData Buffer and split it in its single information pieces. Its structure is specified here: https://w3c.github.io/webauthn/#authenticator-data
export function parseAuthenticatorData(authData: Buffer) {
  try {
    const authenticatorData: any = {}

    authenticatorData.rpIdHash = authData.slice(0, 32)
    authenticatorData.flags = authData[32]
    authenticatorData.signCount =
      (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36]

    //Check if the client sent attestedCredentialdata, which is necessary for every new public key scheduled. This is indicated by the 6th bit of the flag byte being 1 (See specification at function start for reference)
    if (authenticatorData.flags & 64) {
      //Extract the data from the Buffer. Reference of the structure can be found here: https://w3c.github.io/webauthn/#sctn-attested-credential-data
      const attestedCredentialData: { [key: string]: any } = {}
      attestedCredentialData.aaguid = unparse(authData.slice(37, 53)) ///.toUpperCase()
      attestedCredentialData.credentialIdLength = (authData[53] << 8) | authData[54]
      attestedCredentialData.credentialId = authData.slice(
        55,
        55 + attestedCredentialData.credentialIdLength
      )
      //Public key is the first CBOR element of the remaining buffer
      const publicKeyCoseBuffer = authData.slice(
        55 + attestedCredentialData.credentialIdLength,
        authData.length
      )

      //convert public key to JWK for storage
      attestedCredentialData.credentialPublicKey = coseToJwk(publicKeyCoseBuffer)

      authenticatorData.attestedCredentialData = attestedCredentialData
    }

    //Check for extension data in the authData, which is indicated by the 7th bit of the flag byte being 1 (See specification at function start for reference)
    if (authenticatorData.flags & 128) {
      //has extension data

      let extensionDataCbor

      if (authenticatorData.attestedCredentialData) {
        //if we have attesttestedCredentialData, then extension data is
        //the second element
        extensionDataCbor = CBOR.decode( //decodeAllSync(
          authData.slice(
            55 + authenticatorData.attestedCredentialData.credentialIdLength,
            authData.length
          )
        )
        extensionDataCbor = extensionDataCbor[1]
      } else {
        //Else it's the first element
        extensionDataCbor = CBOR.decode(authData.slice(37, authData.length))
      }

      authenticatorData.extensionData = CBOR.encode(extensionDataCbor).toString("base64")
    }

    return authenticatorData
  } catch (e) {
    throw new Error("Authenticator Data could not be parsed")
  }
}

//Convert the Public Key from the cose format to jwk format
export function coseToJwk(cose: any) {
  try {
    let publicKeyJwk = {}
    const publicKeyCbor = CBOR.decode(cose)
    //Determine which encryption method was used to create the public key
    if (publicKeyCbor.get(3) == -7) {
      publicKeyJwk = {
        kty: "EC",
        crv: "P-256",
        x: publicKeyCbor.get(-2).toString("base64"),
        y: publicKeyCbor.get(-3).toString("base64"),
      }
    } else if (publicKeyCbor.get(3) == -257) {
      publicKeyJwk = {
        kty: "RSA",
        n: publicKeyCbor.get(-1).toString("base64"),
        e: publicKeyCbor.get(-2).toString("base64"),
      }
    } else {
      throw new Error("Unknown public key algorithm")
    }

    return publicKeyJwk
  } catch (e) {
    throw new Error("Could not decode COSE Key")
  }
}

//Hash a given data with the SHA256 algorithm
export function sha256(data: any) {
  const hash = crypto.createHash("sha256")
  hash.update(data)
  return hash.digest()
}

//Helper function that generates a random string that can be used for the user challenge
function generateChallenge() {
  let charPool = "1234567890qwertzuiopasdfghjklyxcvbnm"
  let rString = ""
  for (let i = 0; i < 32; i++) {
    rString += charPool.charAt(Math.floor(Math.random() * charPool.length))
  }
  return rString
}

//As Webauthn provides us only with the challenge as a base64 encoded string, we have to manually convert the scheduled plaintext string
function base64encode(string: string) {
  let buff = Buffer.from(string)
  let base64String = buff.toString("base64")
  return base64String.substring(0, base64String.length - 1)
}

//Copied from https://medium.com/@herrjemand/verifying-fido-tpm2-0-attestation-fc7243847498
//Full specification can be found here (Chapter 10.12.8): https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
export function parseCertInfo(certInfoBuffer: Buffer) {
  let magicBuffer = certInfoBuffer.slice(0, 4)
  let magic = magicBuffer.readUInt32BE(0)
  certInfoBuffer = certInfoBuffer.slice(4)

  let typeBuffer = certInfoBuffer.slice(0, 2)
  //@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
  let type = TPM_ST[typeBuffer.readUInt16BE(0)]
  certInfoBuffer = certInfoBuffer.slice(2)

  let qualifiedSignerLength = certInfoBuffer.slice(0, 2).readUInt16BE(0)
  certInfoBuffer = certInfoBuffer.slice(2)
  let qualifiedSigner = certInfoBuffer.slice(0, qualifiedSignerLength)
  certInfoBuffer = certInfoBuffer.slice(qualifiedSignerLength)

  let extraDataLength = certInfoBuffer.slice(0, 2).readUInt16BE(0)
  certInfoBuffer = certInfoBuffer.slice(2)
  let extraData = certInfoBuffer.slice(0, extraDataLength)
  certInfoBuffer = certInfoBuffer.slice(extraDataLength)

  let clockInfo = {
    clock: certInfoBuffer.slice(0, 8),
    resetCount: certInfoBuffer.slice(8, 12).readUInt32BE(0),
    restartCount: certInfoBuffer.slice(12, 16).readUInt32BE(0),
    safe: !!certInfoBuffer[16],
  }
  certInfoBuffer = certInfoBuffer.slice(17)

  let firmwareVersion = certInfoBuffer.slice(0, 8)
  certInfoBuffer = certInfoBuffer.slice(8)

  let attestedNameBufferLength = certInfoBuffer.slice(0, 2).readUInt16BE(0)
  let attestedNameBuffer = certInfoBuffer.slice(2, attestedNameBufferLength + 2)
  certInfoBuffer = certInfoBuffer.slice(2 + attestedNameBufferLength)

  let attestedQualifiedNameBufferLength = certInfoBuffer.slice(0, 2).readUInt16BE(0)
  let attestedQualifiedNameBuffer = certInfoBuffer.slice(2, attestedQualifiedNameBufferLength + 2)
  certInfoBuffer = certInfoBuffer.slice(2 + attestedQualifiedNameBufferLength)

  let attested = {
    //@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
    nameAlg: TPM_ALG[attestedNameBuffer.slice(0, 2).readUInt16BE(0)],
    name: attestedNameBuffer,
    qualifiedName: attestedQualifiedNameBuffer,
  }

  return {
    magic,
    type,
    qualifiedSigner,
    extraData,
    clockInfo,
    firmwareVersion,
    attested,
  }
}

//Copied from https://medium.com/@herrjemand/verifying-fido-tpm2-0-attestation-fc7243847498
//Full specification can be found here (Chapter 12.2.4): https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
export function parsePubArea(pubAreaBuffer: Buffer) {
  let typeBuffer = pubAreaBuffer.slice(0, 2)
  //@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
  let type = TPM_ALG[typeBuffer.readUInt16BE(0)]
  pubAreaBuffer = pubAreaBuffer.slice(2)

  let nameAlgBuffer = pubAreaBuffer.slice(0, 2)
  //@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
  let nameAlg = TPM_ALG[nameAlgBuffer.readUInt16BE(0)]
  pubAreaBuffer = pubAreaBuffer.slice(2)

  let objectAttributesBuffer = pubAreaBuffer.slice(0, 4)
  let objectAttributesInt = objectAttributesBuffer.readUInt32BE(0)
  let objectAttributes = {
    fixedTPM: !!(objectAttributesInt & 1),
    stClear: !!(objectAttributesInt & 2),
    fixedParent: !!(objectAttributesInt & 8),
    sensitiveDataOrigin: !!(objectAttributesInt & 16),
    userWithAuth: !!(objectAttributesInt & 32),
    adminWithPolicy: !!(objectAttributesInt & 64),
    noDA: !!(objectAttributesInt & 512),
    encryptedDuplication: !!(objectAttributesInt & 1024),
    restricted: !!(objectAttributesInt & 32768),
    decrypt: !!(objectAttributesInt & 65536),
    signORencrypt: !!(objectAttributesInt & 131072),
  }
  pubAreaBuffer = pubAreaBuffer.slice(4)

  let authPolicyLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0)
  pubAreaBuffer = pubAreaBuffer.slice(2)
  let authPolicy = pubAreaBuffer.slice(0, authPolicyLength)
  pubAreaBuffer = pubAreaBuffer.slice(authPolicyLength)

  let parameters = undefined
  if (type === "TPM_ALG_RSA") {
    parameters = {
      //@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
      symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
      //@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
      scheme: TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
      keyBits: pubAreaBuffer.slice(4, 6).readUInt16BE(0),
      exponent: pubAreaBuffer.slice(6, 10).readUInt32BE(0),
    }
    pubAreaBuffer = pubAreaBuffer.slice(10)
  } else if (type === "TPM_ALG_ECC") {
    parameters = {
      //@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
      symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
      //@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
      scheme: TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
      //@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
      curveID: TPM_ECC_CURVE[pubAreaBuffer.slice(4, 6).readUInt16BE(0)],
      //@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
      kdf: TPM_ALG[pubAreaBuffer.slice(6, 8).readUInt16BE(0)],
    }
    pubAreaBuffer = pubAreaBuffer.slice(8)
  } else throw new Error(type + " is an unsupported type!")

  let uniqueLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0)
  pubAreaBuffer = pubAreaBuffer.slice(2)
  let unique = pubAreaBuffer.slice(0, uniqueLength)
  pubAreaBuffer = pubAreaBuffer.slice(uniqueLength)

  return {
    type,
    nameAlg,
    objectAttributes,
    authPolicy,
    parameters,
    unique,
  }
}

function getEndian() {
  let arrayBuffer = new ArrayBuffer(2)
  let uint8Array = new Uint8Array(arrayBuffer)
  let uint16array = new Uint16Array(arrayBuffer)
  uint8Array[0] = 0xaa // set first byte
  uint8Array[1] = 0xbb // set second byte

  if (uint16array[0] === 0xbbaa) return "little"
  else return "big"
}

function readBE16(buffer: Buffer) {
  if (buffer.length !== 2) throw new Error("Only 2byte buffer allowed!")

  if (getEndian() !== "big") buffer = buffer.reverse()

  return new Uint16Array(buffer.buffer)[0]
}

function readBE32(buffer: Buffer) {
  if (buffer.length !== 4) throw new Error("Only 4byte buffers allowed!")

  if (getEndian() !== "big") buffer = buffer.reverse()

  return new Uint32Array(buffer.buffer)[0]
}

export function ecdaaWarning() {
  console.warn(
    "Your clients TPM module is using an ECDAA key to encrypt its verification data. ECDAA verification is not yet supported in this framework and will be implemented in a further release. If you want to support the development of this library, please create an issue on the GitHub repository with the following information:\n\n ECDAA Verification not supported!\nClient machine: <your-device>\nAuthentication method used: <e.g. Windows Hello, Apple Touch ID, ...>"
  )
}

export function algorithmWarning(alg: number | string) {
  console.warn(
    "The authenticator is using an algorithm which is not supported to encrypt its signature. This is a shortcoming of this library and will be fixed in further releases. If you want to support the development of this library, please create an issue on the GitHub repository with following information:\n\n TPM Verification Algorithm not supported!\nAlgorithm: " +
      alg
  )
}

export function btoh(bytes: Uint8Array /* Uint8Array */) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

let TPM_ALG = {
  0x0000: "TPM_ALG_ERROR",
  0x0001: "TPM_ALG_RSA",
  0x0003: "TPM_ALG_SHA",
  0x0004: "TPM_ALG_SHA1",
  0x0005: "TPM_ALG_HMAC",
  0x0006: "TPM_ALG_AES",
  0x0007: "TPM_ALG_MGF1",
  0x0008: "TPM_ALG_KEYEDHASH",
  0x000a: "TPM_ALG_XOR",
  0x000b: "TPM_ALG_SHA256",
  0x000c: "TPM_ALG_SHA384",
  0x000d: "TPM_ALG_SHA512",
  0x0010: "TPM_ALG_NULL",
  0x0012: "TPM_ALG_SM3_256",
  0x0013: "TPM_ALG_SM4",
  0x0014: "TPM_ALG_RSASSA",
  0x0015: "TPM_ALG_RSAES",
  0x0016: "TPM_ALG_RSAPSS",
  0x0017: "TPM_ALG_OAEP",
  0x0018: "TPM_ALG_ECDSA",
  0x0019: "TPM_ALG_ECDH",
  0x001a: "TPM_ALG_ECDAA",
  0x001b: "TPM_ALG_SM2",
  0x001c: "TPM_ALG_ECSCHNORR",
  0x001d: "TPM_ALG_ECMQV",
  0x0020: "TPM_ALG_KDF1_SP800_56A",
  0x0021: "TPM_ALG_KDF2",
  0x0022: "TPM_ALG_KDF1_SP800_108",
  0x0023: "TPM_ALG_ECC",
  0x0025: "TPM_ALG_SYMCIPHER",
  0x0026: "TPM_ALG_CAMELLIA",
  0x0040: "TPM_ALG_CTR",
  0x0041: "TPM_ALG_OFB",
  0x0042: "TPM_ALG_CBC",
  0x0043: "TPM_ALG_CFB",
  0x0044: "TPM_ALG_ECB",
}

let TPM_ECC_CURVE = {
  0x0000: "TPM_ECC_NONE",
  0x0001: "TPM_ECC_NIST_P192",
  0x0002: "TPM_ECC_NIST_P224",
  0x0003: "TPM_ECC_NIST_P256",
  0x0004: "TPM_ECC_NIST_P384",
  0x0005: "TPM_ECC_NIST_P521",
  0x0010: "TPM_ECC_BN_P256",
  0x0011: "TPM_ECC_BN_P638",
  0x0020: "TPM_ECC_SM2_P256",
}

let TPM_ST = {
  0x00c4: "TPM_ST_RSP_COMMAND",
  0x8000: "TPM_ST_NULL",
  0x8001: "TPM_ST_NO_SESSIONS",
  0x8002: "TPM_ST_SESSIONS",
  0x8014: "TPM_ST_ATTEST_NV",
  0x8015: "TPM_ST_ATTEST_COMMAND_AUDIT",
  0x8016: "TPM_ST_ATTEST_SESSION_AUDIT",
  0x8017: "TPM_ST_ATTEST_CERTIFY",
  0x8018: "TPM_ST_ATTEST_QUOTE",
  0x8019: "TPM_ST_ATTEST_TIME",
  0x801a: "TPM_ST_ATTEST_CREATION",
  0x8021: "TPM_ST_CREATION",
  0x8022: "TPM_ST_VERIFIED",
  0x8023: "TPM_ST_AUTH_SECRET",
  0x8024: "TPM_ST_HASHCHECK",
  0x8025: "TPM_ST_AUTH_SIGNED",
  0x8029: "TPM_ST_FU_MANIFEST",
}


function extractBigNum(fullArray: any, start: any, end: any, expectedLength: any): any {
	let num = fullArray.slice(start, end);
	if (num.length !== expectedLength){
		num = Array(expectedLength).fill(0).concat(...num).slice(num.length);
	}
	return num;
}

/*
    Convert signature from DER to raw
    Expects Uint8Array
*/
export function derToRaw(signature: any): Uint8Array {
	const rStart = 4;
	const rEnd = rStart + signature[3];
	const sStart = rEnd + 2;
	return new Uint8Array([
		...extractBigNum(signature, rStart, rEnd, 32),
		...extractBigNum(signature, sStart, signature.length, 32),
	]);
}