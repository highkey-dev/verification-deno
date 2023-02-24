import { GenericAttestation } from "../../custom/GenericAttestation.ts";
import { AuthenticatorData } from "../AuthenticatorData.ts";
import { Buffer } from "https://deno.land/std@0.162.0/node/buffer.ts";
import * as util from "../../../authentication/util.ts";
import { X509Certificate } from "https://deno.land/std@0.143.0/node/internal/crypto/x509.ts";
import { x5cInterface } from "../../custom/x5cCertificate.ts";

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-packed-attestation
 */
export interface PackedAttestation extends GenericAttestation {
	fmt: "packed";
	attStmt: PackedStmt;
}

export interface PackedStmt {
	ver: "2.0";
	alg: number;
	x5c?: Array<Buffer>;
	ecdaaKeyId?: Buffer;
	sig: Buffer;
}

export function isPackedAttestation(obj: { [key: string]: any }): boolean {
	if (
		obj["fmt"] &&
		obj["fmt"] === "packed" &&
		obj["attStmt"])
		return true;
	return false;
}

export function PackedVerify(attestation: GenericAttestation, attStmt: PackedStmt, clientDataHash: Buffer | string, authenticatorData: AuthenticatorData): boolean {

	if (attStmt.x5c) {
		//Verify the sig is a valid signature over certInfo using the attestation public key in aikCert (x5c first element, caCert second element) with the algorithm specified in alg.
		let x5cString = attStmt.x5c[0].toString("base64");

		//Add headers to cert to make it a valid PEM certificate
		let cert = "-----BEGIN CERTIFICATE-----\n" + x5cString + "\n-----END CERTIFICATE-----";

		if (attStmt.alg != -7) util.algorithmWarning(attStmt.alg);
		else {
			let signedData = new Uint8Array(attestation.authData.length + clientDataHash.length)
			signedData.set(attestation.authData);
			signedData.set(clientDataHash as Buffer, attestation.authData.length);

			//await crypto.subtle.importKey("pkcs8", cert, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);

			//if (!crypto.subtle.verify({name: "ECDSA", namedCurve: "p-256", hash: {name: "SHA-256"}} as any, cert, attStmt.sig, signedData.buffer)) return false;
		}

		const decryptCert:any = new X509Certificate(Buffer.from(cert));
		if(!validatex509Cert(decryptCert)) return false;
	}

	else if(attStmt.ecdaaKeyId) {
		console.warn(util.ecdaaWarning());
		//TODO: Perform ECDAA-Verify on sig to verify that it is a valid signature over certInfo (see [FIDOEcdaaAlgorithm]).
		//Unfortunately no test scenario found so far on which this could have been implemented

	}
	//If neither a x5c or an ECDAA key are present, self-attestation was used
	else {
		//Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
		//Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.
	}
	return true;
}

function validatex509Cert(cert:x5cInterface) {
	//Version MUST be set to 3.
	if (!(cert.version === 3)) return false;


	//Check subject values

	//Look up the countryName of the attestation issuer
	let subjectC = cert.subject.attributes.find((attr:any) => {
		return attr.shortName === "C"
	});
	//Look up the organizationName of the attestation issuer
	let subjectO = cert.subject.attributes.find((attr:any) => {
		return attr.shortName === "O"
	});
	//Look up the organizationalUnitName of the attestation issuer
	let subjectOU = cert.subject.attributes.find((attr:any) => {
		return attr.shortName === "OU"
	});
	//Look up the commonName of the attestation issuer
	let subjectCN = cert.subject.attributes.find((attr:any) => {
		return attr.shortName === "CN"
	});

	if(!(subjectC && subjectO && subjectCN && subjectOU && subjectOU.value === "Authenticator Attestation")) return false;

	//Check if the aaguid is present in the extensions
	let aaguidExtension = cert.extensions.find((ext:any) => {
		return ext.oid === "1.3.6.1.4.1.45724.1.1.4"
	});

	if(aaguidExtension) {
		//TODO: parse valOct as ASN1 and compare to AAGUID in certInfo
		let valOct = aaguidExtension.value.toString("base64");
		if(aaguidExtension.critical) return false;
	}
	
	//The Basic Constraints extension MUST have the CA component set to false.
	const basicConstraints = cert.extensions.find((extension: any) => {
		return extension.name === "basicConstraints";
	})
	if (basicConstraints && basicConstraints.isCA) return false;


	return true;
}
