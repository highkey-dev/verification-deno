import { GenericAttestation } from "../../custom/GenericAttestation.ts";
import { AuthenticatorData } from "../AuthenticatorData.ts";
import * as jwt from "https://deno.land/x/djwt@v2.8/mod.ts";
import { X509Certificate } from "https://deno.land/std@0.143.0/node/internal/crypto/x509.ts";
import { x5cInterface } from "../../custom/x5cCertificate.ts";
import { Buffer } from "https://deno.land/std@0.162.0/node/buffer.ts";

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-android-safetynet-attestation
 */
export interface AndroidSafetyNetAttestation extends GenericAttestation {
	fmt: "android-safetynet";
	attStmt: AndroidSafetyNetStmt;
}

export interface AndroidSafetyNetStmt {
	ver:string;
	response:Buffer;
}

export function isAndroidSafetyNetAttestation(obj: { [key: string]: any }): boolean {
	if (
		obj["fmt"] &&
		obj["fmt"] === "android-safetynet" &&
		obj["attStmt"] &&
		obj["attStmt"]["ver"] &&
		obj["attStmt"]["response"]
	)
		return true;
	return false;
}

export function AndroidSafetyNetVerify(attestation: GenericAttestation, attStmt: AndroidSafetyNetStmt, clientDataHash: Buffer | string, authenticatorData: AuthenticatorData):boolean {
	const jwsutf = attStmt.response.toString();

	const [header, payload, sig] = jwt.decode(jwsutf);
	let cert = "-----BEGIN CERTIFICATE-----\n" + (header as any).x5c[0] + "\n-----END CERTIFICATE-----";
	let secCert = "-----BEGIN CERTIFICATE-----\n" + (header as any).x5c[1] + "\n-----END CERTIFICATE-----";

	const decryptCert:x5cInterface = new X509Certificate(Buffer.from(cert)) as any;
	if(!decryptCert.dnsNames.includes("attest.android.com")) return false;

	//const verify = crypto.createVerify("RSA-SHA256");
	//if(!verify.verify(secCert,jws.signature)) return false;

	return true;
}
