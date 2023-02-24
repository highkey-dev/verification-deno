import { GenericAttestation } from "../../custom/GenericAttestation.ts";
import { Buffer } from "https://deno.land/std@0.162.0/node/buffer.ts";

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-android-key-attestation
 */
export interface AndroidKeyAttestation extends GenericAttestation {
	fmt: "android-key";
	attStmt: {
		alg: number;
		x5c: Array<Buffer>;
		sig: Buffer;
	}
}

export function isAndroidKeyAttestation(obj: { [key: string]: any }): boolean {
	if (
		obj["fmt"] &&
		obj["fmt"] === "android-key" &&
		obj["attStmt"] &&
		obj["attStmt"]["alg"] &&
		obj["attStmt"]["x5c"] &&
		obj["attStmt"]["sig"]
	)
		return true;
	return false;
}

export function AndroidKeyVerify(attestation:GenericAttestation, clientDataHash: Buffer | string):boolean {
	//TODO
	return true;
}