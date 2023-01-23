import { JSONWebKey } from "../custom/JSONWebKey.ts";
import {Buffer} from "https://deno.land/std@0.162.0/node/buffer.ts";

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-attested-credential-data
 */
export interface AttestedCredentialData {
	aaguid: string;
	credentialId: Buffer;
	credentialIdLength: number;
	credentialPublicKey: JSONWebKey;
}