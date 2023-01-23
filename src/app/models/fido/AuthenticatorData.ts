import { JSONWebKey } from "../custom/JSONWebKey.ts";
import { AttestedCredentialData } from "./Attested Credential Data.ts";
import {Buffer} from "https://deno.land/std@0.162.0/node/buffer.ts";
/**
 * In its original form, AuthenticatorData is represented as a bit buffer. The encoding of these bits can be found in the specification.
 * https://w3c.github.io/webauthn/#sctn-authenticator-data
 */
export interface AuthenticatorData {
	flags: number;
	attestedCredentialData: AttestedCredentialData;
	extensions?: {[key:string]:any}
	rpIdHash: Buffer;
	signCount: number;
}