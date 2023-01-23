import { JSONWebKey } from "./JSONWebKey.ts";

//TODO Rename, this thing sure has an official name
export interface User {
	id: string;
	signCount: number;
	credentialPublicKey: JSONWebKey;
}