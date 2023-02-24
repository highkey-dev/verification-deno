import { Buffer } from "https://deno.land/std@0.162.0/node/buffer.ts";
export interface x5cInterface {
	authorityKeyIdentifier: string;
	basicConstraintsValid: boolean;
	dnsNames: Array<string>;
	emailAddresses: Array<string>;
	extensions: Array<Extension>;
	infoSignatureOID:string;
	ipAddresses:Array<string>;
	isCA:boolean;
	issuer:Issuer;
	issuingCertificateURL:string;
	keyUsage:number;
	maxPathLen: number;
	ocspServer:string;
	publicKey: PublicKey;
	publicKeyRaw: Buffer;
	raw: Buffer;
	serialNumber: string;
	signature: Buffer;
	signatureAlgorithm: string;
	signatureOID: string;
	subject: Subject;
	subjectKeyIdentifier: string;
	tbsCertificate: any;
	uris: Array<string>;
	validFrom: Date;
	validTo: Date;
	version: number;

}

interface Extension {
	oid:string;
	name:string;
	critical:boolean;
	subjectKeyIdentifier:string;
	value:Buffer;
	//Extensions can contain any data
	[key:string]:any;
}

interface Issuer {
	attributes: Array<Attribute>;
	commonName:string;
	countryName:string;
	localityName:string;
	organizationalUnitName:string;
	organizationName:string;
	serialName:string;
	uniqueId:string;
}

interface PublicKey {
	_finalKey: Buffer;
	_finalPEM: string;
	_keyRaw: Buffer;
	_pkcs8: any;
	algo:string;
	keyRaw: Buffer;
	oid:string;
}

interface Subject {
	attributes: Array<Attribute>;
	commonName: string;
	countryName: string;
	localityName: string;
	organizationalUnitName: string;
	organizationName: string;
	serialName: string;
	uniqueId: string;
}

interface Attribute {
	name:string;
	oid:string;
	shortName:string;
	value:string;
	valueTag:number;
}