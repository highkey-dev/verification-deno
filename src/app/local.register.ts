import { registerKey } from "./authentication/signup.ts";

const testCred = {
    "id": "CyjJ8JHIVAyNSE6vDSH_yRxSTVCpGVfnje55vlArURw",
    "readableId": "CyjJ8JHIVAyNSE6vDSH_yRxSTVCpGVfnje55vlArURw",
    "clientDataJSON": "{\"type\":\"webauthn.create\",\"challenge\":\"AAAIAAAACQMAAAAAAAAECQEAAAYCAAEDAQAAAAAAAQA\",\"origin\":\"https://demo.highkey.dev\",\"crossOrigin\":false}",
    "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEYwRAIgDOYsZv4BDoD32Qyu3QVc75YuE4IkRmFKglSCgi6GM38CIF4LtdjivsJDOj9x9+dCSPs7mR7og6kiWP4y7dIeJuh5aGF1dGhEYXRhWKSHy6mrsjYSajdNnndeFGrk9sID6YgzQ7IfM21QPliMVUUAAAAArc4AAjW8xgpkiwsl8fBVAwAgCyjJ8JHIVAyNSE6vDSH/yRxSTVCpGVfnje55vlArURylAQIDJiABIVggtGpGdU7lr5qgg17OwkUla9C/uhK+XRrP5d8wXvIrRkMiWCDHzEF4UWx37FMSErpJLMNQtdi7F3GT+jTHICEoOhVEJA=="
}

// testCred.attestationObject = testCred.attestationObject.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
const res = registerKey(testCred, "");
console.log(res);