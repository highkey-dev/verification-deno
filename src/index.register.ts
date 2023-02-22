import { registerKey } from "./app/authentication/signup.ts";

(() => {
    //@ts-ignore: pk injected from lit action context
    pk.attestationObject = pk.attestationObject.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    //@ts-ignore: function injected from lit's action context
    const res: {status: number, text: string, credential: any} = registerKey(pk, userId);
    
    //@ts-ignore: function injected from lit's action context
    setResponse({response: res.credential});
})();