import { generatePublicKeyCredentialRequestOptions } from "./app/authentication/util.ts";


(() => {
    //@ts-ignore: userId passed by lit action context
    const requestOptions = JSON.stringify(generatePublicKeyCredentialRequestOptions(userId));
    //@ts-ignore: setResponse passed by lit action context
    setResponse({response: requestOptions});
})()