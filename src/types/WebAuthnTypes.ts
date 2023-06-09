export interface ISignatureResponse {
    signature: string
    messageSigned?: string
}

export interface IWebAuthnRegistrationResponse {
    q0: string;
    q1: string;
    encodedId: string;
    walletAddress?: string;
    initcode?: boolean;
    username?: string
    saltNonce?: string
}

export interface IWebAuthnSignatureRequest {
    message: string,
    encodedId: string,
    isMessageSignedNeeded?: boolean
}