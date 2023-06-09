import * as base64url from "./utils/base64url-arraybuffer";
import { v4 as uuidv4 } from "uuid";
import Axios from "axios";
import {
  REGISTRATION_LAMBDA_URL,
  VERIFICATION_LAMBDA_URL,
} from "./constants/routes";
import { ethers } from "ethers";
import { IWebAuthnRegistrationResponse, ISignatureResponse, IWebAuthnSignatureRequest } from "./types/WebAuthnTypes";
import { EllipticCurve__factory } from "./typechain/factories/EllipticCurve__factory";
import { JSON_RPC_PROVIDER, ELLIPTIC_CURVE_ADDRESS } from "./constants/index";

export const register = async (): Promise<IWebAuthnRegistrationResponse> => {
  const uuid = uuidv4();
  const chanllenge = uuidv4();
  const isPlatformSupported =
    await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  const authenticationSupport = isPlatformSupported
    ? "platform"
    : "cross-platform";
  const publicKeyParams = {
    challenge: Uint8Array.from(chanllenge, (c) => c.charCodeAt(0)),
    rp: {
      name: "Banana Smart Wallet",
    },
    user: {
      id: Uint8Array.from(uuid, (c) => c.charCodeAt(0)),
      name: "bananawallet",
      displayName: "Banana Smart Wallet",
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: {
      authenticatorAttachment: authenticationSupport,
      userVerification: "required",
    },
    timeout: 60000,
    attestation: "none",
  } as PublicKeyCredentialCreationOptions;

  let publicKeyCredential;
  try {
    publicKeyCredential = await navigator.credentials.create({
      publicKey: publicKeyParams,
    });
  } catch (err) {
    console.log("algo not supported, trying again", err);
    // @ts-ignore
    publicKeyParams.authenticatorSelection.authenticatorAttachment =
      "cross-platform";
    publicKeyCredential = await navigator.credentials.create({
      publicKey: publicKeyParams,
    });
  }

  if (publicKeyCredential === null) {
    // alert('Failed to get credential')
    return Promise.reject(new Error("Failed to create credential"));
  }

  const response = await Axios({
    url: REGISTRATION_LAMBDA_URL,
    method: "post",
    params: {
      aObject: JSON.stringify(
        Array.from(
          new Uint8Array(
            (publicKeyCredential as any).response.attestationObject
          )
        )
      ),

      rawId: JSON.stringify(
        //@ts-ignore
        Array.from(new Uint8Array(publicKeyCredential?.rawId))
      ),
    },
  });
  return {
    q0: response.data.message.q0hexString,
    q1: response.data.message.q1hexString,
    encodedId: response.data.message.encodedId,
  };
};

export const checkAuth = async (
  message: string,
  encodedId: string,
  eoaAddress: [string, string]
): Promise<boolean> => {
  const { signature, messageSigned } = await signMessageViaPassKeys({message, encodedId, isMessageSignedNeeded: true});

  const resp = await verifySignature(
    messageSigned as string,
    signature,
    eoaAddress
  );

  return resp;
};

const verifySignature = async (
  messageSigned: string,
  signature: string,
  eoaAddress: [string, string]
): Promise<boolean> => {
  
  const rValue = ethers.BigNumber.from("0x" + signature.slice(2, 66));
  const sValue = ethers.BigNumber.from("0x" + signature.slice(66, 132));
  const ellipticCurve = EllipticCurve__factory.connect(
    ELLIPTIC_CURVE_ADDRESS,
    new ethers.providers.JsonRpcProvider(JSON_RPC_PROVIDER)
  );
  
  const isVerified = await ellipticCurve.validateSignature(messageSigned, [rValue, sValue], eoaAddress);
  return isVerified;
};


export const signMessageViaPassKeys = async ({
  message,
  encodedId,
  isMessageSignedNeeded
}: IWebAuthnSignatureRequest): Promise<ISignatureResponse> => {
  const decodedId = base64url.decode(encodedId);
  const credential = await navigator.credentials.get({
    publicKey: {
      allowCredentials: [
        {
          id: decodedId,
          type: "public-key",
        },
      ],
      challenge: Uint8Array.from(message, (c) => c.charCodeAt(0)).buffer,
      // Set the required authentication factors
      userVerification: "required",
    },
  });
  if (credential === null) {
    // alert('Failed to get credential')
    return Promise.reject(new Error("Failed to get credential"));
  }
  //@ts-ignore
  const response = credential.response;

  const clientDataJSON = Buffer.from(response.clientDataJSON);

  let signatureValid = false;
  let signature;
  while (!signatureValid) {
    signature = await Axios({
      url: VERIFICATION_LAMBDA_URL,
      method: "post",
      params: {
        authDataRaw: JSON.stringify(
          Array.from(new Uint8Array(response.authenticatorData))
        ),
        cData: JSON.stringify(
          Array.from(new Uint8Array(response.clientDataJSON))
        ),
        signature: JSON.stringify(
          Array.from(new Uint8Array(response.signature))
        ),
      },
    });

    if (signature.data.message.processStatus === "success") {
      signatureValid = true;
    }
  }

  const value = clientDataJSON.toString("hex").slice(72, 248);
  const clientDataJsonRequestId = ethers.utils.keccak256("0x" + value);

  //@ts-ignore
  const finalSignatureWithMessage = signature.data.message.finalSignature + clientDataJsonRequestId.slice(2);

  const abi = ethers.utils.defaultAbiCoder;
  const decoded = abi.decode(
    ["uint256", "uint256", "uint256"],
    finalSignatureWithMessage
  );
  const signedMessage = decoded[2];

  if(isMessageSignedNeeded) {
    
    const rHex = decoded[0].toHexString();
    const sHex = decoded[1].toHexString();
    const finalSignature = rHex + sHex.slice(2);

    return {
      //! signature
      signature: finalSignature,
      messageSigned: signedMessage
    }
  }

  return {
    //! signature + message
    signature: finalSignatureWithMessage,
  };
};
