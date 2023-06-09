import { Signer } from "ethers";
import { TypedDataSigner } from "@ethersproject/abstract-signer";
import { register, signMessageViaPassKeys } from "./WebAuthn";
import { Logger } from "@ethersproject/logger";
import { Provider, TransactionRequest } from "@ethersproject/providers";
import { Deferrable } from "@ethersproject/properties";
import { Bytes } from "@ethersproject/bytes";
import { ethers } from "ethers";
import { IWebAuthnRegistrationResponse } from "./types/WebAuthnTypes";
import { getPasskeyMeta, isUserNameUnqiue } from "./BananaController";
import { _TypedDataEncoder } from "ethers/lib/utils";
import { checkAuth } from "./WebAuthn";
import { generateRandomString } from "./utils/randomMessageGenerator";

const logger = new Logger("abstract-signer/5.7.0");

export class BananaPasskeyEoaSigner extends Signer implements TypedDataSigner {
  #publicKey: IWebAuthnRegistrationResponse =
    {} as IWebAuthnRegistrationResponse;
  readonly provider: Provider;

  //! username from popup
  async init(username: string) {
    const isUserNameUnique = await isUserNameUnqiue(username);
    let webAuthnConnectionResponse: IWebAuthnRegistrationResponse;
    let isUserAuthorized = true;

    if (!isUserNameUnique) {
      webAuthnConnectionResponse = await getPasskeyMeta(username);
      isUserAuthorized = await checkAuth(generateRandomString(30), webAuthnConnectionResponse.encodedId, [webAuthnConnectionResponse.q0, webAuthnConnectionResponse.q1]);
    } else {
      webAuthnConnectionResponse = await register();
    }

    if(!isUserAuthorized) {
      throw new Error('You are not authorized to use this wallet');
    }

    this.#publicKey.q0 = webAuthnConnectionResponse.q0;
    this.#publicKey.q1 = webAuthnConnectionResponse.q1;
    this.#publicKey.encodedId = webAuthnConnectionResponse.encodedId;
  }

  constructor(provider: Provider, publicKey?: IWebAuthnRegistrationResponse) {
    super();
    this.provider = provider;

    if (publicKey) {
      this.#publicKey = publicKey;
    }
  }

  connect(): Signer {
    return logger.throwError(
      "cannot alter JSON-RPC Signer connection",
      Logger.errors.UNSUPPORTED_OPERATION,
      {
        operation: "connect",
      }
    );
  }

  async getChainId(): Promise<number> {
    return (await this.provider.getNetwork()).chainId;
  }

  getAddress(): Promise<string> {
    const uncompressedPublicKey = `0x04${this.#publicKey.q0.slice(
      2
    )}${this.#publicKey.q1.slice(2)}`;
    const eoaAddress = ethers.utils.computeAddress(uncompressedPublicKey);
    return Promise.resolve(eoaAddress);
  }

  //! mainly signMessage is getting userOp not even sign transaction
  signTransaction(
    transaction: Deferrable<TransactionRequest>
  ): Promise<string> {
    return logger.throwError(
      "signing transactions is unsupported",
      Logger.errors.UNSUPPORTED_OPERATION,
      {
        operation: "signTransaction",
      }
    );
  }

  async signMessage(message: Bytes | string): Promise<string> {
    if (!this.#publicKey.encodedId) {
      return Promise.reject(new Error("encoded ID not provided"));
    }

    if (ethers.utils.isBytes(message)) {
      message = ethers.utils.hexlify(message).toString();
    }

    const { signature } = await signMessageViaPassKeys({
      message: message,
      encodedId: this.#publicKey.encodedId,
    });
    return signature;
  }

  async _signTypedData(
    domain: ethers.TypedDataDomain,
    types: Record<string, ethers.TypedDataField[]>,
    value: Record<string, any>
  ): Promise<string> {
    const populated = await _TypedDataEncoder.resolveNames(
      domain,
      types,
      value,
      async (name: string): Promise<any> => {

        if(!this.provider) {
          return logger.throwError(
            "cannot resolve ENS names without a provider",
            Logger.errors.UNSUPPORTED_OPERATION,
            {
              operation: "resolveName",
              info: { name },
            }
          );
        }

        const address = await this.provider.resolveName(name);

        if(!address) {
          return 'UNCONFIGURED_NAME: unconfigured ENS name';
        }

        return address;
      }
    );

    const hash = _TypedDataEncoder.hash(
      populated.domain,
      types,
      populated.value
    );

    const { signature } = await signMessageViaPassKeys({ message: hash, encodedId: this.#publicKey.encodedId });
    return signature;
  }
}
