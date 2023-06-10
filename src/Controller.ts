import { constructUniqueIdentifier } from "./utils/constructUserUniqueIdentifier";
import { BANANA_SERVER, GET_WALLETCRED_ROUTE, IS_WALLETNAME_UNIQUE_ROUTE } from "./constants/routes";
import { IWebAuthnRegistrationResponse, Method } from "./types";
import Axios from "axios";


/**
 * Retrieves passkey metadata for a given wallet identifier.
 * @param walletIdentifier The wallet identifier.
 * @returns A Promise that resolves to an IWebAuthnRegistrationResponse object.
 */
export const getPasskeyMeta = async (walletIdentifier: string): Promise<IWebAuthnRegistrationResponse> => {
  try {
    const identifier = constructUniqueIdentifier(
      walletIdentifier,
      window.location.hostname
    );
    
    const walletCredentials = await Axios({
      url: BANANA_SERVER + GET_WALLETCRED_ROUTE,
      method: Method.GET,
      params: {
        uniqueIdentifier: identifier,
      },
    });
    
    if (walletCredentials.data.data !== "") {
      return JSON.parse(walletCredentials.data.data);
    }

    return {} as IWebAuthnRegistrationResponse;
  } catch (err) {
    console.log(err);
    throw err;
  }
};

/**
 * Checks if a given wallet name is unique.
 * @param walletName The wallet name to check for uniqueness.
 * @returns A boolean indicating whether the wallet name is unique.
 */
export const isUserNameUnqiue = async (walletName: string) => {
    try {
        const identifier = constructUniqueIdentifier(walletName, window.location.hostname);
        const isWalletUnique = await Axios({
            url: BANANA_SERVER + IS_WALLETNAME_UNIQUE_ROUTE,
            method: Method.POST,
            data: {
                walletName: identifier
            }
        })
        if(isWalletUnique.data.isUnique) {
            return true;
        }
        return false;
    } catch (err) {
      console.log(err);
      throw err;
    }
}