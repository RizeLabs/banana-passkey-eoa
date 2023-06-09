import { constructUniqueIdentifier } from "./utils/constructUserUniqueIdentifier";
import { BANANA_SERVER, GET_WALLETCRED_ROUTE, IS_WALLETNAME_UNIQUE_ROUTE } from "./constants/routes";
import { IWebAuthnRegistrationResponse } from "./types/WebAuthnTypes";
import Axios from "axios";

export const getPasskeyMeta = async (walletIdentifier: string): Promise<IWebAuthnRegistrationResponse> => {
  try {
    const identifier = constructUniqueIdentifier(
      walletIdentifier,
      window.location.hostname
    );
    
    const walletCredentials = await Axios({
      url: BANANA_SERVER + GET_WALLETCRED_ROUTE,
      method: "get",
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

export const isUserNameUnqiue = async (walletName: string) => {
    try {
        const identifier = constructUniqueIdentifier(walletName, window.location.hostname);
        const isWalletUnique = await Axios({
            url: BANANA_SERVER + IS_WALLETNAME_UNIQUE_ROUTE,
            method: 'post',
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