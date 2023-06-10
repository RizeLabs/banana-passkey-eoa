import * as dotenv from 'dotenv';
dotenv.config();

export const REGISTRATION_LAMBDA_URL = 'https://8zfpr8iyag.execute-api.us-east-1.amazonaws.com/extract_qvalues'
export const VERIFICATION_LAMBDA_URL = 'https://muw05wa93c.execute-api.us-east-1.amazonaws.com/'
export const BANANA_SERVER = 'https://banana-server.xyz'
export const GET_WALLETCRED_ROUTE = '/get-user-credentials'
export const IS_WALLETNAME_UNIQUE_ROUTE = '/check-walletname-exists'
export const JSON_RPC_PROVIDER = 'https://polygon-mumbai.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}'