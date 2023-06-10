# Passkey Signer for Account Abstraction Wallets

The Passkey Signer is a component designed to facilitate signing operations for Smart Contract wallets using a passkey.

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)


## Introduction

Passkey Signer will be an extension of ethers abstract signer and provide the functionality to sign transactions, messages and typed messages for blockchains using passkeys. A passkey is a digital credential, tied to a user account and a website or application. Passkeys allow users to authenticate without having to enter a username or password, or provide any additional authentication factor. This technology aims to replace legacy authentication mechanisms such as passwords. Passkeys are a replacement for private key management. They are faster to sign in with, easier to use, and much more secure.

## Features

- **Better UX**: There are several hurdles in onboarding a new user to blockchain. Seed phrases and private key management were never a good option. These things should be handled in a manner that users not familiar with the importance of their security concern should also not loose funds.
- **Improved Security**: This is something which should not be advertized but should be inherntly given. With passkeys the problem of weak and reused credentials, leaked credentials and phishing are not possible. 
- **Plug and Play**: Any smart contract wallet or wallet sdk while initialization requires an assistance of EOA wallet for signing messages and transactions. And most Smart contract wallets still uses Metamask for this purpose which kindoff deviates from the goal of simplifying user experience. So instead of having Metamask as an EOA for transaction/message signing wallet infra + wallets can plug in passkey module as an EOA which would facilitate transaction and message signing. 
- **Cross platform support**: Using The solution can be used in devices which don’t support biometric scanning but have TEE support in them. This can be achieved using a simple QR code scanning. In the backed, the devices are performing a local key agreement, proving proximity and establishing an end to end encrypted communication channel. This maintains the strong security standards against phishing.

## Installation

To install the Passkey Signer module, follow these steps:

```
yarn add @rize-labs/banana-passkey-manager

OR

npm i @rize-labs/banana-passkey-manager

```

## Usage

To use the Passkey Signer module, follow these steps:

```
// importing PasskeyEoaSigner package 
import { PasskeyEoaSigner } from '@rize-labs/banana-passkey-manager';
import { ABCWallet } from 'ABCWallet-sdk';

// initializing jsonRpcProvider 
const provider = ethers.getDefaultProvider();

// creating an instance out of it 
const bananaEoaSignerInstance = new PasskeyEoaSigner(provider);

// initializing the EOA with a specific username (it should be unique) corresponding to which the passkey
// would be created and later on accessing
await bananaEoaSignerInstance.init('<username>');

// initializing signer for smart contract wallet.
const abcSmartWalletInstance = new ABCWallet(bananaEoaSignerInstance);

```


## Contributing
Contributions to the Passkey Signer project are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request on the project's GitHub repository.


