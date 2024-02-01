# Farcaster Delegator

A contract designed to own a [Farcaster](https://farcaster.xyz) id with the goal of delegating casting authority and other fid permissions to one or more individuals or groups.

This repo contains a generic abstract contract, [`FarcasterDelegator.sol`](#farcasterdelegatorsol), as well as an implementation powered by [Hats Protocol](https://github.com/hats-protocol/hats-protocol), [`HatsFarcasterDelegator.sol`](#hatsfarcasterdelegatorsol).

It can be useful to think about a FarcasterDelegator contract as a wrapper around an fid that adds more flexibility and control over who can cast from and administer the fid. For example, an organization could use a FarcasterDelegator contract to own an fid and share casting rights among a subset of its members. This use case is especially powerful with HatsFarcasterDelegator, since those rights can be programmed with the full flexibility of Hats Protocol, including programmatic granting and revocation.

See the [Diagrams](./diagrams/) directory for a visual representation of how HatsFarcasterDelegator can be used to delegate casting rights and to cast on behalf of an fid owned by a HatsFarcasterDelegator contract.

These docs are currently intended for smart contract developers and Farcaster client developers. Once support is added to at least one Farcaster client, we'll add docs for end users.

## HatsFarcasterDelegator.sol

[`HatsFarcasterDelegator.sol`](./src/HatsFarcasterDelegator.sol) inherits from [`FarcasterDelegator.sol`](#farcasterdelegatorsol) and implements the `_isValidSigner()` function to authorize signers for various functions via Hats Protocol hats.

### Valid Signers

HatsFarcasterDelegator contracts grant authorities to the wearers of two hats specified at deployment: the `ownerHat` and `casterHat`

The `ownerHat` grants authority for all functions. In other words, a user who wears the `ownerHat` is a valid signer for the following typehashes:

- IdRegistry.TRANSFER_TYPEHASH()
- IdGateway.REGISTER_TYPEHASH()
- KeyGateway.ADD_TYPEHASH()
- SignedKeyRequestValidator.METADATA_TYPEHASH()
- KeyRegistry.REMOVE_TYPEHASH()
- IdRegistry.CHANGE_RECOVERY_ADDRESS_TYPEHASH()

The `casterHat` — aka the `hatId` — grants authority to add a key to the contract's fid. This enables the wearer of the `casterHat` to publish casts from the fid. In other words, a user who wears the `casterHat` is a valid signer for the following typehashes:

- KeyGateway.ADD_TYPEHASH()
- SignedKeyRequestValidator.METADATA_TYPEHASH()

## FarcasterDelegator.sol

[`FarcasterDelegator.sol`](./src/FarcasterDelegator.sol) is an abstract contract designed to be used as a base for any contract that needs to own a Farcaster Id (fid) and grant casting and admin authorities to other actors.

It supports the following functions:

| Function                                                        | Related Farcaster Typehashes                                             |
| --------------------------------------------------------------- | ------------------------------------------------------------------------ |
| 1. Receive an existing fid transferred from a different account | IdRegistry.TRANSFER_TYPEHASH()                                           |
| 2. Register a new fid owned by itself                           | IdGateway.REGISTER_TYPEHASH()                                            |
| 3. Add a key to the fid, e.g. to delegate casting authority     | KeyGateway.ADD_TYPEHASH(), SignedKeyRequestValidator.METADATA_TYPEHASH() |
| 4. Remove a key from the fid                                    | KeyRegistry.REMOVE_TYPEHASH()                                            |
| 5. Transfer ownership of the fid to another account             | IdRegistry.TRANSFER_TYPEHASH()                                           |
| 6. Change the recovery address of the fid                       | IdRegistry.CHANGE_RECOVERY_ADDRESS_TYPEHASH()                            |

Since the [Farcaster contract](https://github.com/farcasterxyz/contracts) functions all have corresponding `<function>For` flavors powered by EIP-712 signatures, each of the above actions can either be initiated by the FarcasterDelegator contract or by a user with a valid signature.

### Valid Signers

This contract leaves the definition of a valid *signer* open to the implementer. In other words, the internal function `FarcasterDelegator._isValidSigner()` is virtual and unimplemented; implementers must override this function with their own logic.

```solidity
function _isValidSigner(bytes32 typehash, address signer) internal view virtual returns (bool);
```

The `typehash` argument is the EIP-712 typehash corresponding to the Farcaster function being authorized. This enables implementers to authorize different signers for different functions.

> [!NOTE]
> For an example implementation of `FarcasterDelegator._isValidSigner()`, see the [HatsFarcasterDelegator implementation](https://github.com/Hats-Protocol/farcaster-delegator/blob/main/src/HatsFarcasterDelegator.sol#L119).

### Valid Signatures

This contract, on the other hand, does specify the definition of a valid *signature*. The primary goal of the design is to enable granular authorization for as many of the above functions as the implementer would like.

```solidity
function isValidSignature(bytes32 hash, bytes calldata signature) public view returns (bytes4 magicValue);
```

Since `FarcasterDelegator.isValidSignature()` must conform to the above EIP-1271 standard function signature, we cannot explicitly pass it a `typehash` parameter for routing like we can with the `FarcasterDelegator._isValidSigner()`. To enable function-specific validation, then, we require the `typehash` be appended to the `signature` parameter so that we can extract it in the implementation.

To ensure that the `typehash` is valid for the function being called, we also require that the other EIP-712 typed data parameters be appended to the `signature` parameter. We can validate by extracting those parameters, recreating the correct typed hash using the EIP-712 domain separator from the relevant Farcaster contract, and comparing it to the `hash` parameter.

If this check passes, we can then validate the signature itself. Since a valid signature will always be 65 bytes long, the signature should be the first 65 bytes of the `signature` parameter. We then recover the signer from the signature and `hash`. If that signer is valid according to the logic in `FarcasterDelegator._isValidSigner()`, then the signature is deemed valid.

In summary, the `signature` parameter must be formatted as follows:

| Offset | Length | Contents                                                                            |
| ------ | ------ | ----------------------------------------------------------------------------------- |
| 0      | 65     | The actual signature                                                                |
| 65     | 32     | The EIP-712 typehash corresponding to the Farcaster function being authorized       |
| 97     | varies | The other EIP-712 typed data parameters for the Farcaster function being authorized |

### 1. Receiving an existing fid

A FarcasterDelegator contract is only useful when it owns an fid. In order to receive an existing fid, a FarcasterDelegator contract must be able to produce a signature authorizing receipt, as required by the Farcaster protocol.

There are two way to have FarcasterDelegator produce a transfer-approval signature, both triggered by a valid signer: a) the valid signer can "prepare" the FarcasterDelegator to receive the fid, or b) the valid signer can produce a valid `TRANSFER_TYPEHASH`-related ECDSA signature.

#### Receive Method A: using `prepareToReceive()`

This method is useful for signers authorized for the `TRANSFER_TYPEHASH` action but are not in a position to make a direct call to the FarcasterDelegator contract. Such as when using a Farcaster client that has not implemented specific support for FarcasterDelegator contracts, or when the signer is a contract itself.

In this method, a valid signer calls `FarcasterDelegator.prepareToReceive()` with the fid to be transferred as the sole argument. This function will store the fid as `receivable`, which will set up the contract to produce the correct transfer-approval signature.

Then, the owner of the fid can call `IdRegistry.transfer()`, passing in the address of the FarcasterDelegator contract (`to`), a `deadline`, and a signature blob (`sig`) as arguments. The signature should take [the form described above](#valid-signatures), but in this case the actual 65 signature bytes can take any value, since the `isValidSignature` logic for this method depends instead on the `receivable` storage variable.

Since `to` is our contract, the IdRegistry will attempt to verify the signature via EIP-1271, which will result in a call to `FarcasterDelegator.isValidSignature()`. As described [above](#valid-signatures), that function will extract the typehash and fid (via the typedData) from the `sig`. If that fid was set as `receivable` earlier, the function will authorize the signature as valid. See the logic in [`FarcasterDelegator._isValidSigner()`](./src/FarcasterDelegator.sol#L202) for the code.

#### Receive Method B: producing a signature

The other method utilizes the same approach to EIP-1271 as for other actions. Here's how it works:

A valid signer generates the EIP-712 typed data associated with the `IdRegistry.TRANSFER_TYPEHASH()` action (which, crucially, includes the fid itself), hashes it with `IdRegistry.hashTypedDataV4()`, signs it, appends the unhashed typed data bytes to the end of the signature, and finally shares the signature blob with the current owner of the fid.

> [!NOTE]
> Farcaster clients or other apps can help users prepare the typed data and signature. It's likely that this will be the most common way FarcasterDelegator contracts are used.

Then, the owner of the fid can call `IdRegistry.transfer()`, passing in the address of the FarcasterDelegator contract (`to`), a `deadline`, and a signature blob (`sig`) as arguments.

Since `to` is a contract, the IdRegistry will attempt to verify the signature via EIP-1271, which will result in a call to `FarcasterDelegator.isValidSignature()`. As described [above](#valid-signatures), that function will extract the typehash from the `sig`.

If the typehash is `TRANSFER_TYPEHASH`, the function will then extract the fid typed data parameter from the `sig`. Unlike Method A, the actual 65 signature bytes must contain an actual signature, since the `isValidSignature` logic for this method depends on the signature itself.

### 2. Registering a new fid

To register a new fid for a FarcasterDelegator contract, they must be a valid signer as determined by `FarcasterDelegator._isValidSigner(REGISTER_TYPEHASH)`.

The user calls `FarcasterDelegator.register()` with the desired recovery address and number of extra storage units. This function must be called with msg.value of sufficient native tokens to cover the cost of the storage units.

No EIP-1271 signatures are required for this action.

### 3. Adding a key to its fid

There are two paths to adding a key to a fid owned by a FarcasterDelegator contract.

#### 3a. Adding a key directly from a FarcasterDelegator contract

This path is useful for users who are authorized for the `ADD_TYPEHASH` action and are in a position to make a direct call to the FarcasterDelegator contract.

Since Farcaster requires that requests to add a new key be signed the owner of the fid, the FarcasterDelegator contract must be able to produce such a signature. We again utilize EIP-1271 to accomplish this. Here's how it works:

Firstly, the user must be a valid signer as determined by `FarcasterDelegator._isValidSigner(ADD_TYPEHASH)`.

The user generates the EIP-712 typed metadata bytes associated with the `SignedKeyRequestValidator.METADATA_TYPEHASH`, hashes it with `SignedKeyRequestValidator.hashTypedDataV4()`, signs it, and appends the unhashed typed data bytes to the end of the signature.

Then, the user generates the EIP-712 typed metadata bytes associated with the `ADD_TYPEHASH`, which includes the `METADATA_TYPEHASH`-related signature blob from above. The user then hashes it with `KeyGateway.hashTypedDataV4()`, signs it, and appends the unhashed typed data bytes to the end of *that* signature.

> [!WARNING]
> Yes, there are two signatures here, one embedded within the other. The order is important: the `METADATA_TYPEHASH`-related signature must be signed first and then incorporated into the hashed digest that is signed to produce the `ADD_TYPEHASH`-related signature.

Finally, anybody in possession of the final hashed typed data and signature blob — typically a Farcaster client or other app — calls `KeyGateway.addFor()`, passing in the key, the other `ADD_TYPEHASH`-related typed data parameters, and the metadata bytes as arguments. This function will in turn call `FarcasterDelegator.isValidSignature()` to verify the signature. If the signature is valid, the key will be added to the fid.

> [!NOTE]
> Farcaster clients or other apps can help users prepare the typed data, signature, and metadata generation. It's likely that this will be the most common way FarcasterDelegator contracts are used.

#### 3b. Adding a key with a signature via `KeyGateway.addFor()`

This method is useful for users who are authorized for the `ADD_TYPEHASH` action but are not in a position to make a direct call to the FarcasterDelegator contract, such as when using a Farcaster client that has not implemented specific support for FarcasterDelegator contracts.

The flow is similar to (3a), with one key (no pun intended) difference: instead of the user calling `FarcasterDelegator.addKey()`, the user generates the EIP-712 typed data associated with the `ADD_TYPEHASH`, signs it, and then appends the unhashed typed data bytes to the end of the signature.

The user generates the EIP-712 typed data associated with the `ADD_TYPEHASH`, signs it, and then appends the unhashed typed data bytes to the end of the signature.

Finally, anybody in possession of the final hashed typed data and signature blob — typically a Farcaster client or other app — can call `KeyGateway.addFor()`, passing in the key, the other `ADD_TYPEHASH`-related typed data parameters, and the metadata bytes as arguments. This function will call `FarcasterDelegator.isValidSignature()` to verify the signature. If the signature is valid, the key will be added to the fid.

> [!NOTE]
> Farcaster clients or other apps can help users prepare the typed data, signature, and metadata generation. It's likely that this will be the most common way FarcasterDelegator contracts are used.

### 4. Removing a key from its fid

There are two paths to removing a key to a fid owned by a FarcasterDelegator contract.

#### 4a. Removing a key directly from a FarcasterDelegator contract

This method is useful for users who are authorized for the `REMOVE_TYPEHASH` action and are in a position to make a direct call to the FarcasterDelegator contract.

To register a new fid for a FarcasterDelegator contract, the user must be a valid signer as determined by `FarcasterDelegator._isValidSigner(REMOVE_TYPEHASH)`.

The user calls `FarcasterDelegator.removeKey()` with the key to be removed as the sole argument.

No EIP-1271 signatures are required for this action.

#### 4b. Removing a key with a signature via `KeyRegistry.removeFor()`

This method is useful for users who are authorized for the `REMOVE_TYPEHASH` action but are not in a position to make a direct call to the FarcasterDelegator contract, such as when using a Farcaster client that has not implemented specific support for FarcasterDelegator contracts.

The flow is similar to (4a), with one key (no pun intended) difference: instead of the user calling `FarcasterDelegator.removeKey()`, the user generates the EIP-712 typed data associated with the `REMOVE_TYPEHASH`, signs it, and then appends the unhashed typed data bytes to the end of the signature.

Then, anybody in possession of the final hashed typed data and signature blob — typically a Farcaster client or other app — can call `KeyRegistry.removeFor()`, passing in the key, the other `REMOVE_TYPEHASH`-related typed data parameters, and the signature blob as arguments. This function will call `FarcasterDelegator.isValidSignature()` to verify the signature. If the signature is valid, the key will be removed from the fid.

> [!NOTE]
> Farcaster clients or other apps can help users prepare the typed data and signature. It's likely that this will be the most common way FarcasterDelegator contracts are used.

### 5. Transferring ownership of its fid

There are two paths to transferring an fid owned by a FarcasterDelegator contract.

#### 5a. Transferring an fid directly from a FarcasterDelegator contract

This method is useful for users who are authorized for the `TRANSFER_TYPEHASH` action and are in a position to make a direct call to the FarcasterDelegator contract.

Similar to the receiving flow [receiving an existing fid](#1-receiving-an-existing-fid), the recipient must sign a message authorizing receipt of the fid.

Then, a user who is a valid signer — as determined by `_isValidSigner(TRANSFER_TYPEHASH)` — calls `FarcasterDelegator.transferFid()`; with the recipient address, signature deadline, and signature as arguments. This function calls `IdRegistry.transfer()`, with the same arguments, which then in turn calls `FarcasterDelegator.isValidSignature()` to verify the signature. If the signature is valid, the fid will be transferred to the recipient.

> [!NOTE]
> Farcaster clients or other apps can help users prepare the typed data and signature. It's likely that this will be the most common way FarcasterDelegator contracts are used.

#### 5b. Transferring an fid with a signature via `IdRegistry.transferFor()`

This method is useful for users who are authorized for the `TRANSFER_TYPEHASH` action but are not in a position to make a direct call to the FarcasterDelegator contract, such as when using a Farcaster client that has not implemented specific support for FarcasterDelegator contracts.

The flow is similar to (5a), with one key (again, no pun intended) difference: instead of the user calling `FarcasterDelegator.transferFid()`, the user generates the EIP-712 typed data associated with the `TRANSFER_TYPEHASH`, signs it, and then appends the unhashed typed data bytes to the end of the signature.

Then, anybody in possession of the final hashed typed data and signature blob — typically a Farcaster client or other app — can call `IdRegistry.transferFor()`, passing in the recipient address, signature deadline, and signature as arguments. This function will call `FarcasterDelegator.isValidSignature()` to verify the signature. If the signature is valid, the fid will be transferred to the recipient.

> [!NOTE]
> Farcaster clients or other apps can help users prepare the typed data and signature. It's likely that this will be the most common way FarcasterDelegator contracts are used.

### 6. Changing the recovery address of its fid

There are two paths to changing the recovery address of an fid owned by a FarcasterDelegator contract.

#### 6a. Changing the recovery address directly from a FarcasterDelegator contract

This method is useful for users who are authorized for the `CHANGE_RECOVERY_ADDRESS_TYPEHASH` action and are in a position to make a direct call to the FarcasterDelegator contract.

To register a new fid for a FarcasterDelegator contract, the user must be a valid signer as determined by `FarcasterDelegator._isValidSigner(CHANGE_RECOVERY_ADDRESS_TYPEHASH)`.

The user calls `FarcasterDelegator.changeRecoveryAddress()` with the new recovery address as the sole argument.

No EIP-1271 signatures are required for this action.

#### 6b. Changing the recovery address with a signature via `IdRegistry.changeRecoveryAddressFor()`

This method is useful for users who are authorized for the `CHANGE_RECOVERY_ADDRESS_TYPEHASH` action but are not in a position to make a direct call to the FarcasterDelegator contract, such as when using a Farcaster client that has not implemented specific support for FarcasterDelegator contracts.

The flow is similar to (6a), with one key (again, no pun intended) difference: instead of the user calling `FarcasterDelegator.changeRecoveryAddress()`, the user generates the EIP-712 typed data associated with the `CHANGE_RECOVERY_ADDRESS_TYPEHASH`, signs it, and then appends the unhashed typed data bytes to the end of the signature.

Then, anybody in possession of the final hashed typed data and signature blob — typically a Farcaster client or other app — can call `IdRegistry.changeRecoveryAddressFor()`, passing in the new recovery address, the other `CHANGE_RECOVERY_ADDRESS_TYPEHASH`-related typed data parameters, and the signature blob as arguments. This function will then call `FarcasterDelegator.isValidSignature()` to verify the signature. If the signature is valid, the recovery address will be changed.

> [!NOTE]
> Farcaster clients or other apps can help users prepare the typed data and signature. It's likely that this will be the most common way FarcasterDelegator contracts are used.

## Development

This repo uses Foundry for development and testing. To get started:

1. Fork the project
2. Install [Foundry](https://book.getfoundry.sh/getting-started/installation)
3. To install dependencies, run `forge install`
4. To compile the contracts, run `forge build`
5. To test, run `forge test`
