// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// import { console2 } from "forge-std/Test.sol"; // comment out before deploy
import { IERC1271 } from "./interfaces/IERC1271.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { IIdRegistry } from "farcaster/interfaces/IIdRegistry.sol";
import { IIdGateway } from "farcaster/interfaces/IIdGateway.sol";
import { IKeyRegistry } from "farcaster/interfaces/IKeyRegistry.sol";
import { IKeyGateway } from "farcaster/interfaces/IKeyGateway.sol";
import { TransferHelper } from "farcaster/libraries/TransferHelper.sol";

interface EIP712Like {
  function hashTypedDataV4(bytes32 structHash) external view returns (bytes32);
}

abstract contract FarcasterDelegator is IERC1271 {
  using TransferHelper for address;
  /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
  //////////////////////////////////////////////////////////////*/

  /// @dev Thrown when a caller is not authorized for the action they are attempting to perform.
  error Unauthorized();

  /// @dev Thrown when attempting to prepare this contract to receive an fid but already has one registered.
  error AlreadyRegistered();

  /// @dev Thrown when attempting to validate a signature with an unknown typehash.
  error InvalidTypehash();

  /// @dev Thrown when attempting to validate a signature with invalid typed data parameters.
  error InvalidTypedData();

  /// @dev Thrown when attempting to validate a signature that is invalid for the signer.
  error InvalidSignature();

  /// @dev Thrown when attempting to validate a signature with an invalid signer.
  error InvalidSigner();

  /*//////////////////////////////////////////////////////////////
                                EVENTS
  //////////////////////////////////////////////////////////////*/

  /// @dev Emitted when the contract has been approved to receive a given fid without an accompanying cryptographic
  /// signature by an authorized signer.
  /// @param fid The fid that the contract is ready to receive.
  event ReadyToReceive(uint256 fid);

  /*//////////////////////////////////////////////////////////////
                            CONSTANTS
  //////////////////////////////////////////////////////////////*/

  bytes32 public constant REGISTER_TYPEHASH =
    keccak256("Register(address to,address recovery,uint256 nonce,uint256 deadline)");

  bytes32 public constant ADD_TYPEHASH = keccak256(
    "Add(address owner,uint32 keyType,bytes key,uint8 metadataType,bytes metadata,uint256 nonce,uint256 deadline)"
  );

  bytes32 public constant REMOVE_TYPEHASH = keccak256("Remove(address owner,bytes key,uint256 nonce,uint256 deadline)");

  bytes32 public constant TRANSFER_TYPEHASH =
    keccak256("Transfer(uint256 fid,address to,uint256 nonce,uint256 deadline)");

  bytes32 public constant CHANGE_RECOVERY_ADDRESS_TYPEHASH =
    keccak256("ChangeRecoveryAddress(uint256 fid,address from,address to,uint256 nonce,uint256 deadline)");

  bytes32 public constant SIGNED_KEY_REQUEST_TYPEHASH =
    keccak256("SignedKeyRequest(uint256 requestFid,bytes key,uint256 deadline)");

  bytes4 public constant ERC1271_MAGICVALUE = IERC1271.isValidSignature.selector;

  /*//////////////////////////////////////////////////////////////
                            MUTABLE STATE
  //////////////////////////////////////////////////////////////*/

  /// @dev A mapping of fids that have been approved as receivable by this contract.
  mapping(uint256 fid => bool receivable) public receivable;

  /*//////////////////////////////////////////////////////////////
                                VIEWS
  //////////////////////////////////////////////////////////////*/

  /// @notice The address of the Farcaster Id Gateway
  function idGateway() public view virtual returns (IIdGateway) { }

  /// @notice The address of the Farcaster Id Registry
  function idRegistry() public view virtual returns (IIdRegistry) { }

  /// @notice The address of the Farcaster Key Gateway
  function keyGateway() public view virtual returns (IKeyGateway) { }

  /// @notice The address of the Farcaster Id Registry
  function keyRegistry() public view virtual returns (IKeyRegistry) { }

  /// @notice The address of the Farcaster SignedKeyRequestValidator
  function signedKeyRequestValidator() public view virtual returns (address) { }

  /*//////////////////////////////////////////////////////////////
                        FARCASTER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// See {IIdGateway.register}
  function register(address _recovery, uint256 _extraStorage)
    public
    payable
    virtual
    returns (uint256 fid, uint256 overpayment)
  {
    _checkValidSigner(REGISTER_TYPEHASH, msg.sender);
    (fid, overpayment) = idGateway().register{ value: msg.value }(_recovery, _extraStorage);

    // refund any overpayment to the caller
    if (overpayment > 0) {
      msg.sender.sendNative(overpayment);
    }
  }

  /// See {IKeyGateway.add}
  function addKey(uint32 _keyType, bytes calldata _key, uint8 _metadataType, bytes calldata _metadata) public virtual {
    _checkValidSigner(ADD_TYPEHASH, msg.sender);
    keyGateway().add(_keyType, _key, _metadataType, _metadata);
  }

  /// See {IKeyRegistry.remove}
  function removeKey(bytes calldata _key) public virtual {
    _checkValidSigner(REMOVE_TYPEHASH, msg.sender);
    keyRegistry().remove(_key);
  }

  /// See {IIdRegistry.transfer}
  function transferFid(address _to, uint256 _deadline, bytes calldata _sig) public virtual {
    _checkValidSigner(TRANSFER_TYPEHASH, msg.sender);
    idRegistry().transfer(_to, _deadline, _sig);
  }

  /// See {IIdRegistry.changeRecoveryAddress}
  function changeRecoveryAddress(address _newRecovery) public virtual {
    _checkValidSigner(CHANGE_RECOVERY_ADDRESS_TYPEHASH, msg.sender);
    idRegistry().changeRecoveryAddress(_newRecovery);
  }

  /*//////////////////////////////////////////////////////////////
                            FID RECEIVING 
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Enable this contract to receive a given fid. Especially useful for use when the signer(s) authorized for
   * the TRANSFER_TYPEHASH cannot conveniently produce a cryptographic signature that can be passed to
   * {idRegistry.transfer}.
   * @dev Establishes the state that will allow this contract to produce a valid ERC1271 signature required to receive
   * an fid transfer. This contract must not already have an fid registered to it.
   * @param _fid The fid that this contract will receive.
   */
  function prepareToReceive(uint256 _fid) public {
    if (idRegistry().idOf(address(this)) > 0) revert AlreadyRegistered();

    _prepareToReceive(_fid);

    emit ReadyToReceive(_fid);
  }

  /// @dev Establishes the state that will allow this contract to produce a valid ERC1271 signature required by
  /// {idRegistry.transfer} to receive the transferred fid
  function _prepareToReceive(uint256 _fid) internal virtual {
    _checkValidSigner(TRANSFER_TYPEHASH, msg.sender);

    receivable[_fid] = true;
  }

  /*//////////////////////////////////////////////////////////////
                        SIGNER VERIFICATION
  //////////////////////////////////////////////////////////////*/

  /**
   * @inheritdoc IERC1271
   * @notice The validity of a signature depends on the Farcaster action it authorizes, denoted by the Farcaster
   * typehash. This function expects the EIP712 typed data parameters used to generate the `_hash` to be appended to the
   * end of the signature blob. It will attempt to extract the typehash and use it to route the validation logic. If
   * the typehash is not recognized, or if the `_hash` cannot be recreated from the typed data parameters, the signature
   * will be considered invalid.
   *
   * @param _signature Must this scheme to enable the relevant typehash-based routing logic:
   * ------------------------------------------------------------------------------------------------------------------|
   * | Offset        | Length   | Description                                                                          |
   * ------------------------------------------------------------------------------------------------------------------|
   * | 0             | 2        | Length of signature, `sigLen`                                                        |
   * | 2             | `sigLen` | The signature associated with the `_hash`. Can be either ECDSA or ERC1271 signature. |
   * | 2  + `sigLen` | 32       | Typehash of the Farcaster action being authorized                                    |
   * | 34 + `sigLen` | any      | EIP712 typed data, not including the typehash                                        |
   * ------------------------------------------------------------------------------------------------------------------|
   *
   * - EOA signatures should be packed ECDSA signatures of the form `{bytes32 r}{bytes32 s}{uint8 v}`, ie 65 bytes long.
   * - ERC1271 signatures should be at least 65 bytes long, where in the first 65 bytes the address of the signing
   * contract is encoded into r and v=0. See
   *
   * There is a special case for TRANSFER_TYPEHASH when this contract has been prepared to receive a given fid and does
   * not already have one registered to it. In this case, a cryptographic signature is not required, and therefore the
   * actualy signature [2:2 + `sigLen`] can take any value or length — a `sigLen` of 0 is recommended for gas
   * efficiency.
   *
   * @return ERC1271_MAGICVALUE if the signature is valid, or one of the following error selectors if invalid:
   *  - `InvalidTypehash.selector` if the typehash is not recognized
   *  - `InvalidTypedData.selector` if the `_hash` cannot be recreated from the typed data parameters
   *  - `InvalidSigner.selector` if the signer is not authorized for the given typehash
   */
  function isValidSignature(bytes32 _hash, bytes calldata _signature) public view override returns (bytes4) {
    // the actual "sig" is the component of the _signature bytes array that corresponds to an ECDSA or ERC1271 signature
    // the length of the actual sig is stored first 2 bytes of the _signature bytes array
    uint256 sigLength = abi.decode(_signature[0:2], (uint256));
    uint256 typehashOffset = 2 + sigLength;

    // extract the typehash from 1st word after the sig
    bytes32 typehash = bytes32(_signature[typehashOffset:typehashOffset + 32]);

    // allocate memory for the address of the typehash source, to be determined below
    address typehashSource;

    // Determine the source of the typehash, returning the InvalidTypehash error code if it is unknown.
    if (typehash == TRANSFER_TYPEHASH) {
      // TRANSFER_TYPEHASH has additional logic, so we handle it first
      // extract fid from 2nd word after the actual sig bytes
      uint256 fid = abi.decode(_signature[typehashOffset + 32:typehashOffset + 64], (uint256));

      if (receivable[fid] && idRegistry().idOf(address(this)) != fid) {
        // this contract does not own fid, and fid has been approved to be received by this contract
        // so this is a valid signature regardless of the value of the actual sig
        return ERC1271_MAGICVALUE;
      } else {
        // otherwise, we handle it just like other typehashes
        typehashSource = address(idRegistry());
      }
    } else if (typehash == ADD_TYPEHASH) {
      typehashSource = address(keyGateway());
    } else if (typehash == REMOVE_TYPEHASH) {
      typehashSource = address(keyRegistry());
    } else if (typehash == CHANGE_RECOVERY_ADDRESS_TYPEHASH) {
      typehashSource = address(idRegistry());
    } else if (typehash == SIGNED_KEY_REQUEST_TYPEHASH) {
      typehashSource = signedKeyRequestValidator();
    } else {
      // unknown or unauthorized typehash
      return InvalidTypehash.selector;
    }

    // extract the typed data params (including the typehash) from the _signature bytes array
    // ie everything after the actual sig
    bytes memory typedData = _signature[typehashOffset:];

    // check that _hash can be recreated from the extracted data, using the typehashSource determined above
    if (_hash != _recreateTypedHash(typehashSource, typedData)) {
      return InvalidTypedData.selector;
    }

    // extract the actual sig from the _signature bytes array
    bytes memory sig = _signature[2:typehashOffset];
    // split the signature into its components
    (uint8 v, bytes32 r, bytes32 s) = _splitSignature(sig);

    // recover the signer
    address signer;

    if (v == 0) {
      // This is an EIP-1271 contract signature
      // The address of the signer contract is encoded into r
      signer = address(uint160(uint256(r)));

      // We also need to check that the signature is valid for the signing contract.
      // The offset of the contract signature data is stored in s
      if (!_isValidContractSignature(signer, _hash, sig, s)) return InvalidSignature.selector;
    } else {
      // This is an EOA signature
      // The signer is recovered from the ECDSA signature
      /// @dev ECDSA.recover() will revert with `InvalidSignature()` if the sig is cryptographically invalid
      signer = ECDSA.recover(_hash, v, r, s);
    }

    // check that the signer is valid for the typehash and return the ERC1271 magic value if so
    if (_isValidSigner(typehash, signer)) {
      return ERC1271_MAGICVALUE;
    } else {
      return InvalidSigner.selector;
    }
  }

  /*//////////////////////////////////////////////////////////////
                    SIGNATURE VALIDATION HELPERS
  //////////////////////////////////////////////////////////////*/

  /// @dev Check whether `_signer` is authorized by this contract for the given `_typehash` action
  function _isValidSigner(bytes32 _typehash, address _signer) internal view virtual returns (bool) { }

  /// @dev Recreate a typed hash from the provided `_typedData` using the provided `_typehashSource`
  function _recreateTypedHash(address _typehashSource, bytes memory _typedData) internal view returns (bytes32) {
    return EIP712Like(_typehashSource).hashTypedDataV4(keccak256(_typedData));
  }

  /**
   * @dev Divides bytes signature into `uint8 v, bytes32 r, bytes32 s`, ignoring anything after the first 65 bytes.
   * Borrowed from https://github.com/gnosis/mech/blob/main/contracts/base/Mech.sol
   * @param signature The signature bytes array
   */
  function _splitSignature(bytes memory signature) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
    // The signature format is a compact form of:
    //   {bytes32 r}{bytes32 s}{uint8 v}
    // Compact means, uint8 is not padded to 32 bytes.
    // solhint-disable-next-line no-inline-assembly
    assembly {
      r := mload(add(signature, 0x20))
      s := mload(add(signature, 0x40))
      v := byte(0, mload(add(signature, 0x60)))
    }
  }

  /**
   * @dev Validates a contract signature using the ERC1271 interface
   * @param _signer The address of the signing contract
   * @param _hash The hash of the message being "signed"
   * @param _signature The ERC1271 signature bytes array
   * @param _offset The offset in the `_signature` bytes array pointing to the start of the contract signature data
   */
  function _isValidContractSignature(address _signer, bytes32 _hash, bytes memory _signature, bytes32 _offset)
    internal
    view
    returns (bool)
  {
    // extract the contract signature data from the _signature bytes array
    bytes memory contractSignature;
    // solhint-disable-next-line no-inline-assembly
    assembly {
      contractSignature := add(add(_signature, _offset), 0x20) // add 0x20 to skip over the length of the bytes array
    }

    // check that the contract signature is valid for the signing contract
    return (IERC1271(_signer).isValidSignature(_hash, contractSignature) == IERC1271.isValidSignature.selector);
  }

  /*//////////////////////////////////////////////////////////////
                            ACCESS CONTROL
  //////////////////////////////////////////////////////////////*/

  /// @dev Revert with `Unauthorized` if `_signer` is not authorized by this contract for the given `_typehash` action
  function _checkValidSigner(bytes32 _typehash, address _signer) internal view virtual {
    if (!_isValidSigner(_typehash, _signer)) revert Unauthorized();
  }

  /*//////////////////////////////////////////////////////////////
                         INTERFACE DETECTION
  //////////////////////////////////////////////////////////////*/

  function supportsInterface(bytes4 _interfaceId) public pure returns (bool) {
    return _interfaceId == type(IERC1271).interfaceId;
  }

  /*//////////////////////////////////////////////////////////////
                            FALLBACK
  //////////////////////////////////////////////////////////////*/

  receive() external payable { }
}
