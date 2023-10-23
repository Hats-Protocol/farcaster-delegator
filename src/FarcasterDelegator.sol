// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// import { console2 } from "forge-std/Test.sol"; // remove before deploy
import { IERC1271 } from "./interfaces/IERC1271.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { IIdRegistry } from "farcaster/interfaces/IIdRegistry.sol";
import { IKeyRegistry } from "farcaster/interfaces/IKeyRegistry.sol";

interface EIP712Like {
  function hashTypedDataV4(bytes32 structHash) external view returns (bytes32);
}

abstract contract FarcasterDelegator is IERC1271 {
  /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
  //////////////////////////////////////////////////////////////*/

  /**
   * @dev Thrown when a caller is not authorized for the action they are attempting to perform.
   */
  error Unauthorized();

  /**
   * @dev Thrown when attempting to prepare this contract to receive an fid but already has one registered.
   */
  error AlreadyRegistered();

  /*//////////////////////////////////////////////////////////////
                                EVENTS
  //////////////////////////////////////////////////////////////*/

  /**
   * @dev Emitted when the contract is ready to receive a fid.
   * @param fid The fid that the contract is ready to receive.
   */
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
    keccak256("ChangeRecoveryAddress(uint256 fid,address recovery,uint256 nonce,uint256 deadline)");

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

  /// @notice The address of the Farcaster Id Registry
  function idRegistry() public view virtual returns (IIdRegistry) { }

  /// @notice The address of the Farcaster Id Registry
  function keyRegistry() public view virtual returns (IKeyRegistry) { }

  /// @notice The address of the Farcaster SignedKeyRequestValidator
  function signedKeyRequestValidator() public view virtual returns (address) { }

  /*//////////////////////////////////////////////////////////////
                        FARCASTER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// See {IIdRegistry.register}
  function register(address _recovery) public returns (uint256 fid) {
    _checkValidSigner(REGISTER_TYPEHASH, msg.sender);
    fid = idRegistry().register(_recovery);
  }

  /// See {IKeydRegistry.add}
  function addKey(uint32 _keyType, bytes calldata _key, uint8 _metadataType, bytes calldata _metadata) public {
    _checkValidSigner(ADD_TYPEHASH, msg.sender);
    keyRegistry().add(_keyType, _key, _metadataType, _metadata);
  }

  /// See {IKeyRegistry.remove}
  function removeKey(bytes calldata _key) public {
    _checkValidSigner(REMOVE_TYPEHASH, msg.sender);
    keyRegistry().remove(_key);
  }

  /// See {IIdRegistry.transfer}
  function transferFid(address _to, uint256 _deadline, bytes calldata _sig) public {
    _checkValidSigner(TRANSFER_TYPEHASH, msg.sender);
    idRegistry().transfer(_to, _deadline, _sig);
  }

  /// See {IIdRegistry.changeRecoveryAddress}
  function changeRecoveryAddress(address _newRecovery) public {
    _checkValidSigner(CHANGE_RECOVERY_ADDRESS_TYPEHASH, msg.sender);
    idRegistry().changeRecoveryAddress(_newRecovery);
  }

  /*//////////////////////////////////////////////////////////////
                            FID RECEIVING 
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Prepare to receive an fid.
   * @dev Establishes the state that will allow this contract to produce a valid ERC1271 signature required to receive
   * an fid transfer.
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
   *  @param _signature Must take the following format to enable the relevant typehash-based routing logic:
   *  - First 65 bytes: the actual signature produced by signing the `_hash`
   *  - Next 32 bytes: the typehash of the Farcaster action being authorized
   *  - Remaining bytes: the EIP712 typed data parameters used to generate the `_hash`, not including the typehash
   */
  function isValidSignature(bytes32 _hash, bytes calldata _signature) public view override returns (bytes4) {
    // extract the signature from the _signature blob, ie the first 65 bytes
    bytes memory sig = _signature[0:65];

    /// @dev ECDSA.recover() will revert with `InvalidSignature()` if the sig is cryptographically invalid
    address signer = ECDSA.recover(_hash, sig);

    // extract the typehash from 1st word after the sig, ie the 66th to 98th bytes of the _signature blob
    bytes32 typehash = bytes32(_signature[65:97]);

    address typehashSource;

    // Check that the typehash is from a known source and if so set that address as our source for recreating the
    // typed hashed data. Otherwise, return invalid signature.
    if (typehash == ADD_TYPEHASH || typehash == REMOVE_TYPEHASH) {
      // typehash is from keyRegistry
      typehashSource = address(keyRegistry());
    } else if (typehash == TRANSFER_TYPEHASH) {
      // extract fid from 2nd word after the sig, ie the 98th to 130th bytes of the _signature blob
      uint256 fid = abi.decode(_signature[97:129], (uint256));
      if (receivable[fid] && idRegistry().idOf(address(this)) != fid) {
        // this contract does not own fid, and fid is approved to be received by this contract
        // so this is a valid signature
        return ERC1271_MAGICVALUE;
      } else {
        // this may be a {idRegistry.transferFor} call to transfer an fid *from* this contract
        // typehash is from idRegistry
        typehashSource = address(idRegistry());
      }
    } else if (typehash == CHANGE_RECOVERY_ADDRESS_TYPEHASH) {
      // typehash is from idRegistry
      typehashSource = address(idRegistry());
    } else if (typehash == SIGNED_KEY_REQUEST_TYPEHASH) {
      // call is originating from a SignedKeyRequestValidator
      typehashSource = signedKeyRequestValidator();
    } else {
      // unknown typehash
      return bytes4(0);
    }

    // extract the typed data params from the _signature blob, ie everything after the first 65 bytes
    bytes memory typedData = _signature[65:];

    // check that _hash can be recreated from the extracted data
    if (_hash != _recreateTypedHash(typehashSource, typedData)) {
      return bytes4(0);
    }
    // check that the signer is valid and return the ERC1271 magic value if so
    if (_isValidSigner(typehash, signer)) {
      return ERC1271_MAGICVALUE;
    } else {
      return bytes4(0);
    }
  }

  /*//////////////////////////////////////////////////////////////
                          VERIFICATION HELPERS
  //////////////////////////////////////////////////////////////*/

  /// @dev Check whether `_signer` is authorized by this contract for the given `_typehash` action
  function _isValidSigner(bytes32 _typehash, address _signer) internal view virtual returns (bool) { }

  /// @dev Recreate a typed hash from the provided `_typedData` using the provided `_typehashSource`
  function _recreateTypedHash(address _typehashSource, bytes memory _typedData) internal view returns (bytes32) {
    return EIP712Like(_typehashSource).hashTypedDataV4(keccak256(_typedData));
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
}
