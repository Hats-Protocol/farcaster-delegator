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
   * @param _signature Must take the following format to enable the relevant typehash-based routing logic:
   *  - First 65 bytes: the actual signature produced by signing the `_hash`
   *  - Next 32 bytes: the typehash of the Farcaster action being authorized
   *  - Remaining bytes: the EIP712 typed data parameters used to generate the `_hash`, not including the typehash
   *
   * There is a special case for TRANSFER_TYPEHASH when this contract has been prepared to receive a given fid and does
   * not already have one registered to it. In this case, a cryptographic signature is not required, and therefore the
   * first 65 bytes can take any value.
   *
   * @return ERC1271_MAGICVALUE if the signature is valid, or one of the following error selectors if invalid:
   *  - `InvalidTypehash.selector` if the typehash is not recognized
   *  - `InvalidTypedData.selector` if the `_hash` cannot be recreated from the typed data parameters
   *  - `InvalidSigner.selector` if the signer is not authorized for the given typehash
   */
  function isValidSignature(bytes32 _hash, bytes calldata _signature) public view override returns (bytes4) {
    // extract the typehash from 1st word after the sig, ie the 66th to 98th bytes of the _signature blob
    bytes32 typehash = bytes32(_signature[65:97]);
    // allocate memory for the address of the typehash source, to be determined below
    address typehashSource;

    // Determine the source of the typehash, returning the InvalidTypehash error code if it is unknown.
    if (typehash == TRANSFER_TYPEHASH) {
      // TRANSFER_TYPEHASH has additional logic, so we handle it first
      // extract fid from 2nd word after the 65 actual signature bytes, ie bytes 98-130 of the _signature blob
      uint256 fid = abi.decode(_signature[97:129], (uint256));

      if (receivable[fid] && idRegistry().idOf(address(this)) != fid) {
        // this contract does not own fid, and fid has been approved to be received by this contract
        // so this is a valid signature regardless of the value of the first 65 bytes
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

    // extract the typed data params from the _signature blob, ie everything after the first 65 bytes
    bytes memory typedData = _signature[65:];

    // check that _hash can be recreated from the extracted data, using the typehashSource determined above
    if (_hash != _recreateTypedHash(typehashSource, typedData)) {
      return InvalidTypedData.selector;
    }

    /// @dev ECDSA.recover() will revert with `InvalidSignature()` if the sig is cryptographically invalid
    // the actual signature to recover from is the first 65 bytes of the _signature blob
    address signer = ECDSA.recover(_hash, _signature[0:65]);

    // check that the signer is valid for the typehash and return the ERC1271 magic value if so
    if (_isValidSigner(typehash, signer)) {
      return ERC1271_MAGICVALUE;
    } else {
      return InvalidSigner.selector;
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

  /*//////////////////////////////////////////////////////////////
                            FALLBACK
  //////////////////////////////////////////////////////////////*/

  receive() external payable { }
}
