// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { console2 } from "forge-std/Test.sol"; // remove before deploy
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
   * @dev Thrown when a function is called by an address that is not the recovery address for the fid that this
   * contract owns.
   */
  error NotRecovery();

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

  bytes32 public constant ADD_TYPEHASH = keccak256(
    "Add(address owner,uint32 keyType,bytes key,uint8 metadataType,bytes metadata,uint256 nonce,uint256 deadline)"
  );

  bytes32 public constant REMOVE_TYPEHASH = keccak256("Remove(address owner,bytes key,uint256 nonce,uint256 deadline)");

  bytes32 public constant TRANSFER_TYPEHASH =
    keccak256("Transfer(uint256 fid,address to,uint256 nonce,uint256 deadline)");

  bytes32 public constant CHANGE_RECOVERY_ADDRESS_TYPEHASH =
    keccak256("ChangeRecoveryAddress(uint256 fid,address recovery,uint256 nonce,uint256 deadline)");

  bytes4 public constant ERC1271_MAGICVALUE = IERC1271.isValidSignature.selector;

  bytes4 public constant ERC1271_INVALID_SIGNATURE = bytes4(0);

  /*//////////////////////////////////////////////////////////////
                            MUTABLE STATE
  //////////////////////////////////////////////////////////////*/

  mapping(uint256 fid => bool receivable) public receivable;

  /*//////////////////////////////////////////////////////////////
                                VIEWS
  //////////////////////////////////////////////////////////////*/

  /// @notice The address of the Farcaster Id Registry
  function idRegistry() public view virtual returns (IIdRegistry) { }

  /// @notice The address of the Farcaster Id Registry
  function keyRegistry() public view virtual returns (IKeyRegistry) { }

  /*//////////////////////////////////////////////////////////////
                        FARCASTER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// See {IIdRegistry.register}
  function register(address _recovery) public returns (uint256 fid) {
    fid = idRegistry().register(_recovery);
  }

  /// See {IKeydRegistry.add}
  function addKey(uint32 _keyType, bytes calldata _key, uint8 _metadataType, bytes calldata _metadata) public {
    _auth();
    keyRegistry().add(_keyType, _key, _metadataType, _metadata);
  }

  /// See {IKeyRegistry.remove}
  function removeKey(bytes calldata _key) public {
    _auth();
    keyRegistry().remove(_key);
  }

  /// See {IIdRegistry.transfer}
  function transferFid(address _to, uint256 _deadline, bytes calldata _sig) public {
    _auth();
    idRegistry().transfer(_to, _deadline, _sig);
  }

  /// See {IIdRegistry.changeRecoveryAddress}
  function changeRecoveryAddress(address _newRecovery) public {
    _auth();
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
    _prepareToReceive(_fid);

    emit ReadyToReceive(_fid);
  }

  /// @dev Establishes the state that will allow this contract to produce a valid ERC1271 signature required to
  function _prepareToReceive(uint256 _fid) internal virtual {
    receivable[_fid] = true;
  }

  /*//////////////////////////////////////////////////////////////
                        SIGNER VERIFICATION
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc IERC1271
  function isValidSignature(bytes32 _hash, bytes calldata _signature) public view override returns (bytes4) {
    // extract the signature from the _signature blob, ie the first 65 bytes
    bytes memory sig = _signature[0:65];

    /// @dev ECDSA.recover() will revert with `InvalidSignature()` if the sig is cryptographically invalid
    address signer = ECDSA.recover(_hash, sig);

    // extract the typehash from the 32 bytes after the sig, ie the 65th to 97th bytes of the _signature blob
    bytes32 typehash = bytes32(_signature[65:97]);

    address registry;

    if (typehash == ADD_TYPEHASH || typehash == REMOVE_TYPEHASH) {
      // typehash is from keyRegistry
      registry = address(keyRegistry());
    } else if (typehash == TRANSFER_TYPEHASH || typehash == CHANGE_RECOVERY_ADDRESS_TYPEHASH) {
      // typehash is from idRegistry
      registry = address(idRegistry());
    } else {
      // unknown typehash
      return ERC1271_INVALID_SIGNATURE;
    }

    // extract the typed data params from the _signature blob, ie everything after the first 65 bytes
    bytes memory data = _signature[65:];

    // check that _hash can be recreated from the extracted data
    if (_hash != _buildDigest(registry, data)) {
      console2.log("hash mismatch");
      return ERC1271_INVALID_SIGNATURE;
    }
    // check that the signer is valid and return the ERC1271 magic value if so
    if (_isValidSigner(typehash, signer)) {
      return ERC1271_MAGICVALUE;
    } else {
      return ERC1271_INVALID_SIGNATURE;
    }
  }

  /// @dev Check whether `_signer` is authorized by this contract for the given `_typehash` action
  function _isValidSigner(bytes32 _typehash, address _signer) internal view virtual returns (bool) { }

  function _buildDigest(address _registry, bytes memory _data) internal view returns (bytes32) {
    return EIP712Like(_registry).hashTypedDataV4(keccak256(_data));
  }

  /*//////////////////////////////////////////////////////////////
                            ACCESS CONTROL
  //////////////////////////////////////////////////////////////*/

  /// @dev Check that the caller is the recovery address for the fid that this contract owns
  function _checkRecovery() internal view {
    if (msg.sender != idRegistry().recoveryOf(idRegistry().idOf(address(this)))) {
      revert NotRecovery();
    }
  }

  /// @dev Check authorization on relevant functions. Override to change authoriization logic
  /// Default is the recovery address for the fid that this contract owns
  function _auth() internal virtual {
    _checkRecovery();
  }

  /*//////////////////////////////////////////////////////////////
                         INTERFACE DETECTION
  //////////////////////////////////////////////////////////////*/

  function supportsInterface(bytes4 _interfaceId) public pure returns (bool) {
    return _interfaceId == type(IERC1271).interfaceId;
  }
}
