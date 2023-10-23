// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import { Test, console2 } from "forge-std/Test.sol";
import { IIdRegistry } from "farcaster/interfaces/IIdRegistry.sol";
import { IKeyRegistry } from "farcaster/interfaces/IKeyRegistry.sol";
import { IdRegistry } from "farcaster/IdRegistry.sol";
import { KeyRegistry } from "farcaster/KeyRegistry.sol";
import { SignedKeyRequestValidator } from "farcaster/validators/SignedKeyRequestValidator.sol";
import { IERC1271 } from "../src/interfaces/IERC1271.sol";

contract Base is Test {
  uint256 public fid;
  IIdRegistry public idRegistry_;
  IKeyRegistry public keyRegistry_;
  IdRegistry public idRegistry;
  KeyRegistry public keyRegistry;
  address public signedKeyRequestValidator;

  // FarcasterDelegator errors
  error Unauthorized();
  error AlreadyRegistered();

  // FarcasterDelegator events
  event ReadyToReceive(uint256 fid);

  // Farcaster TYPEHASHES

  bytes32 public REGISTER;
  bytes32 public ADD;
  bytes32 public REMOVE;
  bytes32 public TRANSFER;
  bytes32 public CHANGE_RECOVERY_ADDRESS;
  bytes32 public SIGNED_KEY_REQUEST;

  /*//////////////////////////////////////////////////////////////
                              ADD KEY
  //////////////////////////////////////////////////////////////*/

  function _encodeAddKeyData(
    address _owner,
    uint32 _keyType,
    bytes memory _key,
    uint8 _metadataType,
    bytes memory _metadata,
    uint256 _nonce,
    uint256 _deadline
  ) internal view returns (bytes memory) {
    return abi.encode(
      keyRegistry.ADD_TYPEHASH(), // 32
      _owner, // 64
      _keyType, // 96
      keccak256(_key), // 128
      _metadataType, // 136
      keccak256(_metadata),
      _nonce,
      _deadline
    );
  }

  function _buildKeyRegistryDigest(bytes memory _data) internal view returns (bytes32) {
    return keyRegistry.hashTypedDataV4(keccak256(_data));
  }

  /// @dev modified from
  /// https://github.com/farcasterxyz/contracts/blob/74784dc6a976be72e9a234df294627f953ac9776/test/KeyRegistry/KeyRegistryTestSuite.sol#L36
  function _signAddKey(
    uint256 _pk,
    address _owner,
    uint32 _keyType,
    bytes memory _key,
    uint8 _metadataType,
    bytes memory _metadata,
    uint256 _nonce,
    uint256 _deadline
  ) internal returns (bytes memory _signature) {
    // encode the data
    bytes memory data = _encodeAddKeyData(_owner, _keyType, _key, _metadataType, _metadata, _nonce, _deadline);

    // build the digest
    bytes32 digest = _buildKeyRegistryDigest(data);

    // sign it to generate the preliminary signature
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, digest);
    _signature = abi.encodePacked(r, s, v);

    // assert that the preliminary signature is the correct length
    assertEq(_signature.length, 65);

    // append the encoded data to the signature
    _signature = abi.encodePacked(_signature, data);
  }

  function _encodeSignedKeyRequestData(
    SignedKeyRequestValidator _validator,
    uint256 _fid,
    bytes memory _key,
    uint256 _deadline
  ) internal view returns (bytes memory) {
    return abi.encode(_validator.METADATA_TYPEHASH(), _fid, keccak256(_key), _deadline);
  }

  function _signKeyRequest(
    SignedKeyRequestValidator _validator,
    uint256 _fid,
    uint256 _pk,
    bytes memory _key,
    uint256 _deadline
  ) internal returns (bytes memory) {
    // encode the data
    bytes memory data = _encodeSignedKeyRequestData(_validator, _fid, _key, _deadline);

    // build the digest
    bytes32 digest = _validator.hashTypedDataV4(keccak256(data));

    // sign it to generate the preliminary signature
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, digest);
    bytes memory signature = abi.encodePacked(r, s, v);

    // assert that the preliminary signature is the correct length
    assertEq(signature.length, 65);

    // append the encoded data to the signature
    return abi.encodePacked(signature, data);
  }

  function _buildSignedKeyRequestMetadata(
    address _validator,
    uint256 _fid,
    uint256 _pk,
    address _owner,
    bytes memory _key,
    uint256 _deadline
  ) internal returns (bytes memory) {
    bytes memory signature = _signKeyRequest(SignedKeyRequestValidator(_validator), _fid, _pk, _key, _deadline);

    return abi.encode(
      SignedKeyRequestValidator.SignedKeyRequestMetadata({
        requestFid: _fid,
        requestSigner: _owner,
        signature: signature,
        deadline: _deadline
      })
    );
  }

  /*//////////////////////////////////////////////////////////////
                            REMOVE KEY
  //////////////////////////////////////////////////////////////*/

  function _encodeRemoveKeyData(address _owner, bytes memory _key, uint256 _deadline)
    internal
    view
    returns (bytes memory)
  {
    return abi.encode(keyRegistry.REMOVE_TYPEHASH(), _owner, keccak256(_key), keyRegistry.nonces(_owner), _deadline);
  }

  function _signRemoveKey(uint256 _pk, address _owner, bytes memory _key, uint256 _deadline)
    internal
    returns (bytes memory signature)
  {
    bytes memory data = _encodeRemoveKeyData(_owner, _key, _deadline);
    bytes32 digest = _buildKeyRegistryDigest(data);

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, digest);
    signature = abi.encodePacked(r, s, v);
    assertEq(signature.length, 65);

    signature = abi.encodePacked(signature, data);
  }

  /*//////////////////////////////////////////////////////////////
                        TRANSFER AND RECEIVE
  //////////////////////////////////////////////////////////////*/

  function _encodeTransferData(uint256 _fid, address _to, uint256 _deadline, address _signer)
    internal
    view
    returns (bytes memory)
  {
    return abi.encode(idRegistry.TRANSFER_TYPEHASH(), _fid, _to, idRegistry.nonces(_signer), _deadline);
  }

  function _buildIdRegistryDigest(bytes memory _data) internal view returns (bytes32) {
    return idRegistry.hashTypedDataV4(keccak256(_data));
  }

  function _signTransfer(uint256 _pk, uint256 _fid, address _to, uint256 _deadline, address _signer)
    internal
    returns (bytes memory _signature)
  {
    // encode the data
    bytes memory data = _encodeTransferData(_fid, _to, _deadline, _signer);

    // build the digest
    bytes32 digest = _buildIdRegistryDigest(data);

    // sign it to generate the preliminary signature
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, digest);
    _signature = abi.encodePacked(r, s, v);

    // assert that the preliminary signature is the correct length
    assertEq(_signature.length, 65);

    // append the encoded data to the signature
    _signature = abi.encodePacked(_signature, data);
  }

  function _signReceive(uint256 _pk, uint256 _fid, address _to, uint256 _deadline)
    internal
    returns (bytes memory _signature)
  {
    return _signTransfer(_pk, _fid, _to, _deadline, _to);
  }

  /// @dev Sign a transfer approval message without appending the encoded data to the signature. Useful for testing
  /// transfering from FarcasterDelegator.
  function _signReceiveEOA(uint256 _pk, uint256 _fid, address _to, uint256 _deadline)
    internal
    returns (bytes memory _signature)
  {
    // encode the data
    bytes memory data = _encodeTransferData(_fid, _to, _deadline, _to);

    // build the digest
    bytes32 digest = _buildIdRegistryDigest(data);

    // sign it to generate the signature
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, digest);
    _signature = abi.encodePacked(r, s, v);

    // assert that the preliminary signature is the correct length
    assertEq(_signature.length, 65);
  }

  /*//////////////////////////////////////////////////////////////
                      CHANGE RECOVERY ADDRESS
  //////////////////////////////////////////////////////////////*/

  function _encodeChangeRecoveryAddressData(uint256 _fid, address _recovery, address _owner, uint256 _deadline)
    internal
    view
    returns (bytes memory)
  {
    return
      abi.encode(idRegistry.CHANGE_RECOVERY_ADDRESS_TYPEHASH(), _fid, _recovery, idRegistry.nonces(_owner), _deadline);
  }

  function _signChangeRecoveryAddress(uint256 _pk, uint256 _fid, address _recovery, address _owner, uint256 _deadline)
    internal
    returns (bytes memory signature)
  {
    bytes memory data = _encodeChangeRecoveryAddressData(_fid, _recovery, _owner, _deadline);

    bytes32 digest = _buildIdRegistryDigest(data);

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, digest);
    signature = abi.encodePacked(r, s, v);
    assertEq(signature.length, 65);

    signature = abi.encodePacked(signature, data);
  }

  /*//////////////////////////////////////////////////////////////
                        CUSTOM ASSERTIONS
  //////////////////////////////////////////////////////////////*/

  /// @dev from
  /// https://github.com/farcasterxyz/contracts/blob/74784dc6a976be72e9a234df294627f953ac9776/test/KeyRegistry/KeyRegistry.t.sol#L1279
  function assertEq(IKeyRegistry.KeyState a, IKeyRegistry.KeyState b) internal {
    assertEq(uint8(a), uint8(b));
  }

  function assertAdded(uint256 _fid, bytes memory _key, uint32 _keyType) internal {
    assertEq(keyRegistry.keyDataOf(_fid, _key).state, IKeyRegistry.KeyState.ADDED);
    assertEq(keyRegistry.keyDataOf(_fid, _key).keyType, _keyType);
  }
}

contract ForkTest is Base {
  uint256 public fork;
  uint256 public BLOCK_NUMBER = 110_694_600; // after idRegistry was taken out of trusted mode

  bytes public signature;
  uint256 public deadline;

  uint32 public keyType = 1;
  bytes public key = abi.encode(keccak256("key"));
  uint8 public metadataType = 1;
  bytes public metadata;

  function setUp() public virtual {
    // create and activate a fork, at BLOCK_NUMBER
    fork = vm.createSelectFork(vm.rpcUrl("optimism"), BLOCK_NUMBER);

    idRegistry_ = IIdRegistry(0x00000000FcAf86937e41bA038B4fA40BAA4B780A);
    keyRegistry_ = IKeyRegistry(0x00000000fC9e66f1c6d86D750B4af47fF0Cc343d);
    idRegistry = IdRegistry(address(idRegistry_));
    keyRegistry = KeyRegistry(address(keyRegistry_));
    signedKeyRequestValidator = 0x00000000FC700472606ED4fA22623Acf62c60553;

    REGISTER = idRegistry.REGISTER_TYPEHASH();
    ADD = keyRegistry.ADD_TYPEHASH();
    REMOVE = keyRegistry.REMOVE_TYPEHASH();
    TRANSFER = idRegistry.TRANSFER_TYPEHASH();
    CHANGE_RECOVERY_ADDRESS = idRegistry.CHANGE_RECOVERY_ADDRESS_TYPEHASH();
    SIGNED_KEY_REQUEST = SignedKeyRequestValidator(signedKeyRequestValidator).METADATA_TYPEHASH();
  }
}
