// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import { Test, console2 } from "forge-std/Test.sol";
// import { Wallet } from "forge-std/Vm.sol";
import { FDTest } from "./FarcasterDelegator.t.sol";
import { HatsFarcasterDelegator } from "../src/HatsFarcasterDelegator.sol";
import { Deploy } from "../script/HatsFarcasterDelegator.s.sol";
import {
  HatsModuleFactory, IHats, deployModuleInstance, deployModuleFactory
} from "hats-module/utils/DeployFunctions.sol";
import { IHats } from "hats-protocol/Interfaces/IHats.sol";
import { IKeyRegistry } from "farcaster/interfaces/IKeyRegistry.sol";
import { IIdRegistry } from "farcaster/interfaces/IIdRegistry.sol";
import { KeyRegistry } from "farcaster/KeyRegistry.sol";
import { SignedKeyRequestValidator } from "farcaster/validators/SignedKeyRequestValidator.sol";
import { EIP712 } from "solady/utils/EIP712.sol";

struct Wallet {
  address addr;
  uint256 publicKeyX;
  uint256 publicKeyY;
  uint256 privateKey;
}

contract ModuleTest is Deploy, FDTest {
  /// @dev variables inherited from Deploy script
  // HatsFarcasterDelegator public implementation;
  // bytes32 public SALT;

  /// @dev variables inherited from FDTest
  // address public recovery = makeAddr("recovery");
  // uint256 public fid;
  // IIdRegistry public idRegistry = IIdRegistry(0x00000000FcAf86937e41bA038B4fA40BAA4B780A);
  // address public trustedCaller;
  // uint256 public fork;
  // uint256 public BLOCK_NUMBER = 110_694_600; // after idRegistry was taked out of trusted mode

  IHats public HATS = IHats(0x3bc1A0Ad72417f2d411118085256fC53CBdDd137); // v1.hatsprotocol.eth
  HatsModuleFactory public factory;
  HatsFarcasterDelegator public instance;
  bytes public otherImmutableArgs;
  bytes public initArgs;

  KeyRegistry public keyRegistry = KeyRegistry(0x00000000fC9e66f1c6d86D750B4af47fF0Cc343d);
  SignedKeyRequestValidator public signedKeyRequestValidator =
    SignedKeyRequestValidator(0x00000000FC700472606ED4fA22623Acf62c60553);

  uint256 public tophat;
  uint256 public casterHat;

  address public org = makeAddr("org");
  address public caster1;
  address public caster2;
  address public nonWearer;
  uint256 public caster1Key;
  uint256 public caster2Key;
  uint256 public nonWearerKey;
  address public eligibility = makeAddr("eligibility");
  address public toggle = makeAddr("toggle");

  string public MODULE_VERSION;

  bytes32 public ADD;
  bytes32 public REMOVE;
  bytes32 public TRANSFER;
  bytes32 public CHANGE_RECOVERY_ADDRESS;

  bytes public sig;
  uint8 public v;
  bytes32 public r;
  bytes32 public s;
  bytes4 public constant ERC1271_MAGICVALUE = 0x1626ba7e; // bytes4(keccak256("isValidSignature(bytes32,bytes)")

  function setUp() public virtual override {
    (caster1, caster1Key) = makeAddrAndKey("caster1");
    (caster2, caster2Key) = makeAddrAndKey("caster2");
    (nonWearer, nonWearerKey) = makeAddrAndKey("nonWearer");

    // create and activate a fork, at BLOCK_NUMBER
    fork = vm.createSelectFork(vm.rpcUrl("optimism"), BLOCK_NUMBER);

    // deploy implementation via the script
    prepare(false, MODULE_VERSION);
    run();

    // deploy the hats module factory
    factory = deployModuleFactory(HATS, SALT, "test factory");

    // set the Farcaster typehashes
    ADD = keyRegistry.ADD_TYPEHASH();
    REMOVE = keyRegistry.REMOVE_TYPEHASH();
    TRANSFER = idRegistry.TRANSFER_TYPEHASH();
    CHANGE_RECOVERY_ADDRESS = idRegistry.CHANGE_RECOVERY_ADDRESS_TYPEHASH();
  }
}

contract WithInstanceTest is ModuleTest {
  function setUp() public virtual override {
    super.setUp();

    // set up the hats
    tophat = HATS.mintTopHat(address(this), "org", "tophat.org/image");
    casterHat = HATS.createHat(tophat, "caster hat", 2, eligibility, toggle, true, "casterhat.tophat.org/image");
    HATS.mintHat(casterHat, caster1);
    HATS.mintHat(casterHat, caster2);
    HATS.transferHat(tophat, address(this), org);

    // set up the other immutable args
    otherImmutableArgs = abi.encodePacked(address(idRegistry), address(keyRegistry), address(signedKeyRequestValidator));

    // set up the instance with an empty recovery address to denote that it should not register a hat for itself
    initArgs = abi.encode(address(0));

    // deploy an instance of the module
    instance = HatsFarcasterDelegator(
      deployModuleInstance(factory, address(implementation), casterHat, otherImmutableArgs, initArgs)
    );
  }
}

contract Deployment is WithInstanceTest {
  /// @dev ensure that both the implementation and instance are properly initialized
  function test_initialization() public {
    // implementation
    vm.expectRevert("Initializable: contract is already initialized");
    implementation.setUp("setUp attempt");
    // instance
    vm.expectRevert("Initializable: contract is already initialized");
    instance.setUp("setUp attempt");
  }

  function test_version() public {
    assertEq(instance.version(), MODULE_VERSION);
  }

  function test_implementation() public {
    assertEq(address(instance.IMPLEMENTATION()), address(implementation));
  }

  function test_hats() public {
    assertEq(address(instance.HATS()), address(HATS));
  }

  function test_hatId() public {
    assertEq(instance.hatId(), casterHat);
  }

  function test_idRegistry() public {
    assertEq(address(instance.idRegistry()), address(idRegistry));
  }
}

contract IsValidSigner is WithInstanceTest {
  function test_addKey_valid() public {
    assertTrue(instance.isValidSigner(ADD, caster1));
    assertTrue(instance.isValidSigner(ADD, caster2));
  }

  function test_addKey_invalid() public {
    assertFalse(instance.isValidSigner(ADD, nonWearer));

    // turn off the caster hat
    vm.prank(toggle);
    HATS.setHatStatus(casterHat, false);

    assertFalse(instance.isValidSigner(ADD, caster1));
    assertFalse(instance.isValidSigner(ADD, caster2));
  }
}

contract WithFarcasterHelpers is WithInstanceTest {
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
    // return keccak256(_data);
  }

  /// @dev modified from
  /// https://github.com/farcasterxyz/contracts/blob/74784dc6a976be72e9a234df294627f953ac9776/test/KeyRegistry/KeyRegistryTestSuite.sol#L36
  function _signAdd(
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
    SignedKeyRequestValidator _validator,
    uint256 _fid,
    uint256 _pk,
    address _owner,
    bytes memory _key,
    uint256 _deadline
  ) internal returns (bytes memory) {
    bytes memory signature = _signKeyRequest(_validator, _fid, _pk, _key, _deadline);

    return abi.encode(
      SignedKeyRequestValidator.SignedKeyRequestMetadata({
        requestFid: _fid,
        requestSigner: _owner,
        signature: signature,
        deadline: _deadline
      })
    );
  }
}

contract IsValidSignature is WithFarcasterHelpers {
  bytes public addKeyData;
  bytes32 public digest;

  address _owner;
  uint32 _keyType;
  bytes _key;
  uint8 _metadataType;
  bytes _metadata;
  uint256 _nonce;
  uint256 _deadline;

  function test_valid() public {
    // set up dummy add key data
    _owner = address(1234);
    _keyType = 1;
    _key = abi.encode("key");
    _metadataType = 1;
    _metadata = abi.encode("metadata");
    _nonce = 1;
    _deadline = 1;

    console2.log("test:keyRegistry", address(keyRegistry));

    // encode add key data
    addKeyData = _encodeAddKeyData(_owner, _keyType, _key, _metadataType, _metadata, _nonce, _deadline);
    console2.log("addKeyData", vm.toString(addKeyData));
    console2.log("test:keccak-ed addKeyData", vm.toString(keccak256(addKeyData)));

    // prepare the digest
    digest = _buildKeyRegistryDigest(addKeyData);
    console2.log("digest", vm.toString(digest));

    // sign it, appending the encoded data to the signature
    sig = _signAdd(caster1Key, _owner, _keyType, _key, _metadataType, _metadata, _nonce, _deadline);
    console2.log("caster1", caster1);

    assertEq(instance.isValidSignature(digest, sig), ERC1271_MAGICVALUE);
  }

  function test_invalid() public {
    // set up dummy add key data
    _owner = address(1234);
    _keyType = 1;
    _key = abi.encode("key");
    _metadataType = 1;
    _metadata = abi.encode("metadata");
    _nonce = 1;
    _deadline = 1;

    // encode add key data
    addKeyData = _encodeAddKeyData(_owner, _keyType, _key, _metadataType, _metadata, _nonce, _deadline);
    console2.log("addKeyData", vm.toString(addKeyData));

    // prepare the digest
    digest = _buildKeyRegistryDigest(addKeyData);
    console2.log("digest", vm.toString(digest));

    // sign it, appending the encoded data to the signature
    sig = _signAdd(nonWearerKey, _owner, _keyType, _key, _metadataType, _metadata, _nonce, _deadline);
    console2.log("nonWearer", nonWearer);

    assertEq(instance.isValidSignature(digest, sig), bytes4(0));
  }
}

contract AddCasterKeyViaClient is WithFarcasterHelpers {
  SignedKeyRequestValidator public validator = SignedKeyRequestValidator(0x00000000FC700472606ED4fA22623Acf62c60553);
  address public client = makeAddr("client");
  bytes public addSig;
  bytes public addRequestSig;

  uint32 public keyType;
  uint8 public metadataType;
  bytes public metadata;
  uint256 public deadline;

  /// @dev from
  /// https://github.com/farcasterxyz/contracts/blob/74784dc6a976be72e9a234df294627f953ac9776/test/KeyRegistry/KeyRegistry.t.sol#L1279
  function assertEq(IKeyRegistry.KeyState a, IKeyRegistry.KeyState b) internal {
    assertEq(uint8(a), uint8(b));
  }

  function assertAdded(uint256 _fid, bytes memory _key, uint32 _keyType) internal {
    assertEq(keyRegistry.keyDataOf(_fid, _key).state, IKeyRegistry.KeyState.ADDED);
    assertEq(keyRegistry.keyDataOf(_fid, _key).keyType, _keyType);
  }

  function test_happy() public {
    // org registers a new fid via its HatsFarcasterDelegator instance
    vm.prank(org);
    fid = instance.register(org);

    // client generates a key for caster1
    bytes memory key = abi.encode(keccak256("key"));

    // client prepares the parameters for the addFor method call
    keyType = 1;
    deadline = block.timestamp + 1 days;
    metadataType = 1; // SignedKeyRequestMetadata
    metadata = _buildSignedKeyRequestMetadata(validator, fid, caster1Key, address(instance), key, deadline);

    // caster signs the digest and appends the encoded typed data to the signature
    addSig = _signAdd(
      caster1Key,
      address(instance),
      keyType,
      key,
      metadataType,
      metadata,
      keyRegistry.nonces(address(instance)),
      deadline
    );

    console2.log("addSig length", addSig.length);

    // client calls addFor with the signature
    vm.prank(client);
    keyRegistry.addFor(address(instance), keyType, key, metadataType, metadata, deadline, addSig);

    // internally, keyRegistry attempts to validate the signature, which results in an isValidSignature call to our
    // instance

    // assert that caster1's key was added
    assertAdded(fid, key, keyType);
  }
}
