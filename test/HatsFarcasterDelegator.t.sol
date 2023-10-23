// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import { Test, console2 } from "forge-std/Test.sol";
import { ForkTest } from "./Base.t.sol";
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

/* solhint-disable state-visibility */

contract ModuleTest is Deploy, ForkTest {
  /// @dev variables inherited from Deploy script
  // HatsFarcasterDelegator public implementation;
  // bytes32 public SALT;

  /// @dev variables inherited from ForkTest
  // address public recovery = makeAddr("recovery");
  // uint256 public fid;
  // IIdRegistry public idRegistry = IIdRegistry(0x00000000FcAf86937e41bA038B4fA40BAA4B780A);
  // IKeyRegistry public keyRegistry_ = IKeyRegistry(0x00000000fC9e66f1c6d86D750B4af47fF0Cc343d);
  // KeyRegistry public keyRegistry = KeyRegistry(address(keyRegistry_));
  // address public signedKeyRequestValidator = 0x00000000FC700472606ED4fA22623Acf62c60553;
  // uint256 public fork;
  // uint256 public BLOCK_NUMBER = 110_694_600; // after idRegistry was taked out of trusted mode

  IHats public HATS = IHats(0x3bc1A0Ad72417f2d411118085256fC53CBdDd137); // v1.hatsprotocol.eth
  HatsModuleFactory public factory = HatsModuleFactory(0xfE661c01891172046feE16D3a57c3Cf456729efA);
  HatsFarcasterDelegator public instance;
  bytes public otherImmutableArgs;
  bytes public initArgs;

  uint256 public tophat;
  uint256 public casterHat;
  uint256 public adminHat;

  address public org = makeAddr("org");
  address public caster1;
  address public caster2;
  address public admin;
  address public nonWearer;
  uint256 public caster1Key;
  uint256 public caster2Key;
  uint256 public adminKey;
  uint256 public nonWearerKey;
  address public eligibility = makeAddr("eligibility");
  address public toggle = makeAddr("toggle");

  string public MODULE_VERSION;

  bytes32 public digest;
  address public owner;
  uint256 public nonce;

  bytes public sig;
  uint8 public v;
  bytes32 public r;
  bytes32 public s;
  bytes4 public constant ERC1271_MAGICVALUE = 0x1626ba7e; // bytes4(keccak256("isValidSignature(bytes32,bytes)")

  function setUp() public virtual override {
    super.setUp();

    (caster1, caster1Key) = makeAddrAndKey("caster1");
    (caster2, caster2Key) = makeAddrAndKey("caster2");
    (admin, adminKey) = makeAddrAndKey("admin");
    (nonWearer, nonWearerKey) = makeAddrAndKey("nonWearer");

    // create and activate a fork, at BLOCK_NUMBER
    fork = vm.createSelectFork(vm.rpcUrl("optimism"), BLOCK_NUMBER);

    // deploy implementation via the script
    prepare(false, MODULE_VERSION);
    run();

    // set the Farcaster typehashes
    // ADD = keyRegistry.ADD_TYPEHASH();
    // REMOVE = keyRegistry.REMOVE_TYPEHASH();
    // TRANSFER = idRegistry.TRANSFER_TYPEHASH();
    // CHANGE_RECOVERY_ADDRESS = idRegistry.CHANGE_RECOVERY_ADDRESS_TYPEHASH();
  }
}

contract WithInstanceTest is ModuleTest {
  function setUp() public virtual override {
    super.setUp();

    // set up the hats
    tophat = HATS.mintTopHat(address(this), "org", "tophat.org/image");
    casterHat = HATS.createHat(tophat, "caster hat", 2, eligibility, toggle, true, "casterhat.tophat.org/image");
    adminHat = HATS.createHat(tophat, "admin hat", 1, eligibility, toggle, true, "adminhat.tophat.org/image");
    HATS.mintHat(casterHat, caster1);
    HATS.mintHat(casterHat, caster2);
    HATS.mintHat(adminHat, admin);
    HATS.transferHat(tophat, address(this), org);

    // set up the other immutable args
    otherImmutableArgs =
      abi.encodePacked(adminHat, address(idRegistry), address(keyRegistry), signedKeyRequestValidator);

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

  function test_removeKey_valid() public {
    assertTrue(instance.isValidSigner(REMOVE, admin));
  }

  function test_removeKey_invalid() public {
    assertFalse(instance.isValidSigner(REMOVE, nonWearer));
  }

  function test_transfer_valid() public {
    assertTrue(instance.isValidSigner(TRANSFER, admin));
  }

  function test_transfer_invalid() public {
    assertFalse(instance.isValidSigner(TRANSFER, nonWearer));
  }

  function test_changeRecoveryAddress_valid() public {
    assertTrue(instance.isValidSigner(CHANGE_RECOVERY_ADDRESS, admin));
  }

  function test_changeRecoveryAddress_invalid() public {
    assertFalse(instance.isValidSigner(CHANGE_RECOVERY_ADDRESS, nonWearer));
  }

  function test_signKeyRequest_valid() public {
    assertTrue(instance.isValidSigner(SIGNED_KEY_REQUEST, caster1));
    assertTrue(instance.isValidSigner(SIGNED_KEY_REQUEST, caster2));
  }

  function test_signKeyRequest_invalid() public {
    assertFalse(instance.isValidSigner(SIGNED_KEY_REQUEST, nonWearer));
  }
}

contract Register is WithInstanceTest {
  function test_isOrg() public {
    vm.prank(admin);
    fid = instance.register(org);

    assertEq(fid, idRegistry.idOf(address(instance)));
  }
}

contract IsValidSignature_AddKey is WithInstanceTest {
  bytes public addKeyData;

  function test_valid_hatId_addKey() public {
    // set up dummy add key data
    owner = address(1234);
    keyType = 1;
    metadataType = 1;
    metadata = abi.encode("metadata");
    nonce = 1;
    deadline = 1;

    // encode add key data
    addKeyData = _encodeAddKeyData(owner, keyType, key, metadataType, metadata, nonce, deadline);

    // prepare the digest
    digest = _buildKeyRegistryDigest(addKeyData);

    // sign it, appending the encoded data to the signature
    sig = _signAddKey(caster1Key, owner, keyType, key, metadataType, metadata, nonce, deadline);

    assertEq(instance.isValidSignature(digest, sig), ERC1271_MAGICVALUE);
  }

  function test_valid_adminHat_addKey() public {
    // set up dummy add key data
    owner = address(1234);
    keyType = 1;
    metadataType = 1;
    metadata = abi.encode("metadata");
    nonce = 1;
    deadline = 1;

    // encode add key data
    addKeyData = _encodeAddKeyData(owner, keyType, key, metadataType, metadata, nonce, deadline);

    // prepare the digest
    digest = _buildKeyRegistryDigest(addKeyData);

    // sign it, appending the encoded data to the signature
    sig = _signAddKey(adminKey, owner, keyType, key, metadataType, metadata, nonce, deadline);

    assertEq(instance.isValidSignature(digest, sig), ERC1271_MAGICVALUE);
  }

  function test_invalid_nonWearer_addKey() public {
    // set up dummy add key data
    owner = address(1234);
    keyType = 1;
    metadataType = 1;
    metadata = abi.encode("metadata");
    nonce = 1;
    deadline = 1;

    // encode add key data
    addKeyData = _encodeAddKeyData(owner, keyType, key, metadataType, metadata, nonce, deadline);

    // prepare the digest
    digest = _buildKeyRegistryDigest(addKeyData);

    // sign it, appending the encoded data to the signature
    sig = _signAddKey(nonWearerKey, owner, keyType, key, metadataType, metadata, nonce, deadline);

    assertEq(instance.isValidSignature(digest, sig), bytes4(0));
  }
}

contract IsValidSignature_SignedKeyRequest is WithInstanceTest {
  bytes public signedKeyRequestData;
  SignedKeyRequestValidator public validator;

  function setUp() public override {
    super.setUp();

    // set up the validator
    validator = SignedKeyRequestValidator(signedKeyRequestValidator);
  }

  function test_valid_adminHat_signedKeyRequest() public {
    // set up dummy signed key request data
    owner = address(1234);
    deadline = 1;

    // encode signed key request data
    signedKeyRequestData = _encodeSignedKeyRequestData(validator, fid, key, deadline);

    // prepare the digest
    digest = validator.hashTypedDataV4(keccak256(signedKeyRequestData));

    // sign it, appending the encoded data to the signature
    sig = _signKeyRequest(validator, fid, adminKey, key, deadline);

    // assert that the signature is valid
    assertEq(instance.isValidSignature(digest, sig), ERC1271_MAGICVALUE);
  }

  function test_valid_hatId_signedKeyRequest() public {
    // set up dummy signed key request data
    owner = address(1234);
    deadline = 1;

    // encode signed key request data
    signedKeyRequestData = _encodeSignedKeyRequestData(validator, fid, key, deadline);

    // prepare the digest
    digest = validator.hashTypedDataV4(keccak256(signedKeyRequestData));

    // sign it, appending the encoded data to the signature
    sig = _signKeyRequest(validator, fid, caster1Key, key, deadline);

    // assert that the signature is valid
    assertEq(instance.isValidSignature(digest, sig), ERC1271_MAGICVALUE);
  }

  function test_invalid_nonWearer_signedKeyRequest() public {
    // set up dummy signed key request data
    owner = address(1234);
    deadline = 1;

    // encode signed key request data
    signedKeyRequestData = _encodeSignedKeyRequestData(validator, fid, key, deadline);

    // prepare the digest
    digest = validator.hashTypedDataV4(keccak256(signedKeyRequestData));

    // sign it, appending the encoded data to the signature
    sig = _signKeyRequest(validator, fid, nonWearerKey, key, deadline);

    // assert that the signature is invalid
    assertEq(instance.isValidSignature(digest, sig), bytes4(0));
  }
}

contract IsValidSignature_RemoveKey is WithInstanceTest {
  bytes public removeKeyData;

  function test_valid_adminHat_removeKey() public {
    // set up dummy remove key data
    owner = address(1234);
    deadline = 1;

    // encode remove key data
    removeKeyData = _encodeRemoveKeyData(owner, key, deadline);

    // prepare the digest
    digest = _buildKeyRegistryDigest(removeKeyData);

    // sign it, appending the encoded data to the signature
    sig = _signRemoveKey(adminKey, owner, key, deadline);

    // assert that the signature is valid
    assertEq(instance.isValidSignature(digest, sig), ERC1271_MAGICVALUE);
  }

  function test_invalid_nonAdmin_removeKey() public {
    // set up dummy remove key data
    owner = address(1234);
    deadline = 1;

    // encode remove key data
    removeKeyData = _encodeRemoveKeyData(owner, key, deadline);

    // prepare the digest
    digest = _buildKeyRegistryDigest(removeKeyData);

    // sign it, appending the encoded data to the signature
    sig = _signRemoveKey(nonWearerKey, owner, key, deadline);

    // assert that the signature is invalid
    assertEq(instance.isValidSignature(digest, sig), bytes4(0));
  }
}

contract IsValidSignature_Transfer is WithInstanceTest {
  bytes public transferData;
  address public recipient = makeAddr("recipient");

  function test_valid_adminHat_transfer() public {
    // set up dummy transfer data
    owner = address(1234);
    deadline = 1;

    // encode transfer data
    transferData = _encodeTransferData(fid, recipient, deadline, owner);

    // prepare the digest
    digest = _buildIdRegistryDigest(transferData);

    // sign it, appending the encoded data to the signature
    sig = _signTransfer(adminKey, fid, recipient, deadline, owner);

    // assert that the signature is valid
    assertEq(instance.isValidSignature(digest, sig), ERC1271_MAGICVALUE);
  }

  function test_invalid_nonWearer_transfer() public {
    // set up dummy transfer data
    owner = address(1234);
    deadline = 1;

    // encode transfer data
    transferData = _encodeTransferData(fid, recipient, deadline, owner);

    // prepare the digest
    digest = _buildIdRegistryDigest(transferData);

    // sign it, appending the encoded data to the signature
    sig = _signTransfer(nonWearerKey, fid, recipient, deadline, owner);

    // assert that the signature is invalid
    assertEq(instance.isValidSignature(digest, sig), bytes4(0));
  }
}

contract IsValidSignature_ChangeRecoveryAddress is WithInstanceTest {
  bytes public changeRecoveryAddressData;
  address public newRecovery = makeAddr("newRecovery");

  function test_valid_adminHat_changeRecoveryAddress() public {
    // set up dummy change recovery address data
    owner = address(1234);
    deadline = 1;

    // encode change recovery address data
    changeRecoveryAddressData = _encodeChangeRecoveryAddressData(fid, newRecovery, owner, deadline);

    // prepare the digest
    digest = _buildIdRegistryDigest(changeRecoveryAddressData);

    // sign it, appending the encoded data to the signature
    sig = _signChangeRecoveryAddress(adminKey, fid, newRecovery, owner, deadline);

    // assert that the signature is valid
    assertEq(instance.isValidSignature(digest, sig), ERC1271_MAGICVALUE);
  }

  function test_invalid_nonWearer_changeRecoveryAddress() public {
    // set up dummy change recovery address data
    owner = address(1234);
    deadline = 1;

    // encode change recovery address data
    changeRecoveryAddressData = _encodeChangeRecoveryAddressData(fid, newRecovery, owner, deadline);

    // prepare the digest
    digest = _buildIdRegistryDigest(changeRecoveryAddressData);

    // sign it, appending the encoded data to the signature
    sig = _signChangeRecoveryAddress(nonWearerKey, fid, newRecovery, owner, deadline);

    // assert that the signature is invalid
    assertEq(instance.isValidSignature(digest, sig), bytes4(0));
  }
}

contract AddCasterKeyViaClient is WithInstanceTest {
  address public client = makeAddr("client");
  bytes public addKeySig;
  bytes public addRequestSig;

  function test_happy() public {
    // admin registers a new fid via its HatsFarcasterDelegator instance
    vm.prank(admin);
    fid = instance.register(org);

    // client generates a key for caster1
    key;

    // client prepares the parameters for the addFor method call
    keyType = 1;
    deadline = block.timestamp + 1 days;
    metadataType = 1; // SignedKeyRequestMetadata
    metadata =
      _buildSignedKeyRequestMetadata(signedKeyRequestValidator, fid, caster1Key, address(instance), key, deadline);

    // caster signs the digest and appends the encoded typed data to the signature
    addKeySig = _signAddKey(
      caster1Key,
      address(instance),
      keyType,
      key,
      metadataType,
      metadata,
      keyRegistry.nonces(address(instance)),
      deadline
    );

    // client calls addFor with the signature
    vm.prank(client);
    keyRegistry.addFor(address(instance), keyType, key, metadataType, metadata, deadline, addKeySig);

    // internally, keyRegistry attempts to validate the signature, which results in an isValidSignature call to our
    // instance

    // assert that caster1's key was added
    assertAdded(fid, key, keyType);
  }
}
