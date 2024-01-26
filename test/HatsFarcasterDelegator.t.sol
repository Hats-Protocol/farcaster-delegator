// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import { Test, console2 } from "forge-std/Test.sol";
import { ForkTest } from "./Base.t.sol";
import { HatsFarcasterDelegator } from "../src/HatsFarcasterDelegator.sol";
import { DeployImplementation, DeployInstance } from "../script/HatsFarcasterDelegator.s.sol";
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

contract ModuleTest is DeployImplementation, ForkTest {
  /// @dev variables inherited from DeployImplementation script
  // HatsFarcasterDelegator public implementation;
  // bytes32 public SALT;

  /// @dev variables inherited from ForkTest
  // address public recovery = makeAddr("recovery");
  // uint256 public fid;
  // idGateway_ = IIdGateway(0x00000000Fc25870C6eD6b6c7E41Fb078b7656f69);
  // idRegistry_ = IIdRegistry(0x00000000Fc6c5F01Fc30151999387Bb99A9f489b);
  // keyGateway_ = IKeyGateway(0x00000000fC56947c7E7183f8Ca4B62398CaAdf0B);
  // keyRegistry_ = IKeyRegistry(0x00000000Fc1237824fb747aBDE0FF18990E59b7e);
  // idGateway = IdGateway(address(idGateway_));
  // idRegistry = IdRegistry(address(idRegistry_));
  // keyGateway = KeyGateway(address(keyGateway_));
  // keyRegistry = KeyRegistry(address(keyRegistry_));
  // signedKeyRequestValidator = 0x00000000FC700472606ED4fA22623Acf62c60553;

  IHats public HATS = IHats(0x3bc1A0Ad72417f2d411118085256fC53CBdDd137); // v1.hatsprotocol.eth
  HatsModuleFactory public factory = HatsModuleFactory(0xfE661c01891172046feE16D3a57c3Cf456729efA);
  HatsFarcasterDelegator public instance;
  bytes public otherImmutableArgs;
  bytes public initArgs;

  uint256 public tophat;
  uint256 public casterHat;
  uint256 public ownerHat;

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
    fork = vm.createSelectFork(vm.rpcUrl("optimism"));

    // deploy implementation via the script
    prepare(false, MODULE_VERSION);
    run();

    // set the Farcaster typehashes
    // ADD = keyGateway.ADD_TYPEHASH();
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
    ownerHat = HATS.createHat(tophat, "admin hat", 1, eligibility, toggle, true, "adminhat.tophat.org/image");
    HATS.mintHat(casterHat, caster1);
    HATS.mintHat(casterHat, caster2);
    HATS.mintHat(ownerHat, admin);
    HATS.transferHat(tophat, address(this), org);

    // deploy and prepare the DeployInstance script
    DeployInstance deployInstance = new DeployInstance();
    deployInstance.prepare(
      false,
      ownerHat,
      casterHat,
      address(implementation),
      address(idGateway),
      address(idRegistry),
      address(keyGateway),
      address(keyRegistry),
      signedKeyRequestValidator
    );

    // run the script to deploy an instance
    instance = HatsFarcasterDelegator(payable(deployInstance.run()));
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
    fid = _registerViaFarcasterDelegator(address(instance), admin, org);

    assertEq(fid, idRegistry.idOf(address(instance)));
  }
}

contract IsValidSignature_InvalidTypehash is WithInstanceTest {
  function test_invalidTypehash() public {
    // sign a digest using the wrong typehash
    (digest, sig) = _signInvalidTypehash(caster1Key);

    assertEq(instance.isValidSignature(digest, sig), InvalidTypehash.selector);
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
    digest = _buildKeyGatewayDigest(addKeyData);

    // sign it, appending the encoded data to the signature
    sig = _signAddKey(caster1Key, owner, keyType, key, metadataType, metadata, nonce, deadline);

    assertEq(instance.isValidSignature(digest, sig), ERC1271_MAGICVALUE);
  }

  function test_valid_ownerHat_addKey() public {
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
    digest = _buildKeyGatewayDigest(addKeyData);

    // sign it, appending the encoded data to the signature
    sig = _signAddKey(adminKey, owner, keyType, key, metadataType, metadata, nonce, deadline);

    assertEq(instance.isValidSignature(digest, sig), ERC1271_MAGICVALUE);
  }

  function test_invalidSigner_nonWearer_addKey() public {
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
    digest = _buildKeyGatewayDigest(addKeyData);

    // sign it, appending the encoded data to the signature
    sig = _signAddKey(nonWearerKey, owner, keyType, key, metadataType, metadata, nonce, deadline);

    assertEq(instance.isValidSignature(digest, sig), InvalidSigner.selector);
  }

  function test_invalidTypedData_wearer_addKey() public {
    // set up dummy add key data
    owner = address(1234);
    keyType = 1;
    metadataType = 1;
    metadata = abi.encode("metadata");
    nonce = 1;
    deadline = 1;

    // encode add key data
    addKeyData = _encodeAddKeyData(owner, keyType, key, metadataType, metadata, nonce, deadline);

    // prepare the digest using the wrong typehash
    digest = _buildKeyRegistryDigest(addKeyData);

    // sign it, appending the encoded data to the signature
    sig = _signAddKey(caster1Key, owner, keyType, key, metadataType, metadata, nonce, deadline);

    assertEq(instance.isValidSignature(digest, sig), InvalidTypedData.selector);
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

  function test_valid_ownerHat_signedKeyRequest() public {
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
    assertEq(instance.isValidSignature(digest, sig), InvalidSigner.selector);
  }

  function test_invalidTypedData_wearer_signedKeyRequest() public {
    // set up dummy signed key request data
    owner = address(1234);
    deadline = 1;

    // encode signed key request data
    signedKeyRequestData = _encodeSignedKeyRequestData(validator, fid, key, deadline);

    // prepare the digest using the wrong typehash
    digest = _buildKeyRegistryDigest(signedKeyRequestData);

    // sign it, appending the encoded data to the signature
    sig = _signKeyRequest(validator, fid, caster1Key, key, deadline);

    // assert that the signature is invalid
    assertEq(instance.isValidSignature(digest, sig), InvalidTypedData.selector);
  }
}

contract IsValidSignature_RemoveKey is WithInstanceTest {
  bytes public removeKeyData;

  function test_valid_ownerHat_removeKey() public {
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
    assertEq(instance.isValidSignature(digest, sig), InvalidSigner.selector);
  }

  function test_invalidTypedData_wearer_removeKey() public {
    // set up dummy remove key data
    owner = address(1234);
    deadline = 1;

    // encode remove key data
    removeKeyData = _encodeRemoveKeyData(owner, key, deadline);

    // prepare the digest using the wrong typehash
    digest = _buildKeyGatewayDigest(removeKeyData);

    // sign it, appending the encoded data to the signature
    sig = _signRemoveKey(adminKey, owner, key, deadline);

    // assert that the signature is invalid
    assertEq(instance.isValidSignature(digest, sig), InvalidTypedData.selector);
  }
}

contract IsValidSignature_Transfer is WithInstanceTest {
  bytes public transferData;
  address public recipient = makeAddr("recipient");

  function test_valid_ownerHat_transfer() public {
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
    assertEq(instance.isValidSignature(digest, sig), InvalidSigner.selector);
  }

  function test_valid_self_preparedToReceive() public {
    // register a new fid to org
    fid = _registerViaGateway(org, org);

    // set transfer data
    owner = org;
    deadline = 1;

    // ownerHat-wearer prepare the instance to receive an fid
    vm.prank(admin);
    instance.prepareToReceive(fid);

    // encode transfer data
    transferData = _encodeTransferData(fid, recipient, deadline, owner);

    // prepare the digest
    digest = _buildIdRegistryDigest(transferData);

    // sign it, appending the encoded data to the signature
    bytes memory emptySig = new bytes(65);
    // sig = _signTransfer(adminKey, fid, recipient, deadline, owner);
    sig = abi.encodePacked(emptySig, transferData);
    console2.logBytes(sig);

    // assert that the signature is valid
    assertEq(instance.isValidSignature(digest, sig), ERC1271_MAGICVALUE);
  }

  function test_invalidTypedData_wearer_transfer() public {
    // set up dummy transfer data
    owner = address(1234);
    deadline = 1;

    // encode transfer data
    transferData = _encodeTransferData(fid, recipient, deadline, owner);

    // prepare the digest using the wrong typehash
    digest = _buildKeyGatewayDigest(transferData);

    // sign it, appending the encoded data to the signature
    sig = _signTransfer(adminKey, fid, recipient, deadline, owner);

    // assert that the signature is invalid
    assertEq(instance.isValidSignature(digest, sig), InvalidTypedData.selector);
  }
}

contract IsValidSignature_ChangeRecoveryAddress is WithInstanceTest {
  bytes public changeRecoveryAddressData;
  address public newRecovery = makeAddr("newRecovery");

  function test_valid_ownerHat_changeRecoveryAddress() public {
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
    assertEq(instance.isValidSignature(digest, sig), InvalidSigner.selector);
  }

  function test_invalidTypedData_wearer_changeRecoveryAddress() public {
    // set up dummy change recovery address data
    owner = address(1234);
    deadline = 1;

    // encode change recovery address data
    changeRecoveryAddressData = _encodeChangeRecoveryAddressData(fid, newRecovery, owner, deadline);

    // prepare the digest using the wrong typehash
    digest = _buildKeyGatewayDigest(changeRecoveryAddressData);

    // sign it, appending the encoded data to the signature
    sig = _signChangeRecoveryAddress(adminKey, fid, newRecovery, owner, deadline);

    // assert that the signature is invalid
    assertEq(instance.isValidSignature(digest, sig), InvalidTypedData.selector);
  }
}

contract AddCasterKeyViaClient is WithInstanceTest {
  address public client = makeAddr("client");
  bytes public addKeySig;
  bytes public addRequestSig;

  function test_happy() public {
    // admin registers a new fid via its HatsFarcasterDelegator instance
    fid = _registerViaFarcasterDelegator(address(instance), admin, org);

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
    keyGateway.addFor(address(instance), keyType, key, metadataType, metadata, deadline, addKeySig);

    // internally, keyRegistry attempts to validate the signature, which results in an isValidSignature call to our
    // instance

    // assert that caster1's key was added
    assertAdded(fid, key, keyType);
  }
}
