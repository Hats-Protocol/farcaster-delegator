// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import { Test, console2 } from "forge-std/Test.sol";
import { ForkTest } from "./Base.t.sol";
import { MockFarcasterDelegator } from "./mock/MockFarcasterDelegator.sol";
import { IIdRegistry } from "farcaster/interfaces/IIdRegistry.sol";
import { IKeyRegistry } from "farcaster/interfaces/IKeyRegistry.sol";
import { IERC1271 } from "../src/interfaces/IERC1271.sol";

contract MockTest is ForkTest {
  MockFarcasterDelegator public mock;
  address public recovery;
  uint256 public recoveryKey;

  function setUp() public virtual override {
    super.setUp();

    // set up addresses
    (recovery, recoveryKey) = makeAddrAndKey("recovery");

    // deploy the mock
    mock = new MockFarcasterDelegator(idGateway, idRegistry, keyGateway, keyRegistry_, signedKeyRequestValidator);

    // create a new fid for the mock.
    fid = _registerViaGateway(address(mock), recovery);
  }
}

contract CheckValidSigner is MockTest {
  function test_hasFid_recovery() public view {
    mock.checkValidSigner(0x0, recovery);
  }

  function test_hasFid_notRecover() public {
    vm.expectRevert(Unauthorized.selector);
    mock.checkValidSigner(0x0, address(999));
  }

  function test_noFid() public {
    // redeploy the mock but don't create an fid for it
    mock = new MockFarcasterDelegator(idGateway, idRegistry, keyGateway, keyRegistry_, signedKeyRequestValidator);

    mock.checkValidSigner(0x0, address(999));
  }
}

contract InterfaceDetection is MockTest {
  function test_IERC1271() public {
    assertTrue(mock.supportsInterface(type(IERC1271).interfaceId));
  }

  function test_false_IIdRegistry() public {
    assertFalse(mock.supportsInterface(type(IIdRegistry).interfaceId));
  }
}

contract Getters is MockTest {
  function test_idRegistry() public {
    assertEq(address(mock.idRegistry()), address(idRegistry));
  }

  function test_keyRegistry() public {
    assertEq(address(mock.keyRegistry()), address(keyRegistry_));
  }

  function test_signedKeyRequestValidator() public {
    assertEq(mock.signedKeyRequestValidator(), signedKeyRequestValidator);
  }
}

contract Register is MockTest {
  error HasId();

  function test_noFid() public {
    // redeploy the mock but don't create an fid for it
    mock = new MockFarcasterDelegator(idGateway, idRegistry, keyGateway, keyRegistry_, signedKeyRequestValidator);

    // now register an fid for the mock
    fid = _registerViaFarcasterDelegator(address(mock), recovery, recovery);

    assertEq(idRegistry.idOf(address(mock)), fid);
    assertEq(idRegistry.recoveryOf(fid), recovery);
  }

  function test_revert_hasFid() public {
    vm.expectRevert(HasId.selector);
    fid = _registerViaFarcasterDelegator(address(mock), recovery, recovery);
  }

  function test_revert_authorized_hasFid() public {
    vm.prank(recovery);
    vm.expectRevert();
    fid = _registerViaFarcasterDelegator(address(mock), recovery, recovery);
  }
}

contract AddKey is MockTest {
  function test_happy() public {
    // build signed key request metadata for the new key
    metadata = _buildSignedKeyRequestMetadata(
      signedKeyRequestValidator, fid, recoveryKey, address(mock), key, block.timestamp + 1 days
    );

    // recovery adds the key via the mock
    vm.prank(recovery);
    mock.addKey(keyType, key, metadataType, metadata);

    assertAdded(fid, key, keyType);
  }

  function test_revert_notAuthorized() public {
    // build signed key request metadata for the new key
    metadata = _buildSignedKeyRequestMetadata(
      signedKeyRequestValidator, fid, recoveryKey, address(mock), key, block.timestamp + 1 days
    );

    vm.expectRevert(Unauthorized.selector);
    mock.addKey(keyType, key, metadataType, metadata);

    assertEq(keyRegistry.keyDataOf(fid, key).state, IKeyRegistry.KeyState.NULL);
  }
}

contract RemoveKey is MockTest {
  function setUp() public override {
    super.setUp();

    // add a key to the mock
    metadata = _buildSignedKeyRequestMetadata(
      signedKeyRequestValidator, fid, recoveryKey, address(mock), key, block.timestamp + 1 days
    );

    vm.prank(recovery);
    mock.addKey(keyType, key, metadataType, metadata);
  }

  function test_happy() public {
    // recovery removes the key via the mock
    vm.prank(recovery);
    mock.removeKey(key);

    assertEq(keyRegistry.keyDataOf(fid, key).state, IKeyRegistry.KeyState.REMOVED);
  }

  function test_revert_notAuthorized() public {
    vm.expectRevert(Unauthorized.selector);
    mock.removeKey(key);

    assertEq(keyRegistry.keyDataOf(fid, key).state, IKeyRegistry.KeyState.ADDED);
  }
}

contract TransferFid is MockTest {
  address public recipient;
  uint256 public recipientKey;

  function setUp() public override {
    super.setUp();

    (recipient, recipientKey) = makeAddrAndKey("recipient");
  }

  function test_happy() public {
    // the mock owns the fid
    assertEq(idRegistry.idOf(address(mock)), fid);

    // recipient signs the transfer approval
    deadline = block.timestamp + 1 days;
    signature = _signReceiveEOA(recipientKey, fid, recipient, deadline);

    // recovery transfers the mock's fid to the recipient
    vm.prank(recovery);
    mock.transferFid(recipient, deadline, signature);

    assertEq(idRegistry.idOf(recipient), fid, "recipient should own the fid");
    assertEq(idRegistry.idOf(address(mock)), 0, "mock should no longer own the fid");
    assertEq(idRegistry.recoveryOf(fid), recovery, "recovery should still be the recovery address");
  }
}

contract ChangeRecoveryAddress is MockTest {
  function test_happy() public {
    vm.prank(recovery);
    mock.changeRecoveryAddress(address(999));

    assertEq(idRegistry.recoveryOf(fid), address(999));
  }

  function test_revert_notRecovery() public {
    vm.expectRevert(Unauthorized.selector);
    mock.changeRecoveryAddress(address(999));

    assertEq(idRegistry.recoveryOf(fid), recovery);
  }
}

contract PrepareToReceive is MockTest {
  function test_happy() public {
    // redeploy the mock but don't create an fid for it
    mock = new MockFarcasterDelegator(idGateway, idRegistry, keyGateway, keyRegistry_, signedKeyRequestValidator);

    fid = 15;

    vm.expectEmit();
    emit ReadyToReceive(fid);
    mock.prepareToReceive(fid);

    assertTrue(mock.receivable(fid));
  }

  function test_revert_alreadyRegistered() public {
    fid = 15;

    vm.expectRevert(AlreadyRegistered.selector);
    mock.prepareToReceive(fid);
  }
}

contract Receive is MockTest {
  function setUp() public override {
    super.setUp();

    // redeploy the mock
    mock = new MockFarcasterDelegator(idGateway, idRegistry, keyGateway, keyRegistry_, signedKeyRequestValidator);
  }

  function test_transfer() public {
    // recovery registers an fid for itself
    fid = _registerViaGateway(recovery, recovery);

    // recover prepares the mock to receive the fid
    vm.prank(recovery);
    mock.prepareToReceive(fid);

    // recovery generates the transfer signature block for the mock to receive the fid
    deadline = block.timestamp + 1 days;
    signature = _signReceive(recoveryKey, fid, address(mock), deadline);

    // recovery transfers the fid to the mock
    vm.prank(recovery);
    idRegistry.transfer(address(mock), deadline, signature);
  }
}
