// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import { Test, console2 } from "forge-std/Test.sol";
import { MockFarcasterDelegator } from "./mock/MockFarcasterDelegator.sol";
import { IIdRegistry } from "farcaster/interfaces/IIdRegistry.sol";
import { TrustedCaller } from "farcaster/lib/TrustedCaller.sol";
import { IERC1271 } from "../src/interfaces/IERC1271.sol";

contract FDTest is Test {
  MockFarcasterDelegator public mock;
  address public recovery = makeAddr("recovery");
  uint256 public fid;
  IIdRegistry public idRegistry = IIdRegistry(0x00000000FcAf86937e41bA038B4fA40BAA4B780A);

  uint256 public fork;
  uint256 public BLOCK_NUMBER = 110_694_600; // after idRegistry was taken out of trusted mode

  error NotRecovery();

  function setUp() public virtual {
    // create and activate a fork, at BLOCK_NUMBER
    fork = vm.createSelectFork(vm.rpcUrl("optimism"), BLOCK_NUMBER);

    // deploy the mock
    mock = new MockFarcasterDelegator(idRegistry);

    // create a new fid for the mock.
    vm.prank(address(mock));
    fid = idRegistry.register(recovery);
  }
}

contract CheckRecovery is FDTest {
  function test_recovery() public {
    vm.prank(recovery);
    mock.checkRecovery();
  }

  function test_revert_notRecovery() public {
    vm.expectRevert(NotRecovery.selector);
    mock.checkRecovery();
  }
}

contract InterfaceDetection is FDTest {
  function test_IERC1271() public {
    assertTrue(mock.supportsInterface(type(IERC1271).interfaceId));
  }

  function test_false_IIdRegistry() public {
    assertFalse(mock.supportsInterface(type(IIdRegistry).interfaceId));
  }
}

contract GetIdRegistry is FDTest {
  function test_idRegistry() public {
    assertEq(address(mock.idRegistry()), address(idRegistry));
  }
}

contract Register is FDTest {
// TODO
}

contract AddKey is FDTest {
// TODO
}

contract RemoveKey is FDTest {
// TODO
}

contract TransferFid is FDTest {
// TODO
}

contract ChangeRecoveryAddress is FDTest {
  function test_happy() public {
    vm.prank(recovery);
    mock.changeRecoveryAddress(address(999));

    assertEq(idRegistry.recoveryOf(fid), address(999));
  }

  function test_revert_notRecovery() public {
    vm.expectRevert(NotRecovery.selector);
    mock.changeRecoveryAddress(address(999));

    assertEq(idRegistry.recoveryOf(fid), recovery);
  }
}

contract PrepareToReceive is FDTest {
// TODO
}
