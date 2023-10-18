// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { FarcasterDelegator, IIdRegistry } from "../../src/FarcasterDelegator.sol";

contract MockFarcasterDelegator is FarcasterDelegator {
  IIdRegistry internal _idRegistry;

  function idRegistry() public view override returns (IIdRegistry) {
    return _idRegistry;
  }

  constructor(IIdRegistry idRegistry_) {
    _idRegistry = idRegistry_;
  }

  // check recovery
  function checkRecovery() public view {
    _checkRecovery();
  }
}
