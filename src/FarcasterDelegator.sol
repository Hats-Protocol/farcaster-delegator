// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { IERC1271 } from "./interfaces/IERC1271.sol";
import { IFarcasterDelegator } from "./interfaces/IFarcasterDelegator.sol";
import { IIdRegistry } from "farcaster/interfaces/IIdRegistry.sol";

abstract contract FarcasterDelegator is IERC1271, IFarcasterDelegator {
  /// @inheritdoc IFarcasterDelegator
  function idRegistry() public view virtual override returns (IIdRegistry) { }

  /// @inheritdoc IFarcasterDelegator
  function fid() public view virtual override returns (uint256);

  /// @inheritdoc IFarcasterDelegator
  function recovery() public view virtual returns (address) {
    return idRegistry().recoveryOf(fid());
  }

  /// @inheritdoc IERC1271
  function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual override returns (bytes4) { }

  /*//////////////////////////////////////////////////////////////
                         INTERFACE DETECTION
  //////////////////////////////////////////////////////////////*/

  function supportsInterface(bytes4 interfaceId) public pure returns (bool) {
    return interfaceId == type(IERC1271).interfaceId || interfaceId == type(IFarcasterDelegator).interfaceId;
  }
}
