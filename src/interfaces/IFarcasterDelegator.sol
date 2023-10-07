// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { IIdRegistry } from "farcaster/interfaces/IIdRegistry.sol";

interface IFarcasterDelegator {
  /// @notice The Farcaster id registry contract
  function idRegistry() external view returns (IIdRegistry);

  /// @notice The farcaster id owned by this contract
  function fid() external view returns (uint256);

  /// @notice The recovery address for {fid}.
  function recovery() external view returns (address);
}
