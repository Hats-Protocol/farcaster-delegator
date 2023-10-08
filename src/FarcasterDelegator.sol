// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { IERC1271 } from "./interfaces/IERC1271.sol";
import { IIdRegistry } from "farcaster/interfaces/IIdRegistry.sol";

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
                                VIEWS
  //////////////////////////////////////////////////////////////*/

  /// @notice The address of the Farcaster Id Registry
  function idRegistry() public view virtual returns (IIdRegistry) { }

  /*//////////////////////////////////////////////////////////////
                        SIGNER VERIFICATION
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc IERC1271
  function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual override returns (bytes4) { }

  /// @notice Check whether a signer is authorized by this contract
  function isValidSigner(address signer) public view returns (bool) { }

  /*//////////////////////////////////////////////////////////////
                            ACCESS CONTROL
  //////////////////////////////////////////////////////////////*/

  /// @dev Check that the caller is the recovery address for the fid that this contract owns
  function _checkRecovery() internal view {
    if (msg.sender != idRegistry().recoveryOf(idRegistry().idOf(address(this)))) {
      revert NotRecovery();
    }
  }

  /*//////////////////////////////////////////////////////////////
                         INTERFACE DETECTION
  //////////////////////////////////////////////////////////////*/

  function supportsInterface(bytes4 interfaceId) public pure returns (bool) {
    return interfaceId == type(IERC1271).interfaceId;
  }
}
