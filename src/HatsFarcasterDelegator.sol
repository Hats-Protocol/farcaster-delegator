// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// import { console2 } from "forge-std/Test.sol"; // remove before deploy
import { HatsModule } from "hats-module/HatsModule.sol";
import { IIdRegistry } from "farcaster/interfaces/IIdRegistry.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { FarcasterDelegator, IERC1271 } from "./FarcasterDelegator.sol";

/*
Design considerations/questions:
- Should we support contract signatures? This might be relevant as account abstraction proliferates.
- Should we support multiple hats? This would require a different approach to {isValidSignature}, such as potentially
requiring that the hatId be appended to the signature. And also require logic to approve additional hats.
- Are there any relevant Farcaster functions we should wrap to enable the {recovery} address to call them?
*/

/**
 * @title HatsFarcasterDelegator
 * @author spengrah
 * @notice A contract that owns a Farcaster id and uses Hats Protocol to enable authorized signers to sign on its
 * behalf.
 * For example, an authorized hat-wearer could generate a valid signature to call {KeyRegistry.addFor} to add a new
 * Farcaster signer, enabling them to cast on behalf of the fid.
 * @dev This contract inherits from HatsModule, and is designed to deployed with immutable args via the
 * HatsModuleFactory contract.
 */
contract HatsFarcasterDelegator is FarcasterDelegator, HatsModule {
  /*//////////////////////////////////////////////////////////////
                            CONSTANTS 
  //////////////////////////////////////////////////////////////*/

  /**
   * This contract is a clone with immutable args, which means that it is deployed with a set of
   * immutable storage variables (ie constants). Accessing these constants is cheaper than accessing
   * regular storage variables (such as those set on initialization of a typical EIP-1167 clone),
   * but requires a slightly different approach since they are read from calldata instead of storage.
   *
   * Below is a table of constants and their location.
   *
   * For more, see here: https://github.com/Saw-mon-and-Natalie/clones-with-immutable-args
   *
   * ----------------------------------------------------------------------+
   * CLONE IMMUTABLE "STORAGE"                                             |
   * ----------------------------------------------------------------------|
   * Offset  | Constant          | Type    | Length  | Source              |
   * ----------------------------------------------------------------------|
   * 0       | IMPLEMENTATION    | address | 20      | HatsModule          |
   * 20      | HATS              | address | 20      | HatsModule          |
   * 40      | hatId             | uint256 | 32      | HatsModule          |
   * 72      | fid               | uint256 | 32      | this                |
   * 104     | idRegistry        | address | 20      | this                |
   * ----------------------------------------------------------------------+
   */

  /// @inheritdoc FarcasterDelegator
  function fid() public pure override returns (uint256) {
    return _getArgUint256(72);
  }

  /// @inheritdoc FarcasterDelegator
  function idRegistry() public pure override returns (IIdRegistry) {
    return IIdRegistry(_getArgAddress(104));
  }

  /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
  //////////////////////////////////////////////////////////////*/

  /// @notice Deploy the implementation contract and set its version
  /// @dev This is only used to deploy the implementation contract, and should not be used to deploy clones
  constructor(string memory _version) HatsModule(_version) { }

  /*//////////////////////////////////////////////////////////////
                            INITIALIZOR
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc HatsModule
  function _setUp(bytes calldata _initData) internal override { }

  /*//////////////////////////////////////////////////////////////
                        FARCASTER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  // TODO add wrappers for relevant Farcaster functions to enable the {recovery} address to call them?

  /*//////////////////////////////////////////////////////////////
                          ERC1271 FUNCTION
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc FarcasterDelegator
  // TODO support contract signatures?
  // TODO support multiple hats?
  function isValidSignature(bytes32 _hash, bytes calldata _signature) public view override returns (bytes4) {
    /// @dev ECDSA.recoverCalldata() will revert with `InvalidSignature()` if the signature is invalid
    address signer = ECDSA.recoverCalldata(_hash, _signature);

    // check that the signer is wearing the {hatId} hat
    if (HATS().isWearerOfHat(signer, hatId())) {
      return IERC1271.isValidSignature.selector; // the ERC1271 magic value
    } else {
      return 0xFFFFFFFF;
    }
  }
}
