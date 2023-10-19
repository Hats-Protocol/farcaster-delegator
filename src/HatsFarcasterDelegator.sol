// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// import { console2 } from "forge-std/Test.sol"; // remove before deploy
import { HatsModule } from "hats-module/HatsModule.sol";
import { FarcasterDelegator, IERC1271, IIdRegistry, IKeyRegistry } from "./FarcasterDelegator.sol";

/*
Design considerations/questions:
- How can this contract receive fid transfers?
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
   * ----------------------------------------------------------------------------+
   * CLONE IMMUTABLE "STORAGE"                                                   |
   * ----------------------------------------------------------------------------|
   * Offset  | Constant                   | Type          | Length  | Source     |
   * ----------------------------------------------------------------------------|
   * 0       | IMPLEMENTATION             | address       | 20      | HatsModule |
   * 20      | HATS                       | address       | 20      | HatsModule |
   * 40      | hatId                      | uint256       | 32      | HatsModule |
   * 72      | idRegistry                 | IIdRegistry   | 20      | this       |
   * 92      | keyRegistry                | IKeyRegistry  | 20      | this       |
   * 112     | signedKeyRequestValidator  | address       | 20      | this       |
   * ----------------------------------------------------------------------------+
   */

  /// @inheritdoc FarcasterDelegator
  function idRegistry() public pure override returns (IIdRegistry) {
    return IIdRegistry(_getArgAddress(72));
  }

  /// @inheritdoc FarcasterDelegator
  function keyRegistry() public pure override returns (IKeyRegistry) {
    return IKeyRegistry(_getArgAddress(92));
  }

  /// @inheritdoc FarcasterDelegator
  function signedKeyRequestValidator() public pure override returns (address) {
    return _getArgAddress(112);
  }

  /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
  //////////////////////////////////////////////////////////////*/

  /// @notice Deploy the implementation contract and set its version
  /// @dev This is only used to deploy the implementation contract, and should not be used to deploy clones
  constructor(string memory _version) HatsModule(_version) { }

  /*//////////////////////////////////////////////////////////////
                            INITIALIZER
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc HatsModule
  function _setUp(bytes calldata _initData) internal override {
    address recovery = abi.decode(_initData, (address));

    if (recovery != address(0)) {
      register(recovery);
    }
  }

  /*//////////////////////////////////////////////////////////////
                          PUBLIC FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @notice Check whether `_signer` is authorized by this contract for the given `_typeHash` action
  /// @param _typeHash The typehash of the Farcaster action being authorized.
  function isValidSigner(bytes32 _typeHash, address _signer) public view returns (bool) {
    return _isValidSigner(_typeHash, _signer);
  }

  /*//////////////////////////////////////////////////////////////
                            OVERRIDES
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc FarcasterDelegator
  // TODO handle transfer signatures so that this contract can receive fid transfers
  // TODO support multiple hats?
  function _isValidSigner(bytes32 _typeHash, address _signer) internal view override returns (bool) {
    /// @dev Valid signers for adding a new key are addresses that are currently wearing the {hatId} hat
    if (_typeHash == ADD_TYPEHASH || _typeHash == SIGNED_KEY_REQUEST_TYPEHASH) {
      return HATS().isWearerOfHat(_signer, hatId());
    }

    return false;
  }

  function _prepareToReceive(uint256 _fid) internal override { }
}
