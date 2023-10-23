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
   * 72      | adminHat                   | uint256       | 32      | this       |
   * 104     | idRegistry                 | IIdRegistry   | 20      | this       |
   * 124     | keyRegistry                | IKeyRegistry  | 20      | this       |
   * 144     | signedKeyRequestValidator  | address       | 20      | this       |
   * ----------------------------------------------------------------------------+
   */

  /**
   * @notice The wearer(s) of this hat can take the following actions on behalf of this contract:
   *  - Register a fid
   *  - Transfer the fid to a new owner
   *  - Change the recovery address of the fid
   *  - Add a new key for the fid
   */
  function adminHat() public pure returns (uint256) {
    return _getArgUint256(72);
  }

  /// @inheritdoc FarcasterDelegator
  function idRegistry() public pure override returns (IIdRegistry) {
    return IIdRegistry(_getArgAddress(104));
  }

  /// @inheritdoc FarcasterDelegator
  function keyRegistry() public pure override returns (IKeyRegistry) {
    return IKeyRegistry(_getArgAddress(124));
  }

  /// @inheritdoc FarcasterDelegator
  function signedKeyRequestValidator() public pure override returns (address) {
    return _getArgAddress(144);
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

  /// @notice Check whether `_signer` is authorized by this contract for the given `_typehash` action
  /// @param _typehash The typehash of the Farcaster action being authorized.
  function isValidSigner(bytes32 _typehash, address _signer) public view returns (bool) {
    return _isValidSigner(_typehash, _signer);
  }

  /*//////////////////////////////////////////////////////////////
                            OVERRIDES
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc FarcasterDelegator
  function _isValidSigner(bytes32 _typehash, address _signer) internal view override returns (bool) {
    // Must be wearing either the {hatId} hat or the {adminHat} to add a new key
    if (_typehash == ADD_TYPEHASH || _typehash == SIGNED_KEY_REQUEST_TYPEHASH) {
      return HATS().isWearerOfHat(_signer, hatId()) || HATS().isWearerOfHat(_signer, adminHat());
    }

    // Must be wearing the {adminHat} hat to register, transfer, change recovery address, or remove a key
    if (
      _typehash == REGISTER_TYPEHASH || _typehash == TRANSFER_TYPEHASH || _typehash == CHANGE_RECOVERY_ADDRESS_TYPEHASH
        || _typehash == REMOVE_TYPEHASH
    ) {
      return HATS().isWearerOfHat(_signer, adminHat());
    }

    // no other actions are authorized
    return false;
  }
}
