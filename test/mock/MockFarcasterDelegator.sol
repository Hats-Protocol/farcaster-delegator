// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { FarcasterDelegator, IIdRegistry, IKeyRegistry } from "../../src/FarcasterDelegator.sol";

contract MockFarcasterDelegator is FarcasterDelegator {
  IIdRegistry internal _idRegistry;
  IKeyRegistry internal _keyRegistry;
  address internal _signedKeyRequestValidator;

  function idRegistry() public view override returns (IIdRegistry) {
    return _idRegistry;
  }

  function keyRegistry() public view override returns (IKeyRegistry) {
    return _keyRegistry;
  }

  function signedKeyRequestValidator() public view override returns (address) {
    return _signedKeyRequestValidator;
  }

  constructor(IIdRegistry idRegistry_, IKeyRegistry keyRegistry_, address signedKeyRequestValidator_) {
    _idRegistry = idRegistry_;
    _keyRegistry = keyRegistry_;
    _signedKeyRequestValidator = signedKeyRequestValidator_;
  }

  function checkValidSigner(bytes32 _typehash, address _signer) public view {
    _checkValidSigner(_typehash, _signer);
  }

  function _isValidSigner(bytes32, /*_typehash*/ address _signer) internal view override returns (bool) {
    uint256 fid = idRegistry().idOf(address(this));
    if (fid > 0) {
      return _signer == idRegistry().recoveryOf(fid);
    } else {
      return true;
    }
  }
}
