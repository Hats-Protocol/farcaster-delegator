// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {
  FarcasterDelegator,
  IERC1271,
  IIdGateway,
  IIdRegistry,
  IKeyGateway,
  IKeyRegistry
} from "../../src/FarcasterDelegator.sol";

contract MockFarcasterDelegator is FarcasterDelegator {
  IIdGateway internal _idGateway;
  IIdRegistry internal _idRegistry;
  IKeyGateway internal _keyGateway;
  IKeyRegistry internal _keyRegistry;
  address internal _signedKeyRequestValidator;

  function idGateway() public view override returns (IIdGateway) {
    return _idGateway;
  }

  function idRegistry() public view override returns (IIdRegistry) {
    return _idRegistry;
  }

  function keyGateway() public view override returns (IKeyGateway) {
    return _keyGateway;
  }

  function keyRegistry() public view override returns (IKeyRegistry) {
    return _keyRegistry;
  }

  function signedKeyRequestValidator() public view override returns (address) {
    return _signedKeyRequestValidator;
  }

  constructor(
    IIdGateway idGateway_,
    IIdRegistry idRegistry_,
    IKeyGateway keyGateway_,
    IKeyRegistry keyRegistry_,
    address signedKeyRequestValidator_
  ) {
    _idGateway = idGateway_;
    _idRegistry = idRegistry_;
    _keyGateway = keyGateway_;
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
