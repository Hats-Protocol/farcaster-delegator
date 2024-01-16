// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import { Script, console2 } from "forge-std/Script.sol";
import { HatsFarcasterDelegator } from "../src/HatsFarcasterDelegator.sol";
import { HatsModuleFactory } from "hats-module/HatsModuleFactory.sol";

contract DeployImplementation is Script {
  HatsFarcasterDelegator public implementation;
  bytes32 public SALT = bytes32(abi.encode(0x4a75));

  // default values
  bool internal _verbose = true;
  string internal _version = "0.1.0"; // increment this with each new deployment

  /// @dev Override default values, if desired
  function prepare(bool verbose, string memory version) public {
    _verbose = verbose;
    _version = version;
  }

  /// @dev Set up the deployer via their private key from the environment
  function deployer() public returns (address) {
    uint256 privKey = vm.envUint("PRIVATE_KEY");
    return vm.rememberKey(privKey);
  }

  function _log(string memory prefix) internal view {
    if (_verbose) {
      console2.log(string.concat(prefix, "Deployed implementation:"), address(implementation));
    }
  }

  /// @dev Deploy the contract to a deterministic address via forge's create2 deployer factory.
  function run() public virtual {
    vm.startBroadcast(deployer());

    /**
     * @dev Deploy the contract to a deterministic address via forge's create2 deployer factory, which is at this
     * address on all chains: `0x4e59b44847b379578588920cA78FbF26c0B4956C`.
     * The resulting deployment address is determined by only two factors:
     *    1. The bytecode hash of the contract to deploy. Setting `bytecode_hash` to "none" in foundry.toml ensures that
     *       never differs regardless of where its being compiled
     *    2. The provided salt, `SALT`
     */
    implementation = new HatsFarcasterDelegator{ salt: SALT }(_version);

    vm.stopBroadcast();

    _log("");
  }
}

contract DeployInstance is Script {
  HatsModuleFactory public constant FACTORY = HatsModuleFactory(0xfE661c01891172046feE16D3a57c3Cf456729efA);
  address public implementation = 0x7E3c2179BF9AF88F76d03976fF9fb103208C4c3f;
  address public instance;

  // default values
  bool internal _verbose = true;
  uint256 public ownerHat = 0x0000003a00010001000000000000000000000000000000000000000000000000;
  uint256 public casterHat = 0x0000003a00010001000100000000000000000000000000000000000000000000;
  address public idGateway = 0x00000000Fc25870C6eD6b6c7E41Fb078b7656f69;
  address public idRegistry = 0x00000000Fc6c5F01Fc30151999387Bb99A9f489b;
  address public keyGateway = 0x00000000fC56947c7E7183f8Ca4B62398CaAdf0B;
  address public keyRegistry = 0x00000000Fc1237824fb747aBDE0FF18990E59b7e;
  address public signedKeyRequestValidator = 0x00000000FC700472606ED4fA22623Acf62c60553;

  /// @dev Override default values, if desired
  function prepare(
    bool verbose,
    uint256 _ownerHat,
    uint256 _casterHat,
    address _implementation,
    address _idGateway,
    address _idRegistry,
    address _keyGateway,
    address _keyRegistry,
    address _signedKeyRequestValidator
  ) public {
    _verbose = verbose;
    ownerHat = _ownerHat;
    casterHat = _casterHat;
    implementation = _implementation;
    idGateway = _idGateway;
    idRegistry = _idRegistry;
    keyGateway = _keyGateway;
    keyRegistry = _keyRegistry;
    signedKeyRequestValidator = _signedKeyRequestValidator;
  }

  /// @dev Set up the deployer via their private key from the environment
  function deployer() public returns (address) {
    uint256 privKey = vm.envUint("PRIVATE_KEY");
    return vm.rememberKey(privKey);
  }

  function _log(string memory prefix) internal view {
    if (_verbose) {
      console2.log(string.concat(prefix, "Deployed instance:"), instance);
    }
  }

  /// @dev Deploy the contract to a deterministic address via forge's create2 deployer factory.
  function run() public virtual returns (address) {
    vm.startBroadcast(deployer());

    instance = FACTORY.createHatsModule(
      implementation,
      casterHat, // hatId
      abi.encodePacked(ownerHat, idGateway, idRegistry, keyGateway, keyRegistry, signedKeyRequestValidator), // otherImmutableArgs
      abi.encode(address(0)) // initArgs
    );

    vm.stopBroadcast();

    _log("");

    return instance;
  }
}

/* FORGE CLI COMMANDS

## A. Simulate the deployment locally
forge script script/HatsFarcasterDelegator.s.sol -f mainnet

## B. Deploy to real network and verify on etherscan
forge script script/Deploy.s.sol -f mainnet --broadcast --verify

## C. Fix verification issues (replace values in curly braces with the actual values)
forge verify-contract --chain-id 1 --num-of-optimizations 1000000 --watch --constructor-args $(cast abi-encode \
 "constructor({args})" "{arg1}" "{arg2}" "{argN}" ) \ 
 --compiler-version v0.8.19 {deploymentAddress} \
 src/{Counter}.sol:{Counter} --etherscan-api-key $ETHERSCAN_KEY

*/
