// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import { Script, console2 } from "forge-std/Script.sol";
import { HatsFarcasterDelegator } from "../src/HatsFarcasterDelegator.sol";

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

// contract DeployInstance is Script {
//   HatsModuleFactory public constant FACTORY = HatsModuleFactory(0xfE661c01891172046feE16D3a57c3Cf456729efA);
//   address public implementation; // = 0x
//   address public instance;

//   // default values
//   bool internal _verbose = true;
//   uint256 public targetHat;
//   uint256 public threshold;

//   /// @dev Override default values, if desired
//   function prepare(bool verbose, uint256 _targetHat, address _implementation, uint256 _threshold) public {
//     _verbose = verbose;
//     targetHat = _targetHat;
//     implementation = _implementation;
//     threshold = _threshold;
//   }

//   /// @dev Set up the deployer via their private key from the environment
//   function deployer() public returns (address) {
//     uint256 privKey = vm.envUint("PRIVATE_KEY");
//     return vm.rememberKey(privKey);
//   }

//   function _log(string memory prefix) internal view {
//     if (_verbose) {
//       console2.log(string.concat(prefix, "Deployed instance:"), instance);
//     }
//   }

//   /// @dev Deploy the contract to a deterministic address via forge's create2 deployer factory.
//   function run() public virtual returns (address) {
//     vm.startBroadcast(deployer());

//     instance = FACTORY.createHatsModule(
//       implementation,
//       targetHat, // hatId
//       abi.encodePacked(
//         ownerHat,
//         address(idGateway),
//         address(idRegistry),
//         address(keyGateway),
//         address(keyRegistry),
//         signedKeyRequestValidator
//       ), // otherImmutableArgs
//       abi.encode(address(0)); // initArgs
//     );

//     vm.stopBroadcast();

//     _log("");

//     return instance;
//   }
// }

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
