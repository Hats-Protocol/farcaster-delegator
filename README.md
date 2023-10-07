# hats-module-template

Template repo for Hats Module projects.

## Overview and Usage

## Development

This repo uses Foundry for development and testing. To get started:

1. Fork the project
2. Install [Foundry](https://book.getfoundry.sh/getting-started/installation)
3. To install dependencies, run `forge install`
4. To compile the contracts, run `forge build`
5. To test, run `forge test`

### IR-Optimized Builds

This repo also supports contracts compiled via IR. Since compiling all contracts via IR would slow down testing workflows, we only want to do this for our target contract(s), not anything in this `test` or `script` stack. We accomplish this by pre-compiled the target contract(s) and then loading the pre-compiled artifacts in the test suite.

First, we compile the target contract(s) via IR by running`FOUNDRY_PROFILE=optimized forge build` (ensuring that FOUNDRY_PROFILE is not in our .env file)

Next, ensure that tests are using the `DeployOptimized` script, and run `forge test` as normal.

See the wonderful [Seaport repo](https://github.com/ProjectOpenSea/seaport/blob/main/README.md#foundry-tests) for more details and options for this approach.
