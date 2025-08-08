# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Solidity smart contract project using the Foundry framework, based on the ScopeLift Foundry Template. The project uses Solidity 0.8.30 and includes comprehensive testing, linting, and CI/CD workflows.

## Essential Commands

### Build and Test
- `forge build` - Compile all contracts
- `forge test` - Run all tests
- `forge test --match-test testName` - Run a specific test
- `forge test --match-contract ContractName` - Run tests for a specific contract
- `forge coverage` - Generate test coverage report

### Development Profiles
- `forge build --profile lite` - Fast compilation without optimizer
- `forge test --profile ci` - Extended fuzz testing (5000 runs)
- `forge coverage --profile coverage` - Optimized for coverage generation

### Linting and Formatting
- `scopelint fmt` - Format code according to project standards
- `scopelint check` - Check formatting without modifying files

### Deployment
- `forge script script/Deploy.s.sol --rpc-url <RPC_URL>` - Deploy contracts
- Add `--broadcast` flag to actually send transactions

## Architecture

### Contract Structure
- **src/**: Smart contract source code
  - Contracts should follow the pattern of having a single main contract per file
  - Use explicit imports, not global imports
  
### Testing Architecture
- **test/**: Test files following Foundry conventions
  - Tests inherit from both `Test` and the corresponding `Deploy` script
  - Each test contract focuses on a specific function or behavior
  - Test naming: `test_` for unit tests, `testFuzz_` for fuzz tests
  
### Deployment Pattern
- **script/**: Deployment scripts
  - Scripts must have a single public `run()` method (enforced by scopelint)
  - Deploy scripts are inherited by tests for deployment verification
  - Use `vm.broadcast()` for actual deployment transactions

## Key Development Patterns

### Testing Pattern
Tests inherit from the deployment script to ensure deployment and testing consistency:
```solidity
contract CounterTest is Test, Deploy {
    function setUp() public {
        deploy();
    }
}
```

### Formatting Rules
The project enforces specific formatting through scopelint:
- Internal functions must be prefixed with underscore
- Constants must be SCREAMING_SNAKE_CASE
- 100 character line length limit
- 2 space indentation

### Security Considerations
- Slither static analysis runs on CI for all PRs
- Security findings are integrated with GitHub Security tab
- Coverage requirement: 100% for CI builds