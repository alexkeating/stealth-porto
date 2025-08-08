// SPDX-License-Identifier: UNLICENSED
// slither-disable-start reentrancy-benign

pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {StealthSender} from "src/StealthSender.sol";
import {ShieldedPool} from "src/ShieldedPool.sol";
import {IthacaAccount} from "lib/account/src/IthacaAccount.sol";

contract Deploy is Script {
  StealthSender stealthSender;
  IthacaAccount ithacaAccount;
  ShieldedPool shieldedPool;

  function run() public {
    vm.broadcast();
    stealthSender = new StealthSender();

    vm.broadcast();
    // Deploy IthacaAccount with no orchestrator for now (can be updated later)
    ithacaAccount = new IthacaAccount(address(0));

    vm.broadcast();
    shieldedPool = new ShieldedPool();
  }
}
