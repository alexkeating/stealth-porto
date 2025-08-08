// SPDX-License-Identifier: UNLICENSED
// slither-disable-start reentrancy-benign

pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {Counter} from "src/Counter.sol";
import {StealthSender} from "src/StealthSender.sol";
import {SweepAccount} from "src/SweepAccount.sol";
import {ShieldedPool} from "src/ShieldedPool.sol";

contract Deploy is Script {
  Counter counter;
  StealthSender stealthSender;
  SweepAccount sweepAccount;
  ShieldedPool shieldedPool;

  function run() public {
    vm.broadcast();
    counter = new Counter();

    vm.broadcast();
    stealthSender = new StealthSender();

    vm.broadcast();
    // Deploy with no orchestrator for now (can be updated later)
    sweepAccount = new SweepAccount(address(0), msg.sender);

    vm.broadcast();
    shieldedPool = new ShieldedPool();
  }
}
