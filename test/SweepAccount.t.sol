// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {SweepAccount} from "src/SweepAccount.sol";
import {ShieldedPool} from "src/ShieldedPool.sol";
import {ERC20Mock} from "openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract SweepAccountTest is Test {
  using ECDSA for bytes32;

  SweepAccount public sweepAccount;
  ShieldedPool public shieldedPool;
  ERC20Mock public token;

  uint256 public ownerPrivateKey = 0x1234;
  address public owner;
  address public recipient = address(0x2);
  uint256 public constant INITIAL_BALANCE = 1000 ether;

  bytes32 public constant SWEEP_INTENT_TYPEHASH = keccak256(
    "SweepIntent(address token,address recipient,uint256 amount,uint256 nonce,uint256 expiry)"
  );

  event TokensSwept(
    address indexed token, address indexed recipient, uint256 amount, uint256 nonce
  );

  function setUp() public {
    owner = vm.addr(ownerPrivateKey);
    // Use address(0) as orchestrator for basic tests
    sweepAccount = new SweepAccount(address(0), owner);
    shieldedPool = new ShieldedPool();
    token = new ERC20Mock();

    token.mint(address(sweepAccount), INITIAL_BALANCE);
    vm.deal(address(sweepAccount), INITIAL_BALANCE);
  }

  function _signIntent(SweepAccount.SweepIntent memory intent)
    internal
    view
    returns (bytes memory signature)
  {
    bytes32 structHash = keccak256(
      abi.encode(
        SWEEP_INTENT_TYPEHASH,
        intent.token,
        intent.recipient,
        intent.amount,
        intent.nonce,
        intent.expiry
      )
    );

    bytes32 domainSeparator = keccak256(
      abi.encode(
        keccak256(
          "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        ),
        keccak256(bytes("SweepAccount")),
        keccak256(bytes("1")),
        block.chainid,
        address(sweepAccount)
      )
    );

    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
    signature = abi.encodePacked(r, s, v);
  }

  function _createIntent(address tokenAddr, uint256 amount, uint256 nonce)
    internal
    view
    returns (SweepAccount.SweepIntent memory)
  {
    return SweepAccount.SweepIntent({
      token: tokenAddr,
      recipient: recipient,
      amount: amount,
      nonce: nonce,
      expiry: 0
    });
  }
}

contract SweepAccountTest_Constructor is SweepAccountTest {
  function test_ConstructorSetsOwner() public view {
    assertEq(sweepAccount.owner(), owner);
  }

  function test_RevertWhen_ConstructorWithZeroOwner() public {
    vm.expectRevert(SweepAccount.UnauthorizedCaller.selector);
    new SweepAccount(address(0), address(0));
  }
}

contract SweepAccountTest_ExecuteSweep is SweepAccountTest {
  function test_ExecuteSweepERC20() public {
    uint256 sweepAmount = 100 ether;
    uint256 nonce = 1;

    SweepAccount.SweepIntent memory intent = _createIntent(address(token), sweepAmount, nonce);
    bytes memory signature = _signIntent(intent);

    vm.expectEmit(true, true, false, true);
    emit TokensSwept(address(token), recipient, sweepAmount, nonce);

    sweepAccount.executeSweep(intent, signature);

    assertEq(token.balanceOf(recipient), sweepAmount);
    assertEq(token.balanceOf(address(sweepAccount)), INITIAL_BALANCE - sweepAmount);
    assertTrue(sweepAccount.isNonceUsed(nonce));
  }

  function test_ExecuteSweepETH() public {
    uint256 sweepAmount = 100 ether;
    uint256 nonce = 1;

    SweepAccount.SweepIntent memory intent = _createIntent(address(0), sweepAmount, nonce);
    bytes memory signature = _signIntent(intent);

    uint256 recipientBalanceBefore = recipient.balance;

    vm.expectEmit(true, true, false, true);
    emit TokensSwept(address(0), recipient, sweepAmount, nonce);

    sweepAccount.executeSweep(intent, signature);

    assertEq(recipient.balance, recipientBalanceBefore + sweepAmount);
    assertEq(address(sweepAccount).balance, INITIAL_BALANCE - sweepAmount);
    assertTrue(sweepAccount.isNonceUsed(nonce));
  }

  function test_RevertWhen_InvalidSignature() public {
    SweepAccount.SweepIntent memory intent = _createIntent(address(token), 100 ether, 1);

    uint256 wrongPrivateKey = 0x5678;
    bytes32 structHash = keccak256(
      abi.encode(
        SWEEP_INTENT_TYPEHASH,
        intent.token,
        intent.recipient,
        intent.amount,
        intent.nonce,
        intent.expiry
      )
    );
    bytes32 domainSeparator = keccak256(
      abi.encode(
        keccak256(
          "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        ),
        keccak256(bytes("SweepAccount")),
        keccak256(bytes("1")),
        block.chainid,
        address(sweepAccount)
      )
    );
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, digest);
    bytes memory wrongSignature = abi.encodePacked(r, s, v);

    vm.expectRevert(SweepAccount.InvalidSignature.selector);
    sweepAccount.executeSweep(intent, wrongSignature);
  }

  function test_RevertWhen_NonceAlreadyUsed() public {
    uint256 nonce = 1;
    SweepAccount.SweepIntent memory intent = _createIntent(address(token), 100 ether, nonce);
    bytes memory signature = _signIntent(intent);

    sweepAccount.executeSweep(intent, signature);

    vm.expectRevert(SweepAccount.NonceAlreadyUsed.selector);
    sweepAccount.executeSweep(intent, signature);
  }

  function test_RevertWhen_IntentExpired() public {
    vm.warp(1000);
    SweepAccount.SweepIntent memory intent = SweepAccount.SweepIntent({
      token: address(token),
      recipient: recipient,
      amount: 100 ether,
      nonce: 1,
      expiry: 999
    });
    bytes memory signature = _signIntent(intent);

    vm.expectRevert(SweepAccount.IntentExpired.selector);
    sweepAccount.executeSweep(intent, signature);
  }

  function test_RevertWhen_InsufficientBalance() public {
    SweepAccount.SweepIntent memory intent = _createIntent(address(token), INITIAL_BALANCE + 1, 1);
    bytes memory signature = _signIntent(intent);

    vm.expectRevert(SweepAccount.InsufficientBalance.selector);
    sweepAccount.executeSweep(intent, signature);
  }
}

contract SweepAccountTest_ExecuteBatchSweep is SweepAccountTest {
  function test_ExecuteBatchSweep() public {
    uint256[] memory amounts = new uint256[](3);
    amounts[0] = 100 ether;
    amounts[1] = 200 ether;
    amounts[2] = 50 ether;

    SweepAccount.SweepIntent[] memory intents = new SweepAccount.SweepIntent[](3);
    bytes[] memory signatures = new bytes[](3);

    for (uint256 i = 0; i < 3; i++) {
      intents[i] = _createIntent(address(token), amounts[i], i + 1);
      signatures[i] = _signIntent(intents[i]);
    }

    sweepAccount.executeBatchSweep(intents, signatures);

    uint256 totalSwept = amounts[0] + amounts[1] + amounts[2];
    assertEq(token.balanceOf(recipient), totalSwept);
    assertEq(token.balanceOf(address(sweepAccount)), INITIAL_BALANCE - totalSwept);

    for (uint256 i = 0; i < 3; i++) {
      assertTrue(sweepAccount.isNonceUsed(i + 1));
    }
  }

  function test_RevertWhen_MismatchedArrayLengths() public {
    SweepAccount.SweepIntent[] memory intents = new SweepAccount.SweepIntent[](2);
    bytes[] memory signatures = new bytes[](1);

    intents[0] = _createIntent(address(token), 100 ether, 1);
    intents[1] = _createIntent(address(token), 200 ether, 2);
    signatures[0] = _signIntent(intents[0]);

    vm.expectRevert(SweepAccount.InvalidSignature.selector);
    sweepAccount.executeBatchSweep(intents, signatures);
  }
}

contract SweepAccountTest_Execute is SweepAccountTest {
  function test_ExecuteAsOwner() public {
    address target = address(token);
    uint256 value = 0;
    bytes memory data = abi.encodeWithSelector(token.transfer.selector, recipient, 100 ether);

    address[] memory targets = new address[](1);
    uint256[] memory values = new uint256[](1);
    bytes[] memory calldatas = new bytes[](1);

    targets[0] = target;
    values[0] = value;
    calldatas[0] = data;

    bytes memory calls = abi.encode(targets, values, calldatas);

    vm.prank(owner);
    sweepAccount.execute(calls);

    assertEq(token.balanceOf(recipient), 100 ether);
  }

  function test_RevertWhen_ExecuteAsNonOwner() public {
    address target = address(token);
    uint256 value = 0;
    bytes memory data = abi.encodeWithSelector(token.transfer.selector, recipient, 100 ether);

    address[] memory targets = new address[](1);
    uint256[] memory values = new uint256[](1);
    bytes[] memory calldatas = new bytes[](1);

    targets[0] = target;
    values[0] = value;
    calldatas[0] = data;

    bytes memory calls = abi.encode(targets, values, calldatas);

    vm.prank(address(0x9999));
    vm.expectRevert(SweepAccount.UnauthorizedCaller.selector);
    sweepAccount.execute(calls);
  }
}

contract SweepAccountTest_ShieldedPool is SweepAccountTest {
  function test_SweepToShieldedPool() public {
    uint256 sweepAmount = 100 ether;
    uint256 nonce = 1;
    
    // First approve the shielded pool to spend tokens
    SweepAccount.SweepIntent memory approveIntent = SweepAccount.SweepIntent({
      token: address(token),
      recipient: address(sweepAccount), // Keep in account for approval
      amount: 0,
      nonce: nonce,
      expiry: 0
    });
    
    // Prepare the sweep intent to send to shielded pool
    SweepAccount.SweepIntent memory sweepIntent = _createIntent(address(token), sweepAmount, nonce);
    sweepIntent.recipient = address(shieldedPool);
    bytes memory signature = _signIntent(sweepIntent);
    
    // Record initial balances
    uint256 shieldedPoolBalanceBefore = token.balanceOf(address(shieldedPool));
    uint256 sweepAccountBalanceBefore = token.balanceOf(address(sweepAccount));
    
    // Execute sweep to shielded pool
    vm.expectEmit(true, true, false, true);
    emit TokensSwept(address(token), address(shieldedPool), sweepAmount, nonce);
    
    sweepAccount.executeSweep(sweepIntent, signature);
    
    // Verify the sweep was successful
    assertEq(token.balanceOf(address(shieldedPool)), shieldedPoolBalanceBefore + sweepAmount);
    assertEq(token.balanceOf(address(sweepAccount)), sweepAccountBalanceBefore - sweepAmount);
    assertTrue(sweepAccount.isNonceUsed(nonce));
  }
  
  function test_SweepETHToShieldedPool() public {
    uint256 sweepAmount = 1 ether;
    uint256 nonce = 1;
    
    // Prepare sweep intent for ETH
    SweepAccount.SweepIntent memory sweepIntent = _createIntent(address(0), sweepAmount, nonce);
    sweepIntent.recipient = address(shieldedPool);
    bytes memory signature = _signIntent(sweepIntent);
    
    // Record initial balances
    uint256 shieldedPoolETHBefore = address(shieldedPool).balance;
    uint256 sweepAccountETHBefore = address(sweepAccount).balance;
    
    // Execute sweep
    vm.expectEmit(true, true, false, true);
    emit TokensSwept(address(0), address(shieldedPool), sweepAmount, nonce);
    
    sweepAccount.executeSweep(sweepIntent, signature);
    
    // Verify ETH was swept to shielded pool
    assertEq(address(shieldedPool).balance, shieldedPoolETHBefore + sweepAmount);
    assertEq(address(sweepAccount).balance, sweepAccountETHBefore - sweepAmount);
    assertTrue(sweepAccount.isNonceUsed(nonce));
  }
  
  function test_SweepAndDepositToShieldedPool() public {
    uint256 sweepAmount = 50 ether;
    uint256 depositAmount = 10 ether;
    uint256 sweepNonce = 1;
    
    // First, sweep tokens to shielded pool
    SweepAccount.SweepIntent memory sweepIntent = _createIntent(address(token), sweepAmount, sweepNonce);
    sweepIntent.recipient = address(shieldedPool);
    bytes memory signature = _signIntent(sweepIntent);
    
    sweepAccount.executeSweep(sweepIntent, signature);
    
    // Now the shielded pool has tokens, let's simulate a deposit
    // This would normally be done by a user, but we'll do it from the test
    token.mint(address(this), depositAmount);
    token.approve(address(shieldedPool), depositAmount);
    
    // Generate commitment for deposit
    bytes32 commitment = keccak256(abi.encodePacked("secret", "nullifier", block.timestamp));
    bytes32 encryptedNote = keccak256(abi.encodePacked("encrypted", commitment));
    
    // Deposit to shielded pool
    shieldedPool.deposit(address(token), depositAmount, commitment, encryptedNote);
    
    // Verify pool balance increased
    assertEq(shieldedPool.getPoolBalance(address(token)), depositAmount);
    assertEq(token.balanceOf(address(shieldedPool)), sweepAmount + depositAmount);
  }
  
  function test_BatchSweepToMultipleRecipients() public {
    // Create multiple recipients including shielded pool
    address[] memory recipients = new address[](3);
    recipients[0] = address(shieldedPool);
    recipients[1] = address(0x1234);
    recipients[2] = address(0x5678);
    
    uint256[] memory amounts = new uint256[](3);
    amounts[0] = 30 ether;
    amounts[1] = 20 ether;
    amounts[2] = 10 ether;
    
    SweepAccount.SweepIntent[] memory intents = new SweepAccount.SweepIntent[](3);
    bytes[] memory signatures = new bytes[](3);
    
    for (uint256 i = 0; i < 3; i++) {
      intents[i] = SweepAccount.SweepIntent({
        token: address(token),
        recipient: recipients[i],
        amount: amounts[i],
        nonce: i + 1,
        expiry: 0
      });
      signatures[i] = _signIntent(intents[i]);
    }
    
    // Execute batch sweep
    sweepAccount.executeBatchSweep(intents, signatures);
    
    // Verify all recipients received their amounts
    assertEq(token.balanceOf(address(shieldedPool)), amounts[0]);
    assertEq(token.balanceOf(recipients[1]), amounts[1]);
    assertEq(token.balanceOf(recipients[2]), amounts[2]);
    
    // Verify nonces used
    for (uint256 i = 0; i < 3; i++) {
      assertTrue(sweepAccount.isNonceUsed(i + 1));
    }
  }
}

contract SweepAccountTest_Fuzz is SweepAccountTest {
  function testFuzz_ExecuteSweepVariousAmounts(uint256 amount) public {
    vm.assume(amount > 0 && amount <= INITIAL_BALANCE);
    uint256 nonce = 1;

    SweepAccount.SweepIntent memory intent = _createIntent(address(token), amount, nonce);
    bytes memory signature = _signIntent(intent);

    sweepAccount.executeSweep(intent, signature);

    assertEq(token.balanceOf(recipient), amount);
    assertEq(token.balanceOf(address(sweepAccount)), INITIAL_BALANCE - amount);
    assertTrue(sweepAccount.isNonceUsed(nonce));
  }

  function testFuzz_ExecuteSweepVariousNonces(uint256 nonce) public {
    vm.assume(nonce > 0);
    uint256 amount = 100 ether;

    SweepAccount.SweepIntent memory intent = _createIntent(address(token), amount, nonce);
    bytes memory signature = _signIntent(intent);

    sweepAccount.executeSweep(intent, signature);

    assertTrue(sweepAccount.isNonceUsed(nonce));
  }

  function testFuzz_ExecuteSweepVariousRecipients(address randomRecipient) public {
    vm.assume(randomRecipient != address(0));
    uint256 amount = 100 ether;

    SweepAccount.SweepIntent memory intent = SweepAccount.SweepIntent({
      token: address(token),
      recipient: randomRecipient,
      amount: amount,
      nonce: 1,
      expiry: 0
    });
    bytes memory signature = _signIntent(intent);

    sweepAccount.executeSweep(intent, signature);

    assertEq(token.balanceOf(randomRecipient), amount);
  }

  function testFuzz_ExecuteSweepWithExpiry(uint256 expiry) public {
    vm.assume(expiry > block.timestamp);
    uint256 amount = 100 ether;

    SweepAccount.SweepIntent memory intent = SweepAccount.SweepIntent({
      token: address(token),
      recipient: recipient,
      amount: amount,
      nonce: 1,
      expiry: expiry
    });
    bytes memory signature = _signIntent(intent);

    sweepAccount.executeSweep(intent, signature);

    assertEq(token.balanceOf(recipient), amount);
  }
}
