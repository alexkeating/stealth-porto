// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "src/ShieldedPool.sol";
import {ERC20Mock} from "openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";

contract ShieldedPoolTest is Test {
  ShieldedPool public pool;
  ERC20Mock public token;

  address public alice = address(0x1);
  address public bob = address(0x2);
  address public relayer = address(0x3);

  uint256 public constant INITIAL_BALANCE = 100 ether;
  uint256 public constant DEPOSIT_AMOUNT = 1 ether;

  bytes32 public commitment = keccak256("test_commitment");
  bytes32 public nullifier = keccak256("test_nullifier");
  bytes32 public encryptedNote = keccak256("encrypted_note");

  event Deposit(
    bytes32 indexed commitment,
    address indexed token,
    uint256 amount,
    bytes32 encryptedNote
  );

  event Withdrawal(
    bytes32 indexed nullifier,
    address indexed token,
    address indexed recipient,
    uint256 amount,
    uint256 relayerFee
  );

  function setUp() public virtual {
    pool = new ShieldedPool();
    token = new ERC20Mock();

    token.mint(alice, INITIAL_BALANCE);
    vm.deal(alice, INITIAL_BALANCE);
    vm.deal(bob, INITIAL_BALANCE);

    vm.prank(alice);
    token.approve(address(pool), type(uint256).max);
  }
}

contract ShieldedPoolTest_Deposit is ShieldedPoolTest {
  function test_DepositETH() public {
    uint256 aliceBalanceBefore = alice.balance;

    vm.expectEmit(true, true, false, true);
    emit Deposit(commitment, address(0), DEPOSIT_AMOUNT, encryptedNote);

    vm.prank(alice);
    pool.deposit{value: DEPOSIT_AMOUNT}(address(0), DEPOSIT_AMOUNT, commitment, encryptedNote);

    assertEq(alice.balance, aliceBalanceBefore - DEPOSIT_AMOUNT);
    assertEq(pool.getPoolBalance(address(0)), DEPOSIT_AMOUNT);
    
    (bytes32 noteCommitment, uint256 amount, address tokenAddr, uint256 timestamp) = pool.commitments(commitment);
    assertEq(noteCommitment, commitment);
    assertEq(amount, DEPOSIT_AMOUNT);
    assertEq(tokenAddr, address(0));
    assertGt(timestamp, 0);
  }

  function test_DepositERC20() public {
    uint256 aliceBalanceBefore = token.balanceOf(alice);

    vm.expectEmit(true, true, false, true);
    emit Deposit(commitment, address(token), DEPOSIT_AMOUNT, encryptedNote);

    vm.prank(alice);
    pool.deposit(address(token), DEPOSIT_AMOUNT, commitment, encryptedNote);

    assertEq(token.balanceOf(alice), aliceBalanceBefore - DEPOSIT_AMOUNT);
    assertEq(token.balanceOf(address(pool)), DEPOSIT_AMOUNT);
    assertEq(pool.getPoolBalance(address(token)), DEPOSIT_AMOUNT);
  }

  function test_RevertWhen_DepositAmountTooSmall() public {
    vm.expectRevert(ShieldedPool.InvalidAmount.selector);
    vm.prank(alice);
    pool.deposit{value: 0.0001 ether}(address(0), 0.0001 ether, commitment, encryptedNote);
  }

  function test_RevertWhen_DepositAmountTooLarge() public {
    // Give alice enough balance for the large deposit
    vm.deal(alice, 200 ether);
    
    vm.expectRevert(ShieldedPool.InvalidAmount.selector);
    vm.prank(alice);
    pool.deposit{value: 101 ether}(address(0), 101 ether, commitment, encryptedNote);
  }

  function test_RevertWhen_CommitmentAlreadyExists() public {
    vm.prank(alice);
    pool.deposit{value: DEPOSIT_AMOUNT}(address(0), DEPOSIT_AMOUNT, commitment, encryptedNote);

    vm.expectRevert(ShieldedPool.InvalidCommitment.selector);
    vm.prank(alice);
    pool.deposit{value: DEPOSIT_AMOUNT}(address(0), DEPOSIT_AMOUNT, commitment, encryptedNote);
  }

  function test_RevertWhen_InvalidCommitment() public {
    vm.expectRevert(ShieldedPool.InvalidCommitment.selector);
    vm.prank(alice);
    pool.deposit{value: DEPOSIT_AMOUNT}(address(0), DEPOSIT_AMOUNT, bytes32(0), encryptedNote);
  }

  function test_RevertWhen_ETHAmountMismatch() public {
    vm.expectRevert(ShieldedPool.InvalidAmount.selector);
    vm.prank(alice);
    pool.deposit{value: 0.5 ether}(address(0), DEPOSIT_AMOUNT, commitment, encryptedNote);
  }

  function test_RevertWhen_SendingETHForERC20() public {
    vm.expectRevert(ShieldedPool.InvalidAmount.selector);
    vm.prank(alice);
    pool.deposit{value: DEPOSIT_AMOUNT}(address(token), DEPOSIT_AMOUNT, commitment, encryptedNote);
  }
}

contract ShieldedPoolTest_Withdraw is ShieldedPoolTest {
  function setUp() public override {
    super.setUp();
    
    vm.prank(alice);
    pool.deposit{value: DEPOSIT_AMOUNT}(address(0), DEPOSIT_AMOUNT, commitment, encryptedNote);
  }

  function test_WithdrawETH() public {
    uint256 bobBalanceBefore = bob.balance;
    bytes memory proof = pool.generateMockProof(address(0), DEPOSIT_AMOUNT, nullifier, bob);

    vm.expectEmit(true, true, true, true);
    emit Withdrawal(nullifier, address(0), bob, DEPOSIT_AMOUNT, 0);

    pool.withdraw(address(0), DEPOSIT_AMOUNT, nullifier, bob, address(0), 0, proof);

    assertEq(bob.balance, bobBalanceBefore + DEPOSIT_AMOUNT);
    assertEq(pool.getPoolBalance(address(0)), 0);
    assertTrue(pool.isSpent(nullifier));
  }

  function test_WithdrawERC20() public {
    vm.prank(alice);
    pool.deposit(address(token), DEPOSIT_AMOUNT, keccak256("commitment2"), encryptedNote);

    uint256 bobBalanceBefore = token.balanceOf(bob);
    bytes memory proof = pool.generateMockProof(address(token), DEPOSIT_AMOUNT, nullifier, bob);

    pool.withdraw(address(token), DEPOSIT_AMOUNT, nullifier, bob, address(0), 0, proof);

    assertEq(token.balanceOf(bob), bobBalanceBefore + DEPOSIT_AMOUNT);
    assertEq(pool.getPoolBalance(address(token)), 0);
    assertTrue(pool.isSpent(nullifier));
  }

  function test_WithdrawWithRelayer() public {
    uint256 relayerFee = 0.01 ether;
    uint256 bobBalanceBefore = bob.balance;
    uint256 relayerBalanceBefore = relayer.balance;

    bytes memory proof = pool.generateMockProof(address(0), DEPOSIT_AMOUNT, nullifier, bob);

    pool.withdraw(address(0), DEPOSIT_AMOUNT, nullifier, bob, relayer, relayerFee, proof);

    assertEq(bob.balance, bobBalanceBefore + DEPOSIT_AMOUNT - relayerFee);
    assertEq(relayer.balance, relayerBalanceBefore + relayerFee);
    assertTrue(pool.isSpent(nullifier));
  }

  function test_RevertWhen_NullifierAlreadySpent() public {
    bytes memory proof = pool.generateMockProof(address(0), DEPOSIT_AMOUNT, nullifier, bob);
    
    pool.withdraw(address(0), DEPOSIT_AMOUNT, nullifier, bob, address(0), 0, proof);

    vm.expectRevert(ShieldedPool.NullifierAlreadySpent.selector);
    pool.withdraw(address(0), DEPOSIT_AMOUNT, nullifier, bob, address(0), 0, proof);
  }

  function test_RevertWhen_InvalidNullifier() public {
    bytes memory proof = pool.generateMockProof(address(0), DEPOSIT_AMOUNT, bytes32(0), bob);

    vm.expectRevert(ShieldedPool.InvalidNullifier.selector);
    pool.withdraw(address(0), DEPOSIT_AMOUNT, bytes32(0), bob, address(0), 0, proof);
  }

  function test_RevertWhen_InvalidProof() public {
    bytes memory invalidProof = abi.encode(keccak256("invalid"));

    vm.expectRevert(ShieldedPool.InvalidProof.selector);
    pool.withdraw(address(0), DEPOSIT_AMOUNT, nullifier, bob, address(0), 0, invalidProof);
  }

  function test_RevertWhen_InsufficientPoolBalance() public {
    bytes memory proof = pool.generateMockProof(address(0), DEPOSIT_AMOUNT, nullifier, bob);
    
    pool.withdraw(address(0), DEPOSIT_AMOUNT, nullifier, bob, address(0), 0, proof);

    bytes32 newNullifier = keccak256("new_nullifier");
    proof = pool.generateMockProof(address(0), DEPOSIT_AMOUNT, newNullifier, bob);

    vm.expectRevert(ShieldedPool.InsufficientPoolBalance.selector);
    pool.withdraw(address(0), DEPOSIT_AMOUNT, newNullifier, bob, address(0), 0, proof);
  }

  function test_RevertWhen_RelayerFeeTooHigh() public {
    uint256 excessiveFee = DEPOSIT_AMOUNT / 10;
    bytes memory proof = pool.generateMockProof(address(0), DEPOSIT_AMOUNT, nullifier, bob);

    vm.expectRevert(ShieldedPool.InvalidAmount.selector);
    pool.withdraw(address(0), DEPOSIT_AMOUNT, nullifier, bob, relayer, excessiveFee, proof);
  }
}

contract ShieldedPoolTest_Relayer is ShieldedPoolTest {
  function test_RegisterRelayer() public {
    uint256 fee = 100;

    vm.expectEmit(true, false, false, true);
    emit ShieldedPool.RelayerRegistered(relayer, fee);

    vm.prank(relayer);
    pool.registerRelayer(fee);

    assertEq(pool.relayerFees(relayer), fee);
  }

  function test_RevertWhen_RelayerFeeTooHigh() public {
    vm.expectRevert(ShieldedPool.InvalidAmount.selector);
    vm.prank(relayer);
    pool.registerRelayer(501);
  }
}

contract ShieldedPoolTest_Fuzz is ShieldedPoolTest {
  function testFuzz_DepositWithdrawCycle(
    uint256 amount,
    bytes32 commitmentFuzz,
    bytes32 nullifierFuzz,
    address recipient
  ) public {
    vm.assume(amount >= pool.MIN_DEPOSIT() && amount <= pool.MAX_DEPOSIT());
    vm.assume(commitmentFuzz != bytes32(0));
    vm.assume(nullifierFuzz != bytes32(0));
    vm.assume(recipient != address(0));

    vm.prank(alice);
    pool.deposit{value: amount}(address(0), amount, commitmentFuzz, encryptedNote);

    bytes memory proof = pool.generateMockProof(address(0), amount, nullifierFuzz, recipient);
    
    uint256 recipientBalanceBefore = recipient.balance;
    pool.withdraw(address(0), amount, nullifierFuzz, recipient, address(0), 0, proof);

    assertEq(recipient.balance, recipientBalanceBefore + amount);
    assertTrue(pool.isSpent(nullifierFuzz));
  }

  function testFuzz_MultipleDepositsWithdrawals(uint8 numOperations) public {
    vm.assume(numOperations > 0 && numOperations <= 10);

    uint256 totalDeposited = 0;
    uint256 totalWithdrawn = 0;

    for (uint256 i = 0; i < numOperations; i++) {
      bytes32 commitmentFuzz = keccak256(abi.encodePacked("commitment", i));
      bytes32 nullifierFuzz = keccak256(abi.encodePacked("nullifier", i));
      uint256 amount = 0.1 ether * (i + 1);

      vm.prank(alice);
      pool.deposit{value: amount}(address(0), amount, commitmentFuzz, encryptedNote);
      totalDeposited += amount;

      if (i % 2 == 0) {
        bytes memory proof = pool.generateMockProof(address(0), amount, nullifierFuzz, bob);
        pool.withdraw(address(0), amount, nullifierFuzz, bob, address(0), 0, proof);
        totalWithdrawn += amount;
      }
    }

    assertEq(pool.getPoolBalance(address(0)), totalDeposited - totalWithdrawn);
  }
}