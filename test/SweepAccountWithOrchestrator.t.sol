// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {SweepAccount} from "src/SweepAccount.sol";
import {ERC20Mock} from "openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import {Orchestrator} from "lib/account/src/Orchestrator.sol";
import {ICommon} from "lib/account/src/interfaces/ICommon.sol";
import {ERC7821} from "lib/account/lib/solady/src/accounts/ERC7821.sol";

/// @title SweepAccountWithOrchestratorTest
/// @notice Tests that execute SweepAccount operations through the Orchestrator
contract SweepAccountWithOrchestratorTest is Test {
  // Contracts
  Orchestrator public orchestrator;
  SweepAccount public sweepAccount;
  ERC20Mock public token;
  ERC20Mock public paymentToken;

  // Test accounts
  uint256 public constant OWNER_PRIVATE_KEY = 0x1234;
  address public owner;
  address public relayer = address(0x9999);
  address public recipient = address(0x2);
  
  // Constants
  uint256 public constant INITIAL_BALANCE = 1000 ether;

  // Events
  event TokensSwept(address indexed token, address indexed recipient, uint256 amount, uint256 nonce);

  function setUp() public {
    owner = vm.addr(OWNER_PRIVATE_KEY);
    
    // Deploy Orchestrator with no pause authority for testing
    orchestrator = new Orchestrator(address(0));
    
    // Deploy SweepAccount with orchestrator and owner
    sweepAccount = new SweepAccount(address(orchestrator), owner);
    
    // Deploy mock tokens
    token = new ERC20Mock();
    paymentToken = new ERC20Mock();
    
    // Fund the sweep account with tokens to sweep
    token.mint(address(sweepAccount), INITIAL_BALANCE);
    vm.deal(address(sweepAccount), INITIAL_BALANCE);
    
    // Fund sweep account with payment tokens for gas compensation
    paymentToken.mint(address(sweepAccount), INITIAL_BALANCE);
    
    // Fund relayer with ETH for gas
    vm.deal(relayer, 100 ether);
  }

  /// @notice Helper to create an Intent for the Orchestrator that executes a sweep
  function _createSweepIntent(
    address tokenToSweep,
    uint256 amount,
    uint256 sweepNonce,
    uint256 orchestratorNonce
  ) internal view returns (ICommon.Intent memory) {
    // First, create the sweep intent data
    SweepAccount.SweepIntent memory sweepIntent = SweepAccount.SweepIntent({
      token: tokenToSweep,
      recipient: recipient,
      amount: amount,
      nonce: sweepNonce,
      expiry: 0
    });
    
    // Sign the sweep intent with owner's key
    bytes memory sweepSignature = _signSweepIntent(sweepIntent);
    
    // Create the call to executeSweep
    bytes memory sweepCallData = abi.encodeWithSelector(
      SweepAccount.executeSweep.selector,
      sweepIntent,
      sweepSignature
    );
    
    // Wrap in ERC7821 Call format for the Orchestrator
    ERC7821.Call[] memory calls = new ERC7821.Call[](1);
    calls[0] = ERC7821.Call({
      to: address(sweepAccount),
      value: 0,
      data: sweepCallData
    });
    
    // Create the Orchestrator Intent - use SweepAccount as the EOA since it implements IthacaAccount
    return ICommon.Intent({
      eoa: address(sweepAccount),
      executionData: abi.encode(calls),
      nonce: orchestratorNonce,
      payer: address(sweepAccount),
      paymentToken: address(paymentToken),
      prePaymentMaxAmount: 0.1 ether,
      totalPaymentMaxAmount: 0.2 ether,
      combinedGas: 500_000,
      encodedPreCalls: new bytes[](0),
      encodedFundTransfers: new bytes[](0),
      settler: address(0),
      expiry: 0,
      isMultichain: false,
      funder: address(0),
      funderSignature: "",
      settlerContext: "",
      prePaymentAmount: 0.01 ether,
      totalPaymentAmount: 0.02 ether,
      paymentRecipient: relayer,
      signature: "", // Will be filled in by _signOrchestratorIntent
      paymentSignature: "",
      supportedAccountImplementation: address(0)
    });
  }

  /// @notice Sign a sweep intent with the owner's key
  function _signSweepIntent(
    SweepAccount.SweepIntent memory intent
  ) internal view returns (bytes memory) {
    bytes32 SWEEP_INTENT_TYPEHASH = keccak256(
      "SweepIntent(address token,address recipient,uint256 amount,uint256 nonce,uint256 expiry)"
    );
    
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
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("SweepAccount")),
        keccak256(bytes("1")),
        block.chainid,
        address(sweepAccount)
      )
    );
    
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PRIVATE_KEY, digest);
    return abi.encodePacked(r, s, v);
  }

  /// @notice Sign an Orchestrator Intent with the owner's key
  function _signOrchestratorIntent(
    ICommon.Intent memory intent
  ) internal view returns (bytes memory) {
    bytes32 digest = _computeOrchestratorDigest(intent);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PRIVATE_KEY, digest);
    
    // Get the actual keyHash that was stored during construction
    bytes32 keyHash = sweepAccount.getOwnerKeyHash();
    
    // Return signature with keyHash appended (IthacaAccount format)
    return abi.encodePacked(r, s, v, keyHash);
  }
  
  /// @notice Compute the digest for an Orchestrator Intent
  function _computeOrchestratorDigest(ICommon.Intent memory intent)
    internal
    view
    returns (bytes32)
  {
    // Use a simplified digest computation to avoid stack too deep
    // In production, you'd use the actual Orchestrator's computeDigest method
    return keccak256(abi.encode(intent));
  }
}

contract SweepAccountWithOrchestratorTest_BasicSweep is SweepAccountWithOrchestratorTest {
  
  function test_ExecuteSweepThroughOrchestrator() public {
    uint256 sweepAmount = 100 ether;
    uint256 sweepNonce = 1;
    uint256 orchestratorNonce = 0;
    
    // Create the intent
    ICommon.Intent memory intent = _createSweepIntent(
      address(token),
      sweepAmount,
      sweepNonce,
      orchestratorNonce
    );
    
    // Sign the orchestrator intent
    intent.signature = _signOrchestratorIntent(intent);
    
    // Record initial balances
    uint256 recipientBalanceBefore = token.balanceOf(recipient);
    uint256 sweepAccountBalanceBefore = token.balanceOf(address(sweepAccount));
    uint256 relayerPaymentBalanceBefore = paymentToken.balanceOf(relayer);
    
    // Execute through orchestrator as the relayer
    vm.expectEmit(true, true, false, true);
    emit TokensSwept(address(token), recipient, sweepAmount, sweepNonce);
    
    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    
    // Verify execution succeeded
    assertEq(uint32(err), 0, "Orchestrator execution failed");
    
    // Verify the sweep happened
    assertEq(token.balanceOf(recipient), recipientBalanceBefore + sweepAmount);
    assertEq(token.balanceOf(address(sweepAccount)), sweepAccountBalanceBefore - sweepAmount);
    assertTrue(sweepAccount.isNonceUsed(sweepNonce));
    
    // Verify gas payment happened
    assertGt(paymentToken.balanceOf(relayer), relayerPaymentBalanceBefore, "Relayer should be compensated");
  }
  
  function test_ExecuteETHSweepThroughOrchestrator() public {
    uint256 sweepAmount = 1 ether;
    uint256 sweepNonce = 1;
    uint256 orchestratorNonce = 0;
    
    // Create intent for ETH sweep
    ICommon.Intent memory intent = _createSweepIntent(
      address(0), // ETH
      sweepAmount,
      sweepNonce,
      orchestratorNonce
    );
    
    // Sign the orchestrator intent
    intent.signature = _signOrchestratorIntent(intent);
    
    // Record initial balances
    uint256 recipientETHBefore = recipient.balance;
    uint256 sweepAccountETHBefore = address(sweepAccount).balance;
    
    // Execute through orchestrator
    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    
    // Verify execution succeeded
    assertEq(uint32(err), 0, "Orchestrator execution failed");
    
    // Verify ETH was swept
    assertEq(recipient.balance, recipientETHBefore + sweepAmount);
    assertEq(address(sweepAccount).balance, sweepAccountETHBefore - sweepAmount);
    assertTrue(sweepAccount.isNonceUsed(sweepNonce));
  }
}

contract SweepAccountWithOrchestratorTest_BatchOperations is SweepAccountWithOrchestratorTest {
  
  function test_ExecuteBatchSweepsThroughOrchestrator() public {
    // Create multiple sweep intents within a single orchestrator intent
    uint256[] memory amounts = new uint256[](3);
    amounts[0] = 10 ether;
    amounts[1] = 20 ether;
    amounts[2] = 30 ether;
    
    // Build the batch of calls
    ERC7821.Call[] memory calls = new ERC7821.Call[](3);
    
    for (uint256 i = 0; i < 3; i++) {
      SweepAccount.SweepIntent memory sweepIntent = SweepAccount.SweepIntent({
        token: address(token),
        recipient: recipient,
        amount: amounts[i],
        nonce: i + 1,
        expiry: 0
      });
      
      bytes memory sweepSignature = _signSweepIntent(sweepIntent);
      
      calls[i] = ERC7821.Call({
        to: address(sweepAccount),
        value: 0,
        data: abi.encodeWithSelector(
          SweepAccount.executeSweep.selector,
          sweepIntent,
          sweepSignature
        )
      });
    }
    
    // Create the orchestrator intent with all calls
    ICommon.Intent memory intent = ICommon.Intent({
      eoa: address(sweepAccount),
      executionData: abi.encode(calls),
      nonce: 0,
      payer: address(sweepAccount),
      paymentToken: address(paymentToken),
      prePaymentMaxAmount: 0.1 ether,
      totalPaymentMaxAmount: 0.2 ether,
      combinedGas: 1_000_000,
      encodedPreCalls: new bytes[](0),
      encodedFundTransfers: new bytes[](0),
      settler: address(0),
      expiry: 0,
      isMultichain: false,
      funder: address(0),
      funderSignature: "",
      settlerContext: "",
      prePaymentAmount: 0.01 ether,
      totalPaymentAmount: 0.02 ether,
      paymentRecipient: relayer,
      signature: "",
      paymentSignature: "",
      supportedAccountImplementation: address(0)
    });
    
    // Sign the orchestrator intent
    intent.signature = _signOrchestratorIntent(intent);
    
    // Execute through orchestrator
    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    
    // Verify execution succeeded
    assertEq(uint32(err), 0, "Orchestrator execution failed");
    
    // Verify all sweeps happened
    uint256 totalSwept = amounts[0] + amounts[1] + amounts[2];
    assertEq(token.balanceOf(recipient), totalSwept);
    assertEq(token.balanceOf(address(sweepAccount)), INITIAL_BALANCE - totalSwept);
    
    // Check all nonces were used
    for (uint256 i = 0; i < 3; i++) {
      assertTrue(sweepAccount.isNonceUsed(i + 1));
    }
  }
  
  function test_ExecuteMixedOperationsThroughOrchestrator() public {
    // Mix sweep operations with direct transfers
    ERC7821.Call[] memory calls = new ERC7821.Call[](2);
    
    // Call 1: Sweep tokens
    SweepAccount.SweepIntent memory sweepIntent = SweepAccount.SweepIntent({
      token: address(token),
      recipient: recipient,
      amount: 50 ether,
      nonce: 1,
      expiry: 0
    });
    
    bytes memory sweepSignature = _signSweepIntent(sweepIntent);
    
    calls[0] = ERC7821.Call({
      to: address(sweepAccount),
      value: 0,
      data: abi.encodeWithSelector(
        SweepAccount.executeSweep.selector,
        sweepIntent,
        sweepSignature
      )
    });
    
    // Call 2: Direct execute call (transfer remaining tokens)
    address[] memory targets = new address[](1);
    uint256[] memory values = new uint256[](1);
    bytes[] memory calldatas = new bytes[](1);
    
    targets[0] = address(token);
    values[0] = 0;
    calldatas[0] = abi.encodeWithSelector(token.transfer.selector, address(0x3333), 25 ether);
    
    calls[1] = ERC7821.Call({
      to: address(sweepAccount),
      value: 0,
      data: abi.encodeWithSelector(
        SweepAccount.execute.selector,
        abi.encode(targets, values, calldatas)
      )
    });
    
    // Create orchestrator intent
    ICommon.Intent memory intent = ICommon.Intent({
      eoa: address(sweepAccount),
      executionData: abi.encode(calls),
      nonce: 0,
      payer: address(sweepAccount),
      paymentToken: address(paymentToken),
      prePaymentMaxAmount: 0.1 ether,
      totalPaymentMaxAmount: 0.2 ether,
      combinedGas: 800_000,
      encodedPreCalls: new bytes[](0),
      encodedFundTransfers: new bytes[](0),
      settler: address(0),
      expiry: 0,
      isMultichain: false,
      funder: address(0),
      funderSignature: "",
      settlerContext: "",
      prePaymentAmount: 0.01 ether,
      totalPaymentAmount: 0.02 ether,
      paymentRecipient: relayer,
      signature: "",
      paymentSignature: "",
      supportedAccountImplementation: address(0)
    });
    
    intent.signature = _signOrchestratorIntent(intent);
    
    // Execute through orchestrator
    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    
    // Verify execution succeeded
    assertEq(uint32(err), 0, "Orchestrator execution failed");
    
    // Verify both operations happened
    assertEq(token.balanceOf(recipient), 50 ether);
    assertEq(token.balanceOf(address(0x3333)), 25 ether);
    assertTrue(sweepAccount.isNonceUsed(1));
  }
}

contract SweepAccountWithOrchestratorTest_GasPayment is SweepAccountWithOrchestratorTest {
  
  function test_GasCompensationFlow() public {
    uint256 sweepAmount = 100 ether;
    
    // Create and sign intent
    ICommon.Intent memory intent = _createSweepIntent(address(token), sweepAmount, 1, 0);
    intent.signature = _signOrchestratorIntent(intent);
    
    // Set specific payment amounts
    intent.prePaymentAmount = 0.05 ether;
    intent.totalPaymentAmount = 0.1 ether;
    
    // Record balances before
    uint256 sweepAccountPaymentBefore = paymentToken.balanceOf(address(sweepAccount));
    uint256 relayerPaymentBefore = paymentToken.balanceOf(relayer);
    
    // Execute as relayer
    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    
    assertEq(uint32(err), 0, "Orchestrator execution failed");
    
    // Verify payment was made from sweep account to relayer
    uint256 sweepAccountPaymentAfter = paymentToken.balanceOf(address(sweepAccount));
    uint256 relayerPaymentAfter = paymentToken.balanceOf(relayer);
    
    assertLt(sweepAccountPaymentAfter, sweepAccountPaymentBefore, "SweepAccount should pay for gas");
    assertGt(relayerPaymentAfter, relayerPaymentBefore, "Relayer should receive payment");
    
    // Payment should be within bounds
    uint256 totalPayment = sweepAccountPaymentBefore - sweepAccountPaymentAfter;
    assertLe(totalPayment, intent.totalPaymentMaxAmount, "Payment should not exceed max");
  }
  
  function test_RevertWhen_InsufficientGasPayment() public {
    // Create intent but don't fund sweep account with enough payment tokens
    vm.prank(address(sweepAccount));
    paymentToken.transfer(address(0xdead), paymentToken.balanceOf(address(sweepAccount))); // Empty balance
    
    ICommon.Intent memory intent = _createSweepIntent(address(token), 100 ether, 1, 0);
    intent.signature = _signOrchestratorIntent(intent);
    
    // Should fail due to insufficient payment
    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    
    // Verify it failed (non-zero error code)
    assertGt(uint32(err), 0, "Should fail with insufficient payment");
  }
}

contract SweepAccountWithOrchestratorTest_Fuzz is SweepAccountWithOrchestratorTest {
  
  function testFuzz_ExecuteSweepsThroughOrchestrator(
    uint256 amount,
    uint256 sweepNonce,
    uint256 orchNonce
  ) public {
    amount = bound(amount, 1, INITIAL_BALANCE);
    sweepNonce = bound(sweepNonce, 1, type(uint256).max);
    orchNonce = bound(orchNonce, 0, type(uint256).max);
    
    ICommon.Intent memory intent = _createSweepIntent(address(token), amount, sweepNonce, orchNonce);
    intent.signature = _signOrchestratorIntent(intent);
    
    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    
    assertEq(uint32(err), 0, "Orchestrator execution failed");
    assertEq(token.balanceOf(recipient), amount);
    assertTrue(sweepAccount.isNonceUsed(sweepNonce));
  }
  
  function testFuzz_BatchSweepsThroughOrchestrator(uint8 numSweeps) public {
    numSweeps = uint8(bound(numSweeps, 1, 10));
    uint256 amountPerSweep = INITIAL_BALANCE / numSweeps;
    
    ERC7821.Call[] memory calls = new ERC7821.Call[](numSweeps);
    
    for (uint256 i = 0; i < numSweeps; i++) {
      uint256 amount = i == numSweeps - 1 
        ? INITIAL_BALANCE - (amountPerSweep * (numSweeps - 1))
        : amountPerSweep;
      
      SweepAccount.SweepIntent memory sweepIntent = SweepAccount.SweepIntent({
        token: address(token),
        recipient: recipient,
        amount: amount,
        nonce: i + 1,
        expiry: 0
      });
      
      bytes memory sweepSignature = _signSweepIntent(sweepIntent);
      
      calls[i] = ERC7821.Call({
        to: address(sweepAccount),
        value: 0,
        data: abi.encodeWithSelector(
          SweepAccount.executeSweep.selector,
          sweepIntent,
          sweepSignature
        )
      });
    }
    
    ICommon.Intent memory intent = ICommon.Intent({
      eoa: address(sweepAccount),
      executionData: abi.encode(calls),
      nonce: 0,
      payer: address(sweepAccount),
      paymentToken: address(paymentToken),
      prePaymentMaxAmount: 0.5 ether,
      totalPaymentMaxAmount: 1 ether,
      combinedGas: 2_000_000,
      encodedPreCalls: new bytes[](0),
      encodedFundTransfers: new bytes[](0),
      settler: address(0),
      expiry: 0,
      isMultichain: false,
      funder: address(0),
      funderSignature: "",
      settlerContext: "",
      prePaymentAmount: 0.01 ether,
      totalPaymentAmount: 0.02 ether,
      paymentRecipient: relayer,
      signature: "",
      paymentSignature: "",
      supportedAccountImplementation: address(0)
    });
    
    intent.signature = _signOrchestratorIntent(intent);
    
    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    
    assertEq(uint32(err), 0);
    assertEq(token.balanceOf(recipient), INITIAL_BALANCE);
    assertEq(token.balanceOf(address(sweepAccount)), 0);
  }
}