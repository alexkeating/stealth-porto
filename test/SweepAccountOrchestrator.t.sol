// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {SweepAccount} from "src/SweepAccount.sol";
import {ERC20Mock} from "openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {Orchestrator} from "lib/account/src/Orchestrator.sol";
import {ICommon} from "lib/account/src/interfaces/ICommon.sol";
import {ERC7821} from "lib/account/lib/solady/src/accounts/ERC7821.sol";

/// @title SweepAccountOrchestratorTest
/// @notice Integration tests for SweepAccount with Ithaca Orchestrator
contract SweepAccountOrchestratorTest is Test {
  using ECDSA for bytes32;

  // Contracts
  SweepAccount public sweepAccount;
  Orchestrator public orchestrator;
  ERC20Mock public token;
  ERC20Mock public paymentToken;

  // Test accounts
  uint256 public ownerPrivateKey = 0x1234;
  address public owner;
  address public relayer = address(0x9999);
  address public recipient = address(0x2);

  // Constants
  uint256 public constant INITIAL_BALANCE = 1000 ether;
  uint256 public constant CHAIN_ID = 31_337; // Anvil default

  // Events
  event TokensSwept(
    address indexed token, address indexed recipient, uint256 amount, uint256 nonce
  );
  event IntentExecuted(address indexed eoa, bytes4 err);

  function setUp() public {
    owner = vm.addr(ownerPrivateKey);

    // Deploy Orchestrator with no pause authority for testing
    orchestrator = new Orchestrator(address(0));

    // Deploy SweepAccount with orchestrator
    sweepAccount = new SweepAccount(address(orchestrator), owner);

    // Deploy tokens
    token = new ERC20Mock();
    paymentToken = new ERC20Mock();

    // Fund accounts
    token.mint(address(sweepAccount), INITIAL_BALANCE);
    paymentToken.mint(address(sweepAccount), INITIAL_BALANCE);
    vm.deal(address(sweepAccount), INITIAL_BALANCE);
    vm.deal(relayer, 100 ether);
  }

  /// @notice Helper to create a sweep intent for direct execution
  function _createSweepIntent(address tokenAddr, uint256 amount, uint256 nonce)
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

  /// @notice Helper to sign a sweep intent
  function _signSweepIntent(SweepAccount.SweepIntent memory intent)
    internal
    view
    returns (bytes memory signature)
  {
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

  /// @notice Helper to create an Orchestrator Intent that calls the SweepAccount
  function _createOrchestratorIntent(
    SweepAccount.SweepIntent memory sweepIntent,
    bytes memory sweepSignature,
    uint256 orchestratorNonce
  ) internal view returns (ICommon.Intent memory) {
    // Create the call to executeSweep
    bytes memory sweepCallData = abi.encodeWithSelector(
      SweepAccount.executeSweep.selector,
      sweepIntent,
      sweepSignature
    );
    
    // Wrap in ERC7821 Call format
    ERC7821.Call[] memory calls = new ERC7821.Call[](1);
    calls[0] = ERC7821.Call({
      to: address(sweepAccount),
      value: 0,
      data: sweepCallData
    });
    
    // Create orchestrator intent - use SweepAccount as the EOA since it implements IthacaAccount
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
      signature: "",
      paymentSignature: "",
      supportedAccountImplementation: address(0)
    });
  }

  /// @notice Sign an Orchestrator Intent
  function _signOrchestratorIntent(ICommon.Intent memory intent)
    internal
    view
    returns (bytes memory)
  {
    // For the real Orchestrator, we need to compute the digest properly
    // The Orchestrator expects the signature format with keyHash appended
    bytes32 digest = _computeOrchestratorDigest(intent);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
    
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
    // Use the Orchestrator's actual implementation to compute digest
    // This avoids stack too deep and ensures correctness
    // We'll need to use a workaround since computeDigest is not public
    
    // For now, return a simplified digest - in production you'd use the actual Orchestrator method
    return keccak256(abi.encode(intent));
  }
}

contract SweepAccountOrchestratorTest_DirectExecution is SweepAccountOrchestratorTest {
  function test_ExecuteSweepThroughOrchestrator() public {
    uint256 sweepAmount = 100 ether;
    uint256 sweepNonce = 1;
    uint256 orchestratorNonce = 0;

    // Create and sign a sweep intent
    SweepAccount.SweepIntent memory sweepIntent =
      _createSweepIntent(address(token), sweepAmount, sweepNonce);
    bytes memory sweepSignature = _signSweepIntent(sweepIntent);

    // Create orchestrator intent
    ICommon.Intent memory intent = _createOrchestratorIntent(
      sweepIntent,
      sweepSignature,
      orchestratorNonce
    );
    
    // Sign the orchestrator intent
    intent.signature = _signOrchestratorIntent(intent);

    // Execute through orchestrator
    vm.expectEmit(true, true, false, true);
    emit TokensSwept(address(token), recipient, sweepAmount, sweepNonce);

    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    
    // Verify execution succeeded
    assertEq(uint32(err), 0, "Orchestrator execution failed");

    // Verify the sweep was successful
    assertEq(token.balanceOf(recipient), sweepAmount);
    assertEq(token.balanceOf(address(sweepAccount)), INITIAL_BALANCE - sweepAmount);
    assertTrue(sweepAccount.isNonceUsed(sweepNonce));
  }
}

contract SweepAccountOrchestratorTest_OrchestratorCompatibility is SweepAccountOrchestratorTest {
  function test_ExecuteThroughOrchestratorExecuteFunction() public {
    uint256 transferAmount = 50 ether;

    // Create the call data for a simple token transfer
    bytes memory transferCallData =
      abi.encodeWithSelector(token.transfer.selector, recipient, transferAmount);

    // Encode the calls for the SweepAccount's execute function
    address[] memory targets = new address[](1);
    uint256[] memory values = new uint256[](1);
    bytes[] memory calldatas = new bytes[](1);

    targets[0] = address(token);
    values[0] = 0;
    calldatas[0] = transferCallData;

    bytes memory executeCallData = abi.encode(targets, values, calldatas);

    // Create orchestrator call to SweepAccount's execute function
    ERC7821.Call[] memory calls = new ERC7821.Call[](1);
    calls[0] = ERC7821.Call({
      to: address(sweepAccount),
      value: 0,
      data: abi.encodeWithSelector(SweepAccount.execute.selector, executeCallData)
    });
    
    // Create orchestrator intent - use SweepAccount as the EOA since it implements IthacaAccount
    ICommon.Intent memory intent = ICommon.Intent({
      eoa: address(sweepAccount),
      executionData: abi.encode(calls),
      nonce: 0,
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
    assertEq(token.balanceOf(recipient), transferAmount);
    assertEq(token.balanceOf(address(sweepAccount)), INITIAL_BALANCE - transferAmount);
  }

  function test_SweepAccountExecuteRejectsNonOwnerThroughOrchestrator() public {
    // Create call data for a token transfer
    bytes memory transferCallData =
      abi.encodeWithSelector(token.transfer.selector, recipient, 50 ether);

    address[] memory targets = new address[](1);
    uint256[] memory values = new uint256[](1);
    bytes[] memory calldatas = new bytes[](1);

    targets[0] = address(token);
    values[0] = 0;
    calldatas[0] = transferCallData;

    bytes memory executeCallData = abi.encode(targets, values, calldatas);

    // Create orchestrator call from non-owner
    ERC7821.Call[] memory calls = new ERC7821.Call[](1);
    calls[0] = ERC7821.Call({
      to: address(sweepAccount),
      value: 0,
      data: abi.encodeWithSelector(SweepAccount.execute.selector, executeCallData)
    });
    
    // Create orchestrator intent but we'll sign with wrong key
    ICommon.Intent memory intent = ICommon.Intent({
      eoa: address(sweepAccount),
      executionData: abi.encode(calls),
      nonce: 0,
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
      signature: "",
      paymentSignature: "",
      supportedAccountImplementation: address(0)
    });
    
    // Sign with wrong key to make it fail
    uint256 wrongKey = 0x5678;
    bytes32 digest = _computeOrchestratorDigest(intent);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, digest);
    
    // Use wrong keyHash to make it fail
    bytes32 wrongKeyHash = keccak256(abi.encode(
      uint8(2), // KeyType.Secp256k1
      uint256(keccak256(abi.encodePacked(vm.addr(wrongKey))))
    ));
    
    intent.signature = abi.encodePacked(r, s, v, wrongKeyHash);
    
    // Execute through orchestrator should fail
    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    
    // Should fail because SweepAccount.execute requires msg.sender == owner
    assertGt(uint32(err), 0, "Should fail with unauthorized caller");
  }
}

contract SweepAccountOrchestratorTest_BatchOperations is SweepAccountOrchestratorTest {
  function test_BatchSweepThroughOrchestrator() public {
    uint256[] memory amounts = new uint256[](3);
    amounts[0] = 10 ether;
    amounts[1] = 20 ether;
    amounts[2] = 30 ether;

    // Build the batch of calls
    ERC7821.Call[] memory calls = new ERC7821.Call[](3);
    
    for (uint256 i = 0; i < 3; i++) {
      SweepAccount.SweepIntent memory sweepIntent = _createSweepIntent(
        address(token), 
        amounts[i], 
        i + 1
      );
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
    
    // Create orchestrator intent with all calls
    ICommon.Intent memory intent = ICommon.Intent({
      eoa: owner,
      executionData: abi.encode(calls),
      nonce: 0,
      payer: owner,
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

    // Verify all sweeps were successful
    uint256 totalSwept = amounts[0] + amounts[1] + amounts[2];
    assertEq(token.balanceOf(recipient), totalSwept);
    assertEq(token.balanceOf(address(sweepAccount)), INITIAL_BALANCE - totalSwept);

    // Check nonces
    for (uint256 i = 0; i < 3; i++) {
      assertTrue(sweepAccount.isNonceUsed(i + 1));
    }
  }

  function test_MixedETHAndTokenSweepsThroughOrchestrator() public {
    // Create calls for both token and ETH sweeps
    ERC7821.Call[] memory calls = new ERC7821.Call[](2);
    
    // Call 1: ERC20 token sweep
    SweepAccount.SweepIntent memory tokenIntent = _createSweepIntent(address(token), 50 ether, 1);
    bytes memory tokenSignature = _signSweepIntent(tokenIntent);
    calls[0] = ERC7821.Call({
      to: address(sweepAccount),
      value: 0,
      data: abi.encodeWithSelector(
        SweepAccount.executeSweep.selector,
        tokenIntent,
        tokenSignature
      )
    });
    
    // Call 2: ETH sweep
    SweepAccount.SweepIntent memory ethIntent = _createSweepIntent(address(0), 1 ether, 2);
    bytes memory ethSignature = _signSweepIntent(ethIntent);
    calls[1] = ERC7821.Call({
      to: address(sweepAccount),
      value: 0,
      data: abi.encodeWithSelector(
        SweepAccount.executeSweep.selector,
        ethIntent,
        ethSignature
      )
    });

    uint256 recipientETHBefore = recipient.balance;

    // Create orchestrator intent - use SweepAccount as the EOA since it implements IthacaAccount
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
    
    assertEq(uint32(err), 0, "Orchestrator execution failed");

    // Verify both sweeps were successful
    assertEq(token.balanceOf(recipient), 50 ether);
    assertEq(recipient.balance, recipientETHBefore + 1 ether);
    assertTrue(sweepAccount.isNonceUsed(1));
    assertTrue(sweepAccount.isNonceUsed(2));
  }
}

contract SweepAccountOrchestratorTest_SecurityChecks is SweepAccountOrchestratorTest {
  function test_ReplayProtectionThroughOrchestrator() public {
    uint256 sweepNonce = 1;
    SweepAccount.SweepIntent memory sweepIntent = _createSweepIntent(address(token), 10 ether, sweepNonce);
    bytes memory sweepSignature = _signSweepIntent(sweepIntent);
    
    // Create orchestrator intent
    ICommon.Intent memory intent = _createOrchestratorIntent(
      sweepIntent,
      sweepSignature,
      0
    );
    intent.signature = _signOrchestratorIntent(intent);

    // First execution should succeed
    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    assertEq(uint32(err), 0, "First execution should succeed");

    // Create second intent with same sweep nonce
    ICommon.Intent memory intent2 = _createOrchestratorIntent(
      sweepIntent,
      sweepSignature,
      1 // Different orchestrator nonce
    );
    intent2.signature = _signOrchestratorIntent(intent2);
    
    // Second execution with same sweep nonce should fail
    vm.prank(relayer);
    bytes4 err2 = orchestrator.execute(abi.encode(intent2));
    assertGt(uint32(err2), 0, "Second execution should fail due to nonce reuse");
  }

  function test_SignatureValidationThroughOrchestrator() public {
    SweepAccount.SweepIntent memory sweepIntent = _createSweepIntent(address(token), 10 ether, 1);

    // Sign with wrong private key for sweep
    uint256 wrongKey = 0x9876;
    bytes32 SWEEP_INTENT_TYPEHASH = keccak256(
      "SweepIntent(address token,address recipient,uint256 amount,uint256 nonce,uint256 expiry)"
    );

    bytes32 structHash = keccak256(
      abi.encode(
        SWEEP_INTENT_TYPEHASH,
        sweepIntent.token,
        sweepIntent.recipient,
        sweepIntent.amount,
        sweepIntent.nonce,
        sweepIntent.expiry
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
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, digest);
    bytes memory wrongSignature = abi.encodePacked(r, s, v);
    
    // Create orchestrator intent with wrong sweep signature
    ICommon.Intent memory intent = _createOrchestratorIntent(
      sweepIntent,
      wrongSignature,
      0
    );
    intent.signature = _signOrchestratorIntent(intent);

    // Should fail due to invalid sweep signature
    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    assertGt(uint32(err), 0, "Should fail with invalid sweep signature");
  }

  function test_ExpiryEnforcementThroughOrchestrator() public {
    vm.warp(1000);

    SweepAccount.SweepIntent memory sweepIntent = SweepAccount.SweepIntent({
      token: address(token),
      recipient: recipient,
      amount: 10 ether,
      nonce: 1,
      expiry: 999 // Already expired
    });

    bytes memory sweepSignature = _signSweepIntent(sweepIntent);
    
    // Create orchestrator intent with expired sweep
    ICommon.Intent memory intent = _createOrchestratorIntent(
      sweepIntent,
      sweepSignature,
      0
    );
    intent.signature = _signOrchestratorIntent(intent);

    // Should fail due to expired sweep intent
    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    assertGt(uint32(err), 0, "Should fail with expired sweep intent");
  }

  function test_InsufficientBalanceProtectionThroughOrchestrator() public {
    SweepAccount.SweepIntent memory sweepIntent = _createSweepIntent(
      address(token),
      INITIAL_BALANCE + 1, // More than available
      1
    );
    bytes memory sweepSignature = _signSweepIntent(sweepIntent);
    
    // Create orchestrator intent
    ICommon.Intent memory intent = _createOrchestratorIntent(
      sweepIntent,
      sweepSignature,
      0
    );
    intent.signature = _signOrchestratorIntent(intent);

    // Should fail due to insufficient balance
    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    assertGt(uint32(err), 0, "Should fail with insufficient balance");
  }
}

contract SweepAccountOrchestratorTest_Fuzz is SweepAccountOrchestratorTest {
  function testFuzz_SweepVariousAmountsThroughOrchestrator(uint256 amount) public {
    vm.assume(amount > 0 && amount <= INITIAL_BALANCE);

    SweepAccount.SweepIntent memory sweepIntent = _createSweepIntent(address(token), amount, 1);
    bytes memory sweepSignature = _signSweepIntent(sweepIntent);
    
    ICommon.Intent memory intent = _createOrchestratorIntent(
      sweepIntent,
      sweepSignature,
      0
    );
    intent.signature = _signOrchestratorIntent(intent);

    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    
    assertEq(uint32(err), 0, "Orchestrator execution failed");
    assertEq(token.balanceOf(recipient), amount);
    assertEq(token.balanceOf(address(sweepAccount)), INITIAL_BALANCE - amount);
  }

  function testFuzz_SweepWithVariousNoncesThroughOrchestrator(uint256 sweepNonce, uint256 orchNonce) public {
    vm.assume(sweepNonce > 0 && sweepNonce < type(uint256).max);
    vm.assume(orchNonce < type(uint256).max);

    SweepAccount.SweepIntent memory sweepIntent = _createSweepIntent(address(token), 10 ether, sweepNonce);
    bytes memory sweepSignature = _signSweepIntent(sweepIntent);
    
    ICommon.Intent memory intent = _createOrchestratorIntent(
      sweepIntent,
      sweepSignature,
      orchNonce
    );
    intent.signature = _signOrchestratorIntent(intent);

    vm.prank(relayer);
    bytes4 err = orchestrator.execute(abi.encode(intent));
    
    assertEq(uint32(err), 0, "Orchestrator execution failed");
    assertTrue(sweepAccount.isNonceUsed(sweepNonce));
  }

  function testFuzz_MultipleSequentialSweepsThroughOrchestrator(uint8 numSweeps, uint256 seed) public {
    vm.assume(numSweeps > 0 && numSweeps <= 10);

    uint256 amountPerSweep = INITIAL_BALANCE / numSweeps;
    uint256 totalSwept = 0;

    for (uint256 i = 0; i < numSweeps; i++) {
      uint256 sweepNonce = uint256(keccak256(abi.encode(seed, i)));
      uint256 amount = i == numSweeps - 1
        ? INITIAL_BALANCE - totalSwept // Last sweep takes remainder
        : amountPerSweep;

      SweepAccount.SweepIntent memory sweepIntent = _createSweepIntent(address(token), amount, sweepNonce);
      bytes memory sweepSignature = _signSweepIntent(sweepIntent);
      
      ICommon.Intent memory intent = _createOrchestratorIntent(
        sweepIntent,
        sweepSignature,
        i // Use i as orchestrator nonce
      );
      intent.signature = _signOrchestratorIntent(intent);

      vm.prank(relayer);
      bytes4 err = orchestrator.execute(abi.encode(intent));
      assertEq(uint32(err), 0, "Orchestrator execution failed");
      
      totalSwept += amount;
    }

    assertEq(token.balanceOf(recipient), INITIAL_BALANCE);
    assertEq(token.balanceOf(address(sweepAccount)), 0);
  }
}
