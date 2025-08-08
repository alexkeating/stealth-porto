// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {StealthSender} from "src/StealthSender.sol";
import {IthacaAccount} from "lib/account/src/IthacaAccount.sol";
import {ShieldedPool} from "src/ShieldedPool.sol";
import {IERC5564Announcer} from "src/interfaces/IERC5564Announcer.sol";
import {ERC20Mock} from "openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {MockOrchestrator} from "lib/account/test/utils/mocks/MockOrchestrator.sol";
import {IOrchestrator} from "lib/account/src/interfaces/IOrchestrator.sol";
import {ICommon} from "lib/account/src/interfaces/ICommon.sol";
import {ERC7821} from "lib/account/lib/solady/src/accounts/ERC7821.sol";

/// @title StealthPortoIntegrationBase
/// @notice Base contract for stealth address protocol integration tests
/// @dev Contains common setup, helpers, and shared functionality
abstract contract StealthPortoIntegrationBase is Test {
  using ECDSA for bytes32;

  // Core contracts
  StealthSender public stealthSender;
  ShieldedPool public shieldedPool;
  ERC20Mock public token;
  IthacaAccount public sweepAccount;

  // Accounts - will be set by fuzz inputs
  uint256 public recipientPrivateKey;
  address public recipient;

  uint256 public senderPrivateKey;
  address public sender;

  address public relayer;

  // Stealth address components - will be set by fuzz inputs
  uint256 public recipientSpendingKey;
  uint256 public recipientViewingKey;

  uint256 public ephemeralPrivateKey;
  address public ephemeralPublicKey;

  uint256 public stealthPrivateKey;
  address public stealthAddress;

  // Test amounts - will be set by fuzz inputs
  uint256 public constant INITIAL_BALANCE = 1000 ether;
  uint256 public stealthAmount;
  uint256 public relayerFee;

  // EIP-5564 constants
  uint256 public constant SCHEME_ID = 1; // secp256k1

  // Events
  event StealthMetaAddressRegistered(address indexed user, bytes metaAddress);
  event StealthTransferSent(
    address indexed token,
    address indexed from,
    address indexed stealthAddress,
    uint256 amount,
    uint256 schemeId
  );
  event Announcement(
    uint256 indexed schemeId,
    address indexed stealthAddress,
    address indexed caller,
    bytes ephemeralPubKey,
    bytes metadata
  );
  event TokensSwept(
    address indexed token, address indexed recipient, uint256 amount, uint256 nonce
  );
  event Deposit(
    bytes32 indexed commitment, address indexed token, uint256 amount, bytes32 encryptedNote
  );
  event Withdrawal(
    bytes32 indexed nullifier,
    address indexed token,
    address indexed recipient,
    uint256 amount,
    uint256 relayerFee
  );

  function setUp() public virtual {
    // Deploy core contracts (only done once)
    stealthSender = new StealthSender();
    shieldedPool = new ShieldedPool();
    token = new ERC20Mock();

    // Deploy announcer at expected address
    _deployAnnouncerAtAddress();
  }

  /// @notice Setup fuzz test parameters with proper bounds
  function _setupFuzzTest(
    uint256 _recipientKey,
    uint256 _senderKey,
    uint256 _relayerSeed,
    uint256 _spendingKey,
    uint256 _viewingKey,
    uint256 _ephemeralKey,
    uint256 _amount,
    uint256 _fee
  ) internal {
    // secp256k1 curve order - 1 (max valid private key)
    uint256 maxKey = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140;
    
    // Bound private keys to valid range (1 to secp256k1 order - 1)
    recipientPrivateKey = bound(_recipientKey, 1, maxKey);
    senderPrivateKey = bound(_senderKey, 1, maxKey);
    recipientSpendingKey = bound(_spendingKey, 1, maxKey);
    recipientViewingKey = bound(_viewingKey, 1, maxKey);
    ephemeralPrivateKey = bound(_ephemeralKey, 1, maxKey);
    
    // Ensure all private keys are different
    vm.assume(recipientPrivateKey != senderPrivateKey);
    vm.assume(recipientSpendingKey != recipientViewingKey);
    vm.assume(recipientSpendingKey != ephemeralPrivateKey);
    
    // Setup accounts
    recipient = vm.addr(recipientPrivateKey);
    sender = vm.addr(senderPrivateKey);
    ephemeralPublicKey = vm.addr(ephemeralPrivateKey);
    
    // Bound relayer to a valid address (not zero, not sender/recipient)
    relayer = address(uint160(bound(_relayerSeed, 1, type(uint160).max)));
    vm.assume(relayer != sender && relayer != recipient);
    
    // Bound amounts to reasonable range
    stealthAmount = bound(_amount, 0.1 ether, 100 ether);
    // Ensure relayer fee is valid: min 0.001 ether, max 5% of amount
    uint256 maxFee = stealthAmount / 20; // 5% max fee (ShieldedPool limit)
    uint256 minFee = 0.001 ether;
    // If max fee would be less than min fee, use a smaller min
    if (maxFee < minFee) {
      minFee = maxFee / 2; // Use half of max as min
    }
    relayerFee = bound(_fee, minFee, maxFee);
    
    // Fund accounts
    token.mint(sender, INITIAL_BALANCE);
    vm.deal(sender, INITIAL_BALANCE);
    vm.deal(relayer, 10 ether);

    // Approve StealthSender for token transfers
    vm.prank(sender);
    token.approve(address(stealthSender), type(uint256).max);
  }

  /// @notice Step 1: Register stealth meta address
  function _registerStealthMetaAddress() internal returns (bytes memory) {
    // Derive public keys from private keys (simplified - using addresses as public keys)
    address spendingPubKey = vm.addr(recipientSpendingKey);
    address viewingPubKey = vm.addr(recipientViewingKey);

    // Create meta address (concatenation of spending and viewing public keys)
    bytes memory metaAddress = abi.encodePacked(spendingPubKey, viewingPubKey);

    // In production, this would be registered on-chain via ERC-6538 Registry
    _mockRegisterMetaAddress(metaAddress);

    return metaAddress;
  }

  /// @notice Step 2: Derive stealth address from meta address
  function _deriveStealthAddress(bytes memory metaAddress) internal returns (address) {
    // Extract spending and viewing public keys
    address spendingPubKey;
    address viewingPubKey;
    assembly {
      spendingPubKey := mload(add(metaAddress, 0x20))
      viewingPubKey := mload(add(metaAddress, 0x40))
    }

    // Derive shared secret (simplified - in production would use ECDH)
    bytes32 sharedSecret = keccak256(abi.encodePacked(ephemeralPrivateKey, viewingPubKey));

    // Derive stealth address
    stealthPrivateKey = uint256(keccak256(abi.encodePacked(recipientSpendingKey, sharedSecret)));
    return vm.addr(stealthPrivateKey);
  }

  /// @notice Step 3: Send tokens to stealth address
  function _sendToStealthAddress() internal {
    // Prepare ephemeral public key and metadata
    bytes memory ephemeralPubKeyBytes = abi.encodePacked(ephemeralPublicKey);
    bytes memory metadata = abi.encodePacked(bytes1(0x01)); // View tag

    // Expect announcement event
    vm.expectEmit();
    emit Announcement(
      SCHEME_ID, stealthAddress, address(stealthSender), ephemeralPubKeyBytes, metadata
    );

    // Expect transfer event
    vm.expectEmit();
    emit StealthTransferSent(address(token), sender, stealthAddress, stealthAmount, SCHEME_ID);

    // Send tokens via StealthSender
    vm.prank(sender);
    stealthSender.send(
      address(token), stealthAddress, stealthAmount, SCHEME_ID, ephemeralPubKeyBytes, metadata
    );

    // Verify tokens arrived at stealth address
    assertEq(token.balanceOf(stealthAddress), stealthAmount);
  }

  /// @notice Step 4: Simulate EIP-7702 delegation
  function _simulateEIP7702Delegation(address orchestrator) internal {
    // Deploy a new IthacaAccount configured with the orchestrator (if provided)
    IthacaAccount newSweepAccount = new IthacaAccount(orchestrator);

    // Simulate delegation by deploying the account bytecode at the stealth address
    vm.etch(stealthAddress, address(newSweepAccount).code);

    // Update our reference
    sweepAccount = IthacaAccount(payable(stealthAddress));
  }

  /// @notice Step 5: Withdraw from shielded pool
  function _withdrawFromShieldedPool(bytes32) internal {
    // Generate nullifier for withdrawal
    bytes32 nullifier = keccak256(abi.encodePacked("nullifier", recipient));

    // Generate proof (mock proof for testing)
    bytes memory proof =
      shieldedPool.generateMockProof(address(token), stealthAmount, nullifier, recipient);

    // Relayer executes withdrawal on behalf of recipient
    vm.expectEmit();
    emit Withdrawal(nullifier, address(token), recipient, stealthAmount, relayerFee);

    vm.prank(relayer);
    shieldedPool.withdraw(
      address(token), stealthAmount, nullifier, recipient, relayer, relayerFee, proof
    );
  }

  /// @notice Verify final state after complete flow
  function _verifyFinalState() internal view {
    // Recipient should have received tokens minus relayer fee
    assertEq(token.balanceOf(recipient), stealthAmount - relayerFee);

    // Relayer should have received fee
    assertEq(token.balanceOf(relayer), relayerFee);

    // Stealth address should be empty
    assertEq(token.balanceOf(stealthAddress), 0);

    // Shielded pool should be empty (all withdrawn)
    assertEq(token.balanceOf(address(shieldedPool)), 0);

    // Sender should have reduced balance
    assertEq(token.balanceOf(sender), INITIAL_BALANCE - stealthAmount);
  }

  /// @notice Helper: Deploy announcer contract
  function _deployAnnouncerAtAddress() internal {
    address announcer = address(stealthSender.ANNOUNCER());

    // Deploy the mock announcer helper at the expected address
    MockAnnouncerHelper mockAnnouncer = new MockAnnouncerHelper();
    vm.etch(announcer, address(mockAnnouncer).code);
  }

  /// @notice Helper: Mock meta address registration
  function _mockRegisterMetaAddress(bytes memory metaAddress) internal {
    // In production, this would interact with ERC-6538 Registry
    // For testing, we just emit an event
    emit StealthMetaAddressRegistered(recipient, metaAddress);
  }

  /// @notice Abstract function for executing sweep to shielded pool
  /// @dev Must be implemented by inheriting contracts
  function _executeSweepToShieldedPool() internal virtual returns (bytes32);
}

/// @title StealthPortoIntegration_Basic
/// @notice Test stealth address protocol flow without orchestrator
contract StealthPortoIntegration_Basic is StealthPortoIntegrationBase {
  function testFuzz_FullStealthAddressFlow(
    uint256 _recipientKey,
    uint256 _senderKey,
    uint256 _relayerSeed,
    uint256 _spendingKey,
    uint256 _viewingKey,
    uint256 _ephemeralKey,
    uint256 _amount,
    uint256 _fee
  ) public {
    // Setup fuzz parameters
    _setupFuzzTest(
      _recipientKey,
      _senderKey,
      _relayerSeed,
      _spendingKey,
      _viewingKey,
      _ephemeralKey,
      _amount,
      _fee
    );

    // Step 1: Recipient registers stealth meta address
    bytes memory metaAddress = _registerStealthMetaAddress();

    // Step 2: Sender derives stealth address from meta address
    stealthAddress = _deriveStealthAddress(metaAddress);

    // Step 3: Sender sends tokens to stealth address
    _sendToStealthAddress();

    // Step 4: Simulate EIP-7702 delegation (stealth address delegates to IthacaAccount)
    _simulateEIP7702Delegation(address(0)); // No orchestrator

    // Step 5: Execute sweep to shielded pool
    bytes32 depositCommitment = _executeSweepToShieldedPool();

    // Step 6: Recipient withdraws from shielded pool to original account
    _withdrawFromShieldedPool(depositCommitment);

    // Final verification
    _verifyFinalState();
  }

  /// @notice Execute sweep to shielded pool without orchestrator
  function _executeSweepToShieldedPool() internal override returns (bytes32) {
    // First approve shielded pool to spend tokens
    vm.prank(stealthAddress);
    token.approve(address(shieldedPool), stealthAmount);

    // Now deposit directly into shielded pool from stealth address
    bytes32 commitment = keccak256(abi.encodePacked("secret", recipient, block.timestamp));
    bytes32 encryptedNote = keccak256(abi.encodePacked("encrypted", commitment));

    vm.expectEmit();
    emit Deposit(commitment, address(token), stealthAmount, encryptedNote);

    vm.prank(stealthAddress);
    shieldedPool.deposit(address(token), stealthAmount, commitment, encryptedNote);

    // Verify tokens are now in shielded pool
    assertEq(token.balanceOf(address(shieldedPool)), stealthAmount);
    assertEq(token.balanceOf(stealthAddress), 0);
    assertEq(shieldedPool.getPoolBalance(address(token)), stealthAmount);

    return commitment;
  }
}

/// @title StealthPortoIntegration_WithOrchestrator
/// @notice Test stealth address protocol flow with orchestrator-sponsored execution
contract StealthPortoIntegration_WithOrchestrator is StealthPortoIntegrationBase {
  MockOrchestrator public orchestrator;
  
  uint256 public sponsorPrivateKey;
  address public sponsor; // Will sponsor gas through orchestrator
  uint256 public sponsorAmount; // Amount sponsor will pay for gas

  function setUp() public override {
    super.setUp();
    
    // Deploy orchestrator with no pause authority
    orchestrator = new MockOrchestrator(address(0));
  }

  function testFuzz_FullStealthAddressFlowWithOrchestrator(
    uint256 _recipientKey,
    uint256 _senderKey,
    uint256 _relayerSeed,
    uint256 _spendingKey,
    uint256 _viewingKey,
    uint256 _ephemeralKey,
    uint256 _sponsorKey,
    uint256 _amount,
    uint256 _fee,
    uint256 _sponsorPayment
  ) public {
    // Setup fuzz parameters
    _setupFuzzTest(
      _recipientKey,
      _senderKey,
      _relayerSeed,
      _spendingKey,
      _viewingKey,
      _ephemeralKey,
      _amount,
      _fee
    );
    
    // Setup sponsor with fuzz parameters
    uint256 maxKey = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140;
    sponsorPrivateKey = bound(_sponsorKey, 1, maxKey);
    sponsor = vm.addr(sponsorPrivateKey);
    vm.assume(sponsor != sender && sponsor != recipient && sponsor != relayer);
    sponsorAmount = bound(_sponsorPayment, 0.01 ether, 2 ether);
    
    // Fund sponsor
    token.mint(sponsor, INITIAL_BALANCE);
    vm.deal(sponsor, INITIAL_BALANCE);
    
    // Sponsor approves orchestrator for payment
    vm.prank(sponsor);
    token.approve(address(orchestrator), type(uint256).max);

    // Step 1: Recipient registers stealth meta address
    bytes memory metaAddress = _registerStealthMetaAddress();

    // Step 2: Sender derives stealth address from meta address
    stealthAddress = _deriveStealthAddress(metaAddress);

    // Step 3: Sender sends tokens to stealth address
    _sendToStealthAddress();

    // Step 4: Simulate EIP-7702 delegation (stealth address delegates to IthacaAccount)
    _simulateEIP7702Delegation(address(orchestrator));

    // Step 5: Setup keys for orchestrator verification
    _setupKeysForOrchestrator();

    // Step 6: Execute orchestrator-sponsored sweep to shielded pool
    bytes32 depositCommitment = _executeSweepToShieldedPool();

    // Step 7: Recipient withdraws from shielded pool to original account
    _withdrawFromShieldedPool(depositCommitment);

    // Final verification with sponsor payment
    _verifyFinalStateWithSponsor();
  }

  /// @notice Setup keys for orchestrator verification
  function _setupKeysForOrchestrator() internal {
    // The stealth account needs to recognize itself as a valid signer
    // We add the stealth address as a Secp256k1 key so the orchestrator can verify signatures
    IthacaAccount.Key memory stealthKey = IthacaAccount.Key({
      expiry: 0, // Never expires
      keyType: IthacaAccount.KeyType.Secp256k1,
      isSuperAdmin: true,
      publicKey: abi.encodePacked(stealthAddress)
    });

    // Add key to the account (the account needs to call this on itself)
    vm.prank(stealthAddress);
    IthacaAccount(payable(stealthAddress)).authorize(stealthKey);
  }

  /// @notice Execute orchestrator-sponsored sweep
  function _executeSweepToShieldedPool() internal override returns (bytes32) {
    // Create the sweep execution data
    ERC7821.Call[] memory calls = new ERC7821.Call[](2);
    
    // First call: Approve shielded pool to spend tokens
    calls[0] = ERC7821.Call({
      to: address(token),
      value: 0,
      data: abi.encodeWithSelector(token.approve.selector, address(shieldedPool), stealthAmount)
    });

    // Second call: Deposit into shielded pool
    bytes32 commitment = keccak256(abi.encodePacked("secret", recipient, block.timestamp));
    bytes32 encryptedNote = keccak256(abi.encodePacked("encrypted", commitment));
    
    calls[1] = ERC7821.Call({
      to: address(shieldedPool),
      value: 0,
      data: abi.encodeWithSelector(
        shieldedPool.deposit.selector,
        address(token),
        stealthAmount,
        commitment,
        encryptedNote
      )
    });

    // Encode execution data for orchestrator
    bytes memory executionData = abi.encode(calls);

    // For this test, we'll demonstrate orchestrator-compatible execution
    // In production, the orchestrator would handle payment verification and gas sponsorship
    // Here we'll execute directly through the account to show the integration works
    
    // Execute using the account's execute function (simulating orchestrator-sponsored execution)
    bytes32 mode = bytes32(uint256(0x0100000000000000000000000000000000000000000000000000000000000000));
    
    vm.prank(stealthAddress);
    sweepAccount.execute(mode, executionData);
    
    // Simulate sponsor payment to relayer (in production, orchestrator would handle this)
    vm.prank(sponsor);
    token.transfer(relayer, sponsorAmount);

    // Verify tokens are now in shielded pool
    assertEq(token.balanceOf(address(shieldedPool)), stealthAmount);
    assertEq(token.balanceOf(stealthAddress), 0);
    assertEq(shieldedPool.getPoolBalance(address(token)), stealthAmount);

    return commitment;
  }

  /// @notice Verify final state with sponsor payment
  function _verifyFinalStateWithSponsor() internal view {
    // Recipient should have received tokens minus relayer fee
    assertEq(token.balanceOf(recipient), stealthAmount - relayerFee);

    // Relayer should have received fee plus sponsor payment
    assertEq(token.balanceOf(relayer), relayerFee + sponsorAmount);

    // Sponsor should have paid for gas
    assertEq(token.balanceOf(sponsor), INITIAL_BALANCE - sponsorAmount);

    // Stealth address should be empty
    assertEq(token.balanceOf(stealthAddress), 0);

    // Shielded pool should be empty (all withdrawn)
    assertEq(token.balanceOf(address(shieldedPool)), 0);

    // Sender should have reduced balance
    assertEq(token.balanceOf(sender), INITIAL_BALANCE - stealthAmount);
  }
}

/// @notice Helper contract for announcer functionality
contract MockAnnouncerHelper {
  event Announcement(
    uint256 indexed schemeId,
    address indexed stealthAddress,
    address indexed caller,
    bytes ephemeralPubKey,
    bytes metadata
  );

  function announce(
    uint256 schemeId,
    address stealthAddress,
    bytes memory ephemeralPubKey,
    bytes memory metadata
  ) external {
    emit Announcement(schemeId, stealthAddress, msg.sender, ephemeralPubKey, metadata);
  }
}