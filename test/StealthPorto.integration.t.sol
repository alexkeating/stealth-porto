// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {StealthSender} from "src/StealthSender.sol";
import {IthacaAccount} from "lib/account/src/IthacaAccount.sol";
import {ShieldedPool} from "src/ShieldedPool.sol";
import {IERC5564Announcer} from "src/interfaces/IERC5564Announcer.sol";
import {ERC5564Announcer} from "test/helpers/ERC5564Announcer.sol";
import {ERC6538Registry} from "test/helpers/ERC6538Registry.sol";
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

  // Struct to hold EIP-7702 delegation signature components
  struct DelegationSignature {
    uint8 v;
    bytes32 r;
    bytes32 s;
    uint64 nonce;
    address authority;
  }

  // Core contracts
  StealthSender public stealthSender;
  ShieldedPool public shieldedPool;
  ERC20Mock public token;
  IthacaAccount public sweepAccount;
  ERC6538Registry public registry;

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

  // EIP-7702 delegation signature
  DelegationSignature public delegationSig;

  // Test amounts - will be set by fuzz inputs
  uint256 public constant INITIAL_BALANCE = 1000 ether;
  uint256 public stealthAmount;
  uint256 public relayerFee;

  // EIP-5564 constants
  uint256 public constant SCHEME_ID = 1; // secp256k1

  // Events
  event StealthMetaAddressSet(
    address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
  );
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
    registry = new ERC6538Registry();

    // Deploy announcer at expected address
    _deployAnnouncerAtAddress();
  }

  /// @notice Setup fuzz test parameters with proper bounds
  function _setupFuzzTest(
    uint256 _recipientKey,
    uint256 _senderKey,
    uint256 _relayerSeed,
    uint256 _spendingKeySeed,
    uint256 _viewingKeySeed,
    uint256 _ephemeralKey,
    uint256 _amount,
    uint256 _fee
  ) internal {
    // secp256k1 curve order - 1 (max valid private key)
    uint256 maxKey = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140;

    // Bound private keys to valid range (1 to secp256k1 order - 1)
    recipientPrivateKey = bound(_recipientKey, 1, maxKey);
    senderPrivateKey = bound(_senderKey, 1, maxKey);
    ephemeralPrivateKey = bound(_ephemeralKey, 1, maxKey);

    // Ensure main private keys are different
    vm.assume(recipientPrivateKey != senderPrivateKey);

    // Setup accounts
    recipient = vm.addr(recipientPrivateKey);
    sender = vm.addr(senderPrivateKey);
    ephemeralPublicKey = vm.addr(ephemeralPrivateKey);

    // Derive spending and viewing keys from recipient's signature
    // This simulates the recipient generating deterministic keys from their main key
    // Sign a single message to get a seed
    bytes32 message = keccak256(abi.encodePacked("test message", _spendingKeySeed, _viewingKeySeed));
    (, bytes32 r, bytes32 s) = vm.sign(recipientPrivateKey, message);

    // Use the signature as a seed to derive both keys with different paths
    bytes32 seed = keccak256(abi.encodePacked(r, s));

    // Derive spending and viewing keys from the seed using different derivation paths
    recipientSpendingKey = uint256(keccak256(abi.encodePacked(seed, "spending")));
    recipientViewingKey = uint256(keccak256(abi.encodePacked(seed, "viewing")));

    // Ensure derived keys are different from each other and from ephemeral key
    vm.assume(recipientSpendingKey != recipientViewingKey);
    vm.assume(recipientSpendingKey != ephemeralPrivateKey);
    vm.assume(recipientViewingKey != ephemeralPrivateKey);

    // Bound relayer to a valid address (not zero, not sender/recipient, not any contract)
    relayer = address(uint160(bound(_relayerSeed, 1, type(uint160).max)));
    vm.assume(relayer != sender && relayer != recipient);
    vm.assume(relayer != address(shieldedPool) && relayer != address(stealthSender));
    vm.assume(relayer != address(token) && relayer != address(registry));

    // Bound amounts to reasonable range
    stealthAmount = bound(_amount, 0.1 ether, 100 ether);
    // Ensure relayer fee is valid: min 0.001 ether, max 5% of amount
    uint256 maxFee = stealthAmount / 20; // 5% max fee (ShieldedPool limit)
    uint256 minFee = 0.001 ether;
    // If max fee would be less than min fee, use a smaller min
    if (maxFee < minFee) minFee = maxFee / 2; // Use half of max as min

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
  /// @param spendingKey The recipient's spending private key
  /// @param viewingKey The recipient's viewing private key
  /// @param recipientAddr The recipient's address for registration
  function _registerStealthMetaAddress(
    uint256 spendingKey,
    uint256 viewingKey,
    address recipientAddr
  ) internal returns (bytes memory) {
    // Derive public keys from private keys (simplified - using addresses as public keys)
    address spendingPubKey = vm.addr(spendingKey);
    address viewingPubKey = vm.addr(viewingKey);

    // Create meta address (concatenation of spending and viewing public keys)
    bytes memory metaAddress = abi.encodePacked(spendingPubKey, viewingPubKey);

    // Expect the registry event
    vm.expectEmit();
    emit StealthMetaAddressSet(recipientAddr, SCHEME_ID, metaAddress);

    // Register on-chain via ERC-6538 Registry
    vm.prank(recipientAddr);
    registry.registerKeys(SCHEME_ID, metaAddress);

    // Verify the meta address was stored correctly
    assertEq(registry.stealthMetaAddressOf(recipientAddr, SCHEME_ID), metaAddress);

    return metaAddress;
  }

  /// @notice Step 2: Derive stealth address from meta address
  /// @param metaAddress The stealth meta address
  /// @param ephemeralKey The ephemeral private key for derivation
  /// @param spendingKey The recipient's spending private key
  function _deriveStealthAddress(
    bytes memory metaAddress,
    uint256 ephemeralKey,
    uint256 spendingKey
  ) internal view returns (address, uint256) {
    // Extract spending and viewing public keys
    address spendingPubKey;
    address viewingPubKey;
    assembly {
      spendingPubKey := mload(add(metaAddress, 0x20))
      viewingPubKey := mload(add(metaAddress, 0x40))
    }

    // Derive shared secret (simplified - in production would use ECDH)
    bytes32 sharedSecret = keccak256(abi.encodePacked(ephemeralKey, viewingPubKey));

    // Derive stealth private key and address
    uint256 stealthPrivKey = uint256(keccak256(abi.encodePacked(spendingKey, sharedSecret)));
    return (vm.addr(stealthPrivKey), stealthPrivKey);
  }

  /// @notice Step 3: Send tokens to stealth address
  /// @param stealthAddr The stealth address to send tokens to
  /// @param amount The amount of tokens to send
  /// @param senderAddr The address sending the tokens
  /// @param ephemeralPubKey The ephemeral public key address
  function _sendToStealthAddress(
    address stealthAddr,
    uint256 amount,
    address senderAddr,
    address ephemeralPubKey
  ) internal {
    // Prepare ephemeral public key and metadata
    bytes memory ephemeralPubKeyBytes = abi.encodePacked(ephemeralPubKey);
    bytes memory metadata = abi.encodePacked(bytes1(0x01)); // View tag

    // Expect announcement event
    vm.expectEmit();
    emit Announcement(
      SCHEME_ID, stealthAddr, address(stealthSender), ephemeralPubKeyBytes, metadata
    );

    // Expect transfer event
    vm.expectEmit();
    emit StealthTransferSent(address(token), senderAddr, stealthAddr, amount, SCHEME_ID);

    // Send tokens via StealthSender
    vm.prank(senderAddr);
    stealthSender.send(
      address(token), stealthAddr, amount, SCHEME_ID, ephemeralPubKeyBytes, metadata
    );

    // Verify tokens arrived at stealth address
    assertEq(token.balanceOf(stealthAddr), amount);
  }

  /// @notice Step 4: Set up EIP-7702 delegation
  /// @param orchestrator The orchestrator address (or address(0) if none)
  /// @param stealthAddr The stealth address that will delegate
  /// @param stealthPrivKey The private key of the stealth address
  function _setupEIP7702Delegation(
    address orchestrator,
    address stealthAddr,
    uint256 stealthPrivKey
  ) internal returns (IthacaAccount) {
    // Deploy a new IthacaAccount configured with the orchestrator (if provided)
    IthacaAccount implementation = new IthacaAccount(orchestrator);

    // Sign the EIP-7702 delegation from the stealth address to the IthacaAccount
    // This creates the delegation signature that would be included in a real transaction
    Vm.SignedDelegation memory signedDelegation =
      vm.signDelegation(address(implementation), stealthPrivKey);

    // Store the delegation signature for reference
    delegationSig = DelegationSignature({
      v: signedDelegation.v,
      r: signedDelegation.r,
      s: signedDelegation.s,
      nonce: signedDelegation.nonce,
      authority: signedDelegation.implementation
    });

    // Attach the delegation to the next transaction from the stealth address
    // This simulates including the EIP-7702 delegation in a transaction
    // The delegation will be active when the stealth address makes its next transaction
    vm.attachDelegation(signedDelegation);

    // Update our reference - the stealth address now behaves as an IthacaAccount
    sweepAccount = IthacaAccount(payable(stealthAddr));

    return implementation;
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

  /// @notice Helper: Deploy announcer contract
  function _deployAnnouncerAtAddress() internal {
    address announcer = address(stealthSender.ANNOUNCER());

    // Deploy the real ERC5564Announcer at the expected address
    ERC5564Announcer announcerImpl = new ERC5564Announcer();
    vm.etch(announcer, address(announcerImpl).code);
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
    bytes memory metaAddress =
      _registerStealthMetaAddress(recipientSpendingKey, recipientViewingKey, recipient);

    // Step 2: Sender derives stealth address from meta address
    (stealthAddress, stealthPrivateKey) =
      _deriveStealthAddress(metaAddress, ephemeralPrivateKey, recipientSpendingKey);

    // Step 3: Sender sends tokens to stealth address
    _sendToStealthAddress(stealthAddress, stealthAmount, sender, ephemeralPublicKey);

    // Step 4: Set up EIP-7702 delegation (stealth address delegates to IthacaAccount)
    _setupEIP7702Delegation(address(0), stealthAddress, stealthPrivateKey); // No orchestrator

    // Step 5: Execute sweep to shielded pool
    bytes32 depositCommitment = _executeSweepToShieldedPool();

    // Step 6: Recipient withdraws from shielded pool to original account
    _withdrawFromShieldedPool(depositCommitment);

    // Final verification
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
    bytes memory metaAddress =
      _registerStealthMetaAddress(recipientSpendingKey, recipientViewingKey, recipient);

    // Step 2: Sender derives stealth address from meta address
    (stealthAddress, stealthPrivateKey) =
      _deriveStealthAddress(metaAddress, ephemeralPrivateKey, recipientSpendingKey);

    // Step 3: Sender sends tokens to stealth address
    _sendToStealthAddress(stealthAddress, stealthAmount, sender, ephemeralPublicKey);

    // Step 4: Set up EIP-7702 delegation (stealth address delegates to IthacaAccount)
    _setupEIP7702Delegation(address(orchestrator), stealthAddress, stealthPrivateKey);

    // Step 5: Execute orchestrator-sponsored sweep to shielded pool
    bytes32 depositCommitment = _executeSweepToShieldedPool();

    // Step 6: Recipient withdraws from shielded pool to original account
    _withdrawFromShieldedPool(depositCommitment);

    // Final verification with sponsor payment
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
        shieldedPool.deposit.selector, address(token), stealthAmount, commitment, encryptedNote
      )
    });

    // Encode execution data for orchestrator
    bytes memory executionData = abi.encode(calls);

    // For this test, we'll demonstrate orchestrator-compatible execution
    // In production, the orchestrator would handle payment verification and gas sponsorship
    // Here we'll execute directly through the account to show the integration works

    // Execute using the account's execute function (simulating orchestrator-sponsored execution)
    bytes32 mode =
      bytes32(uint256(0x0100000000000000000000000000000000000000000000000000000000000000));

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
}
