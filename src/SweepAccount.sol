// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {IthacaAccount} from "lib/account/src/IthacaAccount.sol";
import {EnumerableSetLib} from "lib/account/lib/solady/src/utils/EnumerableSetLib.sol";

/// @title SweepAccount
/// @notice An Ithaca account that can sweep tokens based on signed intents
/// @dev This contract inherits from IthacaAccount for orchestrator compatibility and adds sweep functionality
contract SweepAccount is IthacaAccount {
  using SafeERC20 for IERC20;
  using ECDSA for bytes32;
  using EnumerableSetLib for EnumerableSetLib.AddressSet;

  /// @notice The delegating EOA owner of this account
  address public immutable delegatingOwner;

  /// @notice Nonce for replay protection
  mapping(uint256 => bool) public usedNonces;

  /// @notice Intent structure for sweep operations
  struct SweepIntent {
    address token;
    address recipient;
    uint256 amount;
    uint256 nonce;
    uint256 expiry;
  }

  /// @notice EIP-712 typehash for SweepIntent
  bytes32 public constant SWEEP_INTENT_TYPEHASH = keccak256(
    "SweepIntent(address token,address recipient,uint256 amount,uint256 nonce,uint256 expiry)"
  );
  
  /// @notice Domain separator for sweep intents (different from regular IthacaAccount operations)
  bytes32 private immutable SWEEP_DOMAIN_SEPARATOR;

  error InvalidSignature();
  error NonceAlreadyUsed();
  error IntentExpired();
  error UnauthorizedCaller();
  error InsufficientBalance();
  error TransferFailed();

  event TokensSwept(
    address indexed token, address indexed recipient, uint256 amount, uint256 nonce
  );

  /// @notice Creates a new SweepAccount
  /// @param _orchestrator The orchestrator contract address
  /// @param _delegatingOwner The EOA that will delegate to this account via EIP-7702
  constructor(address _orchestrator, address _delegatingOwner) IthacaAccount(_orchestrator) {
    if (_delegatingOwner == address(0)) revert UnauthorizedCaller();
    delegatingOwner = _delegatingOwner;
    
    // Initialize the account with the delegating owner as a Secp256k1 key
    // The public key for Secp256k1 in this case is the address itself
    Key memory ownerKey = Key({
      expiry: 0, // Never expires
      keyType: KeyType.Secp256k1,
      isSuperAdmin: true, // Allow the owner to manage keys
      publicKey: abi.encodePacked(_delegatingOwner)
    });
    bytes32 keyHash = _addKey(ownerKey);
    
    // Store the keyHash for testing purposes
    assembly {
      sstore(0x1337, keyHash)
    }
    
    // Allow the orchestrator to verify signatures for this key
    if (_orchestrator != address(0)) {
      _getKeyExtraStorage(keyHash).checkers.add(_orchestrator);
    }
    
    // Compute domain separator for sweep intents
    SWEEP_DOMAIN_SEPARATOR = keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("SweepAccount")),
        keccak256(bytes("1")),
        block.chainid,
        address(this)
      )
    );
  }

  /// @notice Execute a sweep based on a signed intent
  /// @param intent The sweep intent containing transfer details
  /// @param signature The signature from the owner authorizing the sweep
  function executeSweep(SweepIntent calldata intent, bytes calldata signature) external {
    _verifyIntent(intent, signature);
    _performSweep(intent);
  }

  /// @notice Execute multiple sweeps in a single transaction
  /// @param intents Array of sweep intents
  /// @param signatures Array of signatures corresponding to each intent
  function executeBatchSweep(SweepIntent[] calldata intents, bytes[] calldata signatures) external {
    if (intents.length != signatures.length) revert InvalidSignature();

    for (uint256 i = 0; i < intents.length; i++) {
      _verifyIntent(intents[i], signatures[i]);
      _performSweep(intents[i]);
    }
  }

  /// @notice Verify that an intent is valid and signed by the owner
  function _verifyIntent(SweepIntent calldata intent, bytes calldata signature) internal view {
    if (intent.expiry != 0 && block.timestamp > intent.expiry) revert IntentExpired();

    if (usedNonces[intent.nonce]) revert NonceAlreadyUsed();

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

    // Use custom domain separator for sweep intents
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", SWEEP_DOMAIN_SEPARATOR, structHash));
    address signer = digest.recover(signature);

    if (signer != delegatingOwner) revert InvalidSignature();
  }

  /// @notice Perform the actual token sweep
  function _performSweep(SweepIntent calldata intent) internal {
    usedNonces[intent.nonce] = true;

    if (intent.token == address(0)) {
      uint256 balance = address(this).balance;
      if (balance < intent.amount) revert InsufficientBalance();

      (bool success,) = intent.recipient.call{value: intent.amount}("");
      if (!success) revert TransferFailed();
    } else {
      IERC20 token = IERC20(intent.token);
      uint256 balance = token.balanceOf(address(this));
      if (balance < intent.amount) revert InsufficientBalance();

      token.safeTransfer(intent.recipient, intent.amount);
    }

    emit TokensSwept(intent.token, intent.recipient, intent.amount, intent.nonce);
  }

  /// @notice Execute a batch of calls (for compatibility with orchestrator)
  /// @param calls Array of calls encoded as (target, value, data)
  /// @return results Array of return data from each call
  function execute(bytes calldata calls) public returns (bytes[] memory results) {
    // Only allow orchestrator, self, or delegatingOwner to call
    if (msg.sender != delegatingOwner && msg.sender != address(this) && msg.sender != ORCHESTRATOR) {
      revert UnauthorizedCaller();
    }

    (address[] memory targets, uint256[] memory values, bytes[] memory calldatas) =
      abi.decode(calls, (address[], uint256[], bytes[]));

    results = new bytes[](targets.length);

    for (uint256 i = 0; i < targets.length; i++) {
      (bool success, bytes memory result) = targets[i].call{value: values[i]}(calldatas[i]);
      if (!success) {
        assembly {
          revert(add(result, 0x20), mload(result))
        }
      }
      results[i] = result;
    }
  }

  /// @notice Check if a nonce has been used
  /// @param nonce The nonce to check
  /// @return Whether the nonce has been used
  function isNonceUsed(uint256 nonce) external view returns (bool) {
    return usedNonces[nonce];
  }

  /// @notice Get the owner address (for backwards compatibility)
  function owner() external view returns (address) {
    return delegatingOwner;
  }
  
  /// @notice Get the owner's keyHash (for testing)
  function getOwnerKeyHash() external view returns (bytes32) {
    bytes32 keyHash;
    assembly {
      keyHash := sload(0x1337)
    }
    return keyHash;
  }
  
  /// @notice Allows the account to receive ETH
  receive() external payable override {}
}
