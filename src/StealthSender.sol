// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC5564Announcer} from "src/interfaces/IERC5564Announcer.sol";

contract StealthSender {
  using SafeERC20 for IERC20;

  IERC5564Announcer public immutable ANNOUNCER =
    IERC5564Announcer(0x55649E01B5Df198D18D95b5cc5051630cfD45564);

  error InsufficientBalance();
  error InvalidAmount();

  event StealthTransferSent(
    address indexed token,
    address indexed from,
    address indexed stealthAddress,
    uint256 amount,
    uint256 schemeId
  );

  function send(
    address token,
    address stealthAddress,
    uint256 amount,
    uint256 schemeId,
    bytes memory ephemeralPubKey,
    bytes memory metadata
  ) external {
    if (amount == 0) revert InvalidAmount();

    IERC20 erc20Token = IERC20(token);

    uint256 senderBalance = erc20Token.balanceOf(msg.sender);
    if (senderBalance < amount) revert InsufficientBalance();

    erc20Token.safeTransferFrom(msg.sender, stealthAddress, amount);

    ANNOUNCER.announce(schemeId, stealthAddress, ephemeralPubKey, metadata);

    emit StealthTransferSent(token, msg.sender, stealthAddress, amount, schemeId);
  }
}
