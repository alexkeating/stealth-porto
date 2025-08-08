// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {StealthSender} from "src/StealthSender.sol";
import {IERC5564Announcer} from "src/interfaces/IERC5564Announcer.sol";
import {ERC20Mock} from "openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";

// Helper contract that matches the actual ERC5564Announcer implementation
contract ERC5564AnnouncerHelper {
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

contract StealthSenderTest is Test {
  StealthSender public stealthSender;
  ERC20Mock public token;

  address public sender = address(0x1);
  address public stealthAddress = address(0x2);
  uint256 public constant INITIAL_BALANCE = 1000 ether;
  uint256 public constant SCHEME_ID = 1;

  bytes public ephemeralPubKey = hex"04abcd";
  bytes public metadata = hex"01";

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

  function setUp() public {
    stealthSender = new StealthSender();
    token = new ERC20Mock();

    token.mint(sender, INITIAL_BALANCE);

    vm.prank(sender);
    token.approve(address(stealthSender), type(uint256).max);
  }

  function _deployAnnouncerAtAddress() internal {
    address announcer = address(stealthSender.ANNOUNCER());
    // Deploy the actual ERC5564Announcer implementation at the expected address
    vm.etch(announcer, address(new ERC5564AnnouncerHelper()).code);
  }
}

contract StealthSenderTest_Send is StealthSenderTest {
  function testFuzz_SendSuccessful(uint256 amount, address stealthAddr, uint256 schemeId) public {
    vm.assume(amount > 0 && amount <= INITIAL_BALANCE);
    vm.assume(stealthAddr != address(0) && stealthAddr != sender);

    _deployAnnouncerAtAddress();

    vm.expectEmit();
    emit Announcement(schemeId, stealthAddr, address(stealthSender), ephemeralPubKey, metadata);

    vm.expectEmit();
    emit StealthTransferSent(address(token), sender, stealthAddr, amount, schemeId);

    vm.prank(sender);
    stealthSender.send(address(token), stealthAddr, amount, schemeId, ephemeralPubKey, metadata);

    assertEq(token.balanceOf(sender), INITIAL_BALANCE - amount);
    assertEq(token.balanceOf(stealthAddr), amount);
  }

  function testFuzz_RevertWhen_AmountIsZero(address stealthAddr, uint256 schemeId) public {
    vm.assume(stealthAddr != address(0));

    vm.expectRevert(StealthSender.InvalidAmount.selector);
    vm.prank(sender);
    stealthSender.send(address(token), stealthAddr, 0, schemeId, ephemeralPubKey, metadata);
  }

  function testFuzz_RevertWhen_InsufficientBalance(
    uint256 excessAmount,
    address stealthAddr,
    uint256 schemeId
  ) public {
    vm.assume(excessAmount > 0 && excessAmount < type(uint256).max - INITIAL_BALANCE);
    vm.assume(stealthAddr != address(0));
    uint256 amount = INITIAL_BALANCE + excessAmount;

    vm.expectRevert(StealthSender.InsufficientBalance.selector);
    vm.prank(sender);
    stealthSender.send(address(token), stealthAddr, amount, schemeId, ephemeralPubKey, metadata);
  }

  function testFuzz_RevertWhen_NoAllowance(
    uint256 amount,
    address newSender,
    address stealthAddr,
    uint256 schemeId
  ) public {
    vm.assume(amount > 0 && amount <= INITIAL_BALANCE);
    vm.assume(newSender != address(0) && newSender != sender);
    vm.assume(stealthAddr != address(0));

    token.mint(newSender, INITIAL_BALANCE);

    vm.expectRevert();
    vm.prank(newSender);
    stealthSender.send(address(token), stealthAddr, amount, schemeId, ephemeralPubKey, metadata);
  }

  function testFuzz_SendMultipleTransfers(
    uint256 amount1,
    uint256 amount2,
    address stealthAddr1,
    address stealthAddr2,
    uint256 schemeId
  ) public {
    vm.assume(amount1 > 0 && amount2 > 0);
    vm.assume(amount1 <= INITIAL_BALANCE);
    vm.assume(amount2 <= INITIAL_BALANCE - amount1);
    vm.assume(stealthAddr1 != address(0) && stealthAddr1 != sender);
    vm.assume(stealthAddr2 != address(0) && stealthAddr2 != sender && stealthAddr2 != stealthAddr1);

    _deployAnnouncerAtAddress();

    vm.prank(sender);
    stealthSender.send(address(token), stealthAddr1, amount1, schemeId, ephemeralPubKey, metadata);

    vm.prank(sender);
    stealthSender.send(address(token), stealthAddr2, amount2, schemeId, ephemeralPubKey, metadata);

    assertEq(token.balanceOf(sender), INITIAL_BALANCE - amount1 - amount2);
    assertEq(token.balanceOf(stealthAddr1), amount1);
    assertEq(token.balanceOf(stealthAddr2), amount2);
  }

  function testFuzz_SendVariousAmounts(uint256 amount) public {
    vm.assume(amount > 0 && amount <= INITIAL_BALANCE);

    _deployAnnouncerAtAddress();

    vm.prank(sender);
    stealthSender.send(address(token), stealthAddress, amount, SCHEME_ID, ephemeralPubKey, metadata);

    assertEq(token.balanceOf(sender), INITIAL_BALANCE - amount);
    assertEq(token.balanceOf(stealthAddress), amount);
  }

  function testFuzz_SendVariousSchemeIds(uint256 schemeId) public {
    uint256 amount = 100 ether;

    _deployAnnouncerAtAddress();

    vm.expectEmit();
    emit Announcement(schemeId, stealthAddress, address(stealthSender), ephemeralPubKey, metadata);

    vm.prank(sender);
    stealthSender.send(address(token), stealthAddress, amount, schemeId, ephemeralPubKey, metadata);

    assertEq(token.balanceOf(stealthAddress), amount);
  }

  function testFuzz_SendToVariousStealthAddresses(address stealthAddr) public {
    vm.assume(stealthAddr != address(0) && stealthAddr != sender);
    uint256 amount = 100 ether;

    _deployAnnouncerAtAddress();

    vm.prank(sender);
    stealthSender.send(address(token), stealthAddr, amount, SCHEME_ID, ephemeralPubKey, metadata);

    assertEq(token.balanceOf(stealthAddr), amount);
  }

  function testFuzz_SendWithDifferentTokens(uint256 amount, address stealthAddr, uint256 schemeId)
    public
  {
    vm.assume(amount > 0 && amount <= INITIAL_BALANCE);
    vm.assume(stealthAddr != address(0) && stealthAddr != sender);

    ERC20Mock token2 = new ERC20Mock();
    token2.mint(sender, INITIAL_BALANCE);
    vm.prank(sender);
    token2.approve(address(stealthSender), type(uint256).max);

    _deployAnnouncerAtAddress();

    vm.prank(sender);
    stealthSender.send(address(token2), stealthAddr, amount, schemeId, ephemeralPubKey, metadata);

    assertEq(token2.balanceOf(sender), INITIAL_BALANCE - amount);
    assertEq(token2.balanceOf(stealthAddr), amount);
    assertEq(token.balanceOf(sender), INITIAL_BALANCE);
  }

  function testFuzz_SendWithAllParameters(
    uint256 amount,
    address stealthAddr,
    uint256 schemeId,
    bytes memory ephemeralKey,
    bytes memory metadataInput
  ) public {
    vm.assume(amount > 0 && amount <= INITIAL_BALANCE);
    vm.assume(stealthAddr != address(0) && stealthAddr != sender);
    vm.assume(ephemeralKey.length > 0 && ephemeralKey.length <= 100);
    vm.assume(metadataInput.length > 0 && metadataInput.length <= 100);

    _deployAnnouncerAtAddress();

    vm.expectEmit();
    emit Announcement(schemeId, stealthAddr, address(stealthSender), ephemeralKey, metadataInput);

    vm.expectEmit();
    emit StealthTransferSent(address(token), sender, stealthAddr, amount, schemeId);

    vm.prank(sender);
    stealthSender.send(address(token), stealthAddr, amount, schemeId, ephemeralKey, metadataInput);

    assertEq(token.balanceOf(sender), INITIAL_BALANCE - amount);
    assertEq(token.balanceOf(stealthAddr), amount);
  }

  function testFuzz_SendToSameAddressMultipleTimes(
    uint256[] memory amounts,
    address stealthAddr,
    uint256 schemeId
  ) public {
    vm.assume(stealthAddr != address(0) && stealthAddr != sender);
    vm.assume(amounts.length > 0 && amounts.length <= 10);

    uint256 totalAmount = 0;
    for (uint256 i = 0; i < amounts.length; i++) {
      vm.assume(amounts[i] > 0);
      vm.assume(amounts[i] <= INITIAL_BALANCE);
      if (totalAmount + amounts[i] < totalAmount) return; // Skip on overflow
      totalAmount += amounts[i];
    }
    vm.assume(totalAmount <= INITIAL_BALANCE);

    _deployAnnouncerAtAddress();

    for (uint256 i = 0; i < amounts.length; i++) {
      vm.prank(sender);
      stealthSender.send(
        address(token), stealthAddr, amounts[i], schemeId, ephemeralPubKey, metadata
      );
    }

    assertEq(token.balanceOf(sender), INITIAL_BALANCE - totalAmount);
    assertEq(token.balanceOf(stealthAddr), totalAmount);
  }
}
