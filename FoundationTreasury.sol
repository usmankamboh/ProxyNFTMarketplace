

// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity ^0.8.0;

import "./mixins/roles/AdminRole.sol";
import "./mixins/roles/OperatorRole.sol";
import "./mixins/CollateralManagement.sol";

/**
 * @title Manage revenue and roles for Foundation.
 * @notice All fees generated by the market are forwarded to this contract.
 * It also defines the Admin and Operator roles which are used in other contracts.
 */
contract FoundationTreasury is AdminRole, OperatorRole, CollateralManagement {
  /**
   * @notice Called one time after deployment to initialize the contract.
   * @param admin The account to add as the initial admin.
   */
  function initialize(address admin) external initializer {
    AdminRole._initializeAdminRole(admin);
  }
}
