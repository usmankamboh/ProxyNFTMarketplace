// SPDX-License-Identifier: MIT
pragma solidity  0.8.15;
import "./EnumerableSet.sol";
import "./AddressUpgradeable.sol";
import "./ContextUpgradeable.sol";
import "./Initializable.sol";
abstract contract OZAccessControlUpgradeable is Initializable, ContextUpgradeable {
  function __AccessControl_init() internal onlyInitializing {
    __Context_init_unchained();
    __AccessControl_init_unchained();
  }

  function __AccessControl_init_unchained() internal onlyInitializing {}

  using EnumerableSet for EnumerableSet.AddressSet;
  using AddressUpgradeable for address;

  struct RoleData {
    EnumerableSet.AddressSet members;
    bytes32 adminRole;
  }

  mapping(bytes32 => RoleData) private _roles;

  bytes32 internal constant DEFAULT_ADMIN_ROLE = 0x00;
  event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);
  event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
  event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

  /**
   * @dev Returns `true` if `account` has been granted `role`.
   */
  function hasRole(bytes32 role, address account) internal view returns (bool) {
    return _roles[role].members.contains(account);
  }
  function getRoleMemberCount(bytes32 role) internal view returns (uint256) {
    return _roles[role].members.length();
  }
  function getRoleMember(bytes32 role, uint256 index) internal view returns (address) {
    return _roles[role].members.at(index);
  }
  function getRoleAdmin(bytes32 role) internal view returns (bytes32) {
    return _roles[role].adminRole;
  }
  function grantRole(bytes32 role, address account) internal virtual {
    require(hasRole(_roles[role].adminRole, _msgSender()), "AccessControl: sender must be an admin to grant");

    _grantRole(role, account);
  }
  function revokeRole(bytes32 role, address account) internal virtual {
    require(hasRole(_roles[role].adminRole, _msgSender()), "AccessControl: sender must be an admin to revoke");

    _revokeRole(role, account);
  }
  function renounceRole(bytes32 role, address account) internal virtual {
    require(account == _msgSender(), "AccessControl: can only renounce roles for self");

    _revokeRole(role, account);
  }

  function _setupRole(bytes32 role, address account) internal {
    _grantRole(role, account);
  }
  function _setRoleAdmin(bytes32 role, bytes32 adminRole) private {
    emit RoleAdminChanged(role, _roles[role].adminRole, adminRole);
    _roles[role].adminRole = adminRole;
  }

  function _grantRole(bytes32 role, address account) private {
    if (_roles[role].members.add(account)) {
      emit RoleGranted(role, account, _msgSender());
    }
  }

  function _revokeRole(bytes32 role, address account) private {
    if (_roles[role].members.remove(account)) {
      emit RoleRevoked(role, account, _msgSender());
    }
  }

  /**
   * @notice This empty reserved space is put in place to allow future versions to add new
   * variables without shifting down storage in the inheritance chain.
   * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
   */
  uint256[49] private __gap;
}
