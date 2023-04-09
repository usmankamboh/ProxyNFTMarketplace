// SPDX-License-Identifier: MIT
pragma solidity  0.8.15;
interface IERC1271 {
    function isValidSignature(
        bytes32 _messageHash,
        bytes memory _signature
    ) external view returns (bytes4 magicValue);

    function isValidSignature(
        bytes memory _data,
        bytes memory _signature
    ) external view returns (bytes4 magicValue);
}