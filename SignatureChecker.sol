// SPDX-License-Identifier: MIT
pragma solidity  0.8.15;
import "./ECDSA.sol";
import "./Address.sol";
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
library SignatureChecker is  IERC127{
    function isValidSignatureNow(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(hash, signature);
        if (error == ECDSA.RecoverError.NoError && recovered == signer) {
            return true;
        }

        (bool success, bytes memory result) = signer.staticcall(
            abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
        );
        return (success && result.length == 32 && abi.decode(result, (bytes4)) == IERC1271.isValidSignature.selector);
    }
}