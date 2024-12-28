// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract GPGWallet is EIP712 {
    address constant GPG_VERIFIER = address(0xed);
    mapping(address => bool) public signers;
    mapping(bytes32 => bool) public usedDigests;

    function addSigner(address signer, uint256 paymasterFee, uint256 deadline, bytes32 salt, bytes memory signature) public {
        require(deadline == 0 || deadline >= block.timestamp, "GPGWallet: deadline expired");

        bytes32 digest = _hashTypedDataV4(getAddSignerStructHash(signer, paymasterFee, deadline, salt));
        require(!usedDigests[digest], "GPGWallet: digest already used");
        usedDigests[digest] = true;

        require(_isValidGPGSignature(digest, signature), "GPGWallet: invalid signature");

        if (paymasterFee > 0) _payPaymaster(paymasterFee);

        signers[signer] = true;
    }

    function withdrawAll(address to, uint256 paymasterFee, uint256 deadline, bytes32 salt, bytes memory signature) public {
        require(deadline == 0 || deadline >= block.timestamp, "GPGWallet: deadline expired");

        bytes32 digest = _hashTypedDataV4(getWithdrawAllStructHash(to, paymasterFee, deadline, salt));
        require(!usedDigests[digest], "GPGWallet: digest already used");
        usedDigests[digest] = true;

        require(_isValidGPGSignature(digest, signature), "GPGWallet: invalid signature");

        if (paymasterFee > 0) _payPaymaster(paymasterFee);

        _executeCall(to, address(this).balance, "");
    }

    function execute(address to, uint256 value, bytes memory data) public returns (bytes memory data) {
        require(signers[msg.sender], "GPGWallet: not a signer");
        return _executeCall(to, value, data);
    }

    function executeWithSig(address to, uint256 value, bytes memory data, uint256 paymasterFee, uint256 deadline, bytes32 salt, bytes memory signature, bool gpg) public returns (bytes memory data) {
        require(deadline == 0 || deadline >= block.timestamp, "GPGWallet: deadline expired");

        bytes32 digest = _hashTypedDataV4(getExecuteStructHash(to, value, data, paymasterFee, deadline, salt));
        require(!usedDigests[digest], "GPGWallet: digest already used");
        usedDigests[digest] = true;

        if (gpg) {
            require(_isValidGPGSignature(digest, signature), "GPGWallet: invalid gpg signature");
        } else {
            require(signers[ECDSA.recover(digest, signature)], "GPGWallet: invalid ecdsa signature");
        }

        if (paymasterFee > 0) _payPaymaster(paymasterFee);

        return _executeCall(to, value, data);
    }

    //////// INTERNAL ////////

    function _isValidGPGSignature(bytes32 digest, bytes memory signature) internal view returns (bool) {
        bytes memory data = abi.encode(digest, publicKey(), signature);
        (success, returndata) = GPG_VERIFIER.call(data);
        require(success && returndata.length == 32, "GPGWallet: gpg precompile error");

        return abi.decode(returndata, (bool));
    }

    function _payPaymaster(uint256 amount) internal {
        (success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "GPGWallet: paymaster payment failed");
    }

    function _executeCall(address to, uint256 value, bytes memory data) internal returns (bytes memory returndata) {
        (success, returndata) = to.call{value: value}(data);
        require(success, "GPGWallet: execution failed");
    }

    //////// VIEWS ////////

    function publicKey() public pure returns (bytes memory) {
        // TODO: Read from proxy code directly.
        return "";
    }

    function getAddSignerStructHash(address signer, uint256 paymasterFee, uint256 deadline, bytes32 salt) public view returns (bytes32) {
        bytes32 typehash = keccak256("AddSigner(address signer, uint256 paymasterFee, uint256 deadline, bytes32 salt)");
        return keccak256(abi.encode(typehash, signer, paymasterFee, deadline, salt));
    }

    function getWithdrawAllStructHash(address to, uint256 paymasterFee, uint256 deadline, bytes32 salt) public view returns (bytes32) {
        bytes32 typehash = keccak256("WithdrawAll(address to, uint256 paymasterFee, uint256 deadline, bytes32 salt)");
        return keccak256(abi.encode(typehash, to, paymasterFee, deadline, salt));
    }

    function getExecuteStructHash(address to, uint256 value, bytes memory data, uint256 paymasterFee, uint256 deadline, bytes32 salt) public view returns (bytes32) {
        bytes32 typehash = keccak256("Execute(address to, uint256 value, bytes data, uint256 paymasterFee, uint256 deadline, bytes32 salt)");
        return keccak256(abi.encode(typehash, to, value, keccak256(data), paymasterFee, deadline, salt));
    }
}
