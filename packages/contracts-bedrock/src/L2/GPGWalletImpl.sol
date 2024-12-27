// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract GPGWallet is EIP712 {
    address constant GPG_VERIFIER = address(0xed);
    mapping(address => bool) public signers;

    function addSigner(address signer, uint256 paymasterFee, bytes memory signature) public {
        bytes32 digest = _hashTypedDataV4(getAddSignerStructHash(signer, paymasterFee));
        require(_isValidGPGSignature(digest, signature), "GPGWallet: invalid signature");
        if (paymasterFee > 0) _payPaymaster(paymasterFee);
        signers[signer] = true;
    }

    function withdrawAll(address to, uint256 paymasterFee, bytes memory signature) public {
        bytes32 digest = _hashTypedDataV4(getWithdrawAllStructHash(to));
        require(_isValidGPGSignature(digest, signature), "GPGWallet: invalid signature");
        if (paymasterFee > 0) _payPaymaster(paymasterFee);

        (success, ) = to.call{value: address(this).balance}("");
        require(success, "GPGWallet: withdraw failed");
    }

    function execute(address to, uint256 value, bytes memory data) public returns (bytes memory data) {
        require(signers[msg.sender], "GPGWallet: not a signer");
        (success, data) = to.call{value: value}(data);
        require(success, "GPGWallet: execution failed");
    }

    function executeWithSig(address to, uint256 value, bytes memory data, uint256 paymasterFee, bytes memory signature, bool gpg) public {
        bytes32 digest = _hashTypedDataV4(getExecuteStructHash(to, value, data, paymasterFee));

        if (gpg) {
            require(_isValidGPGSignature(digest, signature), "GPGWallet: invalid gpg signature");
        } else {
            require(signers[ECDSA.recover(digest, signature)], "GPGWallet: invalid ecdsa signature");
        }

        if (paymasterFee > 0) _payPaymaster(paymasterFee);

        (success, ) = to.call{value: value}(data);
        require(success, "GPGWallet: execution failed");
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

    //////// VIEWS ////////

    function publicKey() public pure returns (bytes memory) {
        // TODO: Read from proxy code directly.
        return "";
    }

    function getAddSignerStructHash(address signer, uint256 paymasterFee) public view returns (bytes32) {
        bytes32 typehash = keccak256("AddSigner(address signer, uint256 paymasterFee)");
        return keccak256(abi.encode(typehash, signer, paymasterFee));
    }

    function getWithdrawAllStructHash(address signer, uint256 paymasterFee) public view returns (bytes32) {
        bytes32 typehash = keccak256("WithdrawAll(address to, uint256 paymasterFee)");
        return keccak256(abi.encode(typehash, signer, paymasterFee));
    }

    function getExecuteStructHash(address to, uint256 value, bytes memory data, uint256 paymasterFee) public view returns (bytes32) {
        bytes32 typehash = keccak256("Execute(address to, uint256 value, bytes calldata, uint256 paymasterFee)");
        return keccak256(abi.encode(typehash, to, value, keccak256(data), paymasterFee));
    }
}
