// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title GPGWallet
/// @notice A smart contract wallet that supports both GPG and ECDSA signatures for transaction execution
/// @dev Implements EIP-712 for secure message signing and verification
/// @custom:security-contact security@example.com
contract GPGWallet is EIP712 {
    /// @dev Address of the GPG signature verification precompile
    address constant GPG_VERIFIER = address(0xed);

    /// @notice Mapping of authorized signers for the wallet
    /// @dev Address to boolean mapping where true indicates an authorized signer
    mapping(address => bool) public signers;

    /// @notice Mapping to track used message digests to prevent replay attacks
    /// @dev Digest to boolean mapping where true indicates the digest has been used
    mapping(bytes32 => bool) public usedDigests;

    /// @notice Adds a new signer to the wallet using a GPG signature
    /// @dev Validates the signature and deadline before adding the signer
    /// @param signer Address of the new signer to add
    /// @param paymasterFee Fee to be paid to the paymaster (if any)
    /// @param deadline Timestamp after which the signature is no longer valid (0 for no deadline)
    /// @param salt Random value to ensure uniqueness of the message
    /// @param signature GPG signature of the typed data
    function addSigner(address signer, uint256 paymasterFee, uint256 deadline, bytes32 salt, bytes memory signature) public {
        require(deadline == 0 || deadline >= block.timestamp, "GPGWallet: deadline expired");

        bytes32 digest = _hashTypedDataV4(getAddSignerStructHash(signer, paymasterFee, deadline, salt));
        require(!usedDigests[digest], "GPGWallet: digest already used");
        usedDigests[digest] = true;

        require(_isValidGPGSignature(digest, signature), "GPGWallet: invalid signature");

        if (paymasterFee > 0) _payPaymaster(paymasterFee);

        signers[signer] = true;
    }

    /// @notice Withdraws all funds from the wallet to a specified address
    /// @dev Requires a valid GPG signature to execute
    /// @param to Address to send the funds to
    /// @param paymasterFee Fee to be paid to the paymaster (if any)
    /// @param deadline Timestamp after which the signature is no longer valid (0 for no deadline)
    /// @param salt Random value to ensure uniqueness of the message
    /// @param signature GPG signature of the typed data
    function withdrawAll(address to, uint256 paymasterFee, uint256 deadline, bytes32 salt, bytes memory signature) public {
        require(deadline == 0 || deadline >= block.timestamp, "GPGWallet: deadline expired");

        bytes32 digest = _hashTypedDataV4(getWithdrawAllStructHash(to, paymasterFee, deadline, salt));
        require(!usedDigests[digest], "GPGWallet: digest already used");
        usedDigests[digest] = true;

        require(_isValidGPGSignature(digest, signature), "GPGWallet: invalid signature");

        if (paymasterFee > 0) _payPaymaster(paymasterFee);

        _executeCall(to, address(this).balance, "");
    }

    /// @notice Executes a transaction if called by an authorized signer
    /// @dev Direct execution method for authorized signers
    /// @param to Destination address for the transaction
    /// @param value Amount of ETH to send
    /// @param data Calldata for the transaction
    /// @return data Return data from the executed call
    function execute(address to, uint256 value, bytes memory data) public returns (bytes memory data) {
        require(signers[msg.sender], "GPGWallet: not a signer");
        return _executeCall(to, value, data);
    }

    /// @notice Executes a transaction with either a GPG or ECDSA signature
    /// @dev Supports both signature types for maximum flexibility
    /// @param to Destination address for the transaction
    /// @param value Amount of ETH to send
    /// @param data Calldata for the transaction
    /// @param paymasterFee Fee to be paid to the paymaster (if any)
    /// @param deadline Timestamp after which the signature is no longer valid (0 for no deadline)
    /// @param salt Random value to ensure uniqueness of the message
    /// @param signature The signature (either GPG or ECDSA)
    /// @param gpg Boolean indicating if the signature is GPG (true) or ECDSA (false)
    /// @return data Return data from the executed call
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

    /// @dev Verifies a GPG signature using the precompile
    /// @param digest The message digest to verify
    /// @param signature The GPG signature to verify
    /// @return bool True if the signature is valid
    function _isValidGPGSignature(bytes32 digest, bytes memory signature) internal view returns (bool) {
        bytes memory data = abi.encode(digest, publicKey(), signature);
        (success, returndata) = GPG_VERIFIER.call(data);
        require(success && returndata.length == 32, "GPGWallet: gpg precompile error");

        return abi.decode(returndata, (bool));
    }

    /// @dev Pays the paymaster their fee
    /// @param amount Amount to pay the paymaster
    function _payPaymaster(uint256 amount) internal {
        (success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "GPGWallet: paymaster payment failed");
    }

    /// @dev Executes a call to an external contract
    /// @param to Address to call
    /// @param value Amount of ETH to send
    /// @param data Calldata for the transaction
    /// @return returndata Data returned from the call
    function _executeCall(address to, uint256 value, bytes memory data) internal returns (bytes memory returndata) {
        (success, returndata) = to.call{value: value}(data);
        require(success, "GPGWallet: execution failed");
    }

    //////// VIEWS ////////

    /// @notice Returns the GPG public key associated with this wallet
    /// @dev Currently returns empty bytes - implementation pending
    /// @return bytes The GPG public key
    function publicKey() public pure returns (bytes memory) {
        // TODO: Read from proxy code directly.
        return "";
    }

    /// @notice Computes the struct hash for adding a signer
    /// @param signer Address of the signer to add
    /// @param paymasterFee Fee to be paid to the paymaster
    /// @param deadline Timestamp after which the signature is invalid
    /// @param salt Random value to ensure uniqueness
    /// @return bytes32 The computed struct hash
    function getAddSignerStructHash(address signer, uint256 paymasterFee, uint256 deadline, bytes32 salt) public view returns (bytes32) {
        bytes32 typehash = keccak256("AddSigner(address signer, uint256 paymasterFee, uint256 deadline, bytes32 salt)");
        return keccak256(abi.encode(typehash, signer, paymasterFee, deadline, salt));
    }

    /// @notice Computes the struct hash for withdrawing all funds
    /// @param to Address to withdraw to
    /// @param paymasterFee Fee to be paid to the paymaster
    /// @param deadline Timestamp after which the signature is invalid
    /// @param salt Random value to ensure uniqueness
    /// @return bytes32 The computed struct hash
    function getWithdrawAllStructHash(address to, uint256 paymasterFee, uint256 deadline, bytes32 salt) public view returns (bytes32) {
        bytes32 typehash = keccak256("WithdrawAll(address to, uint256 paymasterFee, uint256 deadline, bytes32 salt)");
        return keccak256(abi.encode(typehash, to, paymasterFee, deadline, salt));
    }

    /// @notice Computes the struct hash for executing a transaction
    /// @param to Destination address for the transaction
    /// @param value Amount of ETH to send
    /// @param data Calldata for the transaction
    /// @param paymasterFee Fee to be paid to the paymaster
    /// @param deadline Timestamp after which the signature is invalid
    /// @param salt Random value to ensure uniqueness
    /// @return bytes32 The computed struct hash
    function getExecuteStructHash(address to, uint256 value, bytes memory data, uint256 paymasterFee, uint256 deadline, bytes32 salt) public view returns (bytes32) {
        bytes32 typehash = keccak256("Execute(address to, uint256 value, bytes data, uint256 paymasterFee, uint256 deadline, bytes32 salt)");
        return keccak256(abi.encode(typehash, to, value, keccak256(data), paymasterFee, deadline, salt));
    }
}
