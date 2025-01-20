// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { ISemver } from "src/universal/interfaces/ISemver.sol";
import { Constants } from "src/libraries/Constants.sol";
import { GasPayingToken, IGasToken } from "src/libraries/GasPayingToken.sol";
import { NotDepositor } from "src/libraries/L1BlockErrors.sol";
import { TeaWAPOracle } from "./TeaWAPOracle.sol";

/// @custom:proxied true
/// @custom:predeploy 0x4200000000000000000000000000000000000015
/// @title L1Block
/// @notice The L1Block predeploy gives users access to information about the last known L1 block.
///         Values within this contract are updated once per epoch (every L1 block) and can only be
///         set by the "depositor" account, a special system address. Depositor account transactions
///         are created by the protocol whenever we move to a new epoch.
contract L1Block is TeaWAPOracle, ISemver, IGasToken {
    /// @notice Event emitted when the gas paying token is set.
    event GasPayingTokenSet(address indexed token, uint8 indexed decimals, bytes32 name, bytes32 symbol);

    /// @notice Address of the special depositor account.
    function DEPOSITOR_ACCOUNT() public pure returns (address addr_) {
        addr_ = Constants.DEPOSITOR_ACCOUNT;
    }

    /// @notice The latest L1 block number known by the L2 system.
    uint64 public number;

    /// @notice The latest L1 timestamp known by the L2 system.
    uint64 public timestamp;

    /// @notice The latest L1 base fee.
    uint256 public basefee;

    /// @notice The latest L1 blockhash.
    bytes32 public hash;

    /// @notice The number of L2 blocks in the same epoch.
    uint64 public sequenceNumber;

    /// @notice The scalar value applied to the L1 blob base fee portion of the blob-capable L1 cost func.
    uint32 public blobBaseFeeScalar;

    /// @notice The scalar value applied to the L1 base fee portion of the blob-capable L1 cost func.
    uint32 public baseFeeScalar;

    /// @notice The versioned hash to authenticate the batcher by.
    bytes32 public batcherHash;

    /// @notice The overhead value applied to the L1 portion of the transaction fee.
    /// @custom:legacy
    uint256 public l1FeeOverhead;

    /// @notice The scalar value applied to the L1 portion of the transaction fee.
    /// @custom:legacy
    uint256 public l1FeeScalar;

    /// @notice The latest L1 blob base fee.
    uint256 public blobBaseFee;

    /// @custom:semver 1.5.1-beta.3
    function version() public pure virtual returns (string memory) {
        return "1.5.1-beta.3";
    }

    /// @notice Returns the gas paying token, its decimals, name and symbol.
    ///         If nothing is set in state, then it means ether is used.
    function gasPayingToken() public view returns (address addr_, uint8 decimals_) {
        (addr_, decimals_) = GasPayingToken.getToken();
    }

    /// @notice Returns the gas paying token name.
    ///         If nothing is set in state, then it means ether is used.
    function gasPayingTokenName() public view returns (string memory name_) {
        name_ = GasPayingToken.getName();
    }

    /// @notice Returns the gas paying token symbol.
    ///         If nothing is set in state, then it means ether is used.
    function gasPayingTokenSymbol() public view returns (string memory symbol_) {
        symbol_ = GasPayingToken.getSymbol();
    }

    /// @notice Getter for custom gas token paying networks. Returns true if the
    ///         network uses a custom gas token.
    function isCustomGasToken() public view returns (bool) {
        (address token,) = gasPayingToken();
        return token != Constants.ETHER;
    }

    /// @custom:legacy
    /// @notice Updates the L1 block values.
    /// @param _number         L1 blocknumber.
    /// @param _timestamp      L1 timestamp.
    /// @param _basefee        L1 basefee.
    /// @param _hash           L1 blockhash.
    /// @param _sequenceNumber Number of L2 blocks since epoch start.
    /// @param _batcherHash    Versioned hash to authenticate batcher by.
    /// @param _l1FeeOverhead  L1 fee overhead.
    /// @param _l1FeeScalar    L1 fee scalar.
    function setL1BlockValues(
        uint64 _number,
        uint64 _timestamp,
        uint256 _basefee,
        bytes32 _hash,
        uint64 _sequenceNumber,
        bytes32 _batcherHash,
        uint256 _l1FeeOverhead,
        uint256 _l1FeeScalar
    )
        external
    {
        require(msg.sender == DEPOSITOR_ACCOUNT(), "L1Block: only the depositor account can set L1 block values");

        number = _number;
        timestamp = _timestamp;
        basefee = _basefee;
        hash = _hash;
        sequenceNumber = _sequenceNumber;
        batcherHash = _batcherHash;
        l1FeeOverhead = _l1FeeOverhead;
        l1FeeScalar = _l1FeeScalar;
    }

    /// @notice Updates the L1 block values for an Ecotone upgraded chain.
    /// Params are packed and passed in as raw msg.data instead of ABI to reduce calldata size.
    /// Params are expected to be in the following order:
    ///   1. _baseFeeScalar      L1 base fee scalar
    ///   2. _blobBaseFeeScalar  L1 blob base fee scalar
    ///   3. _sequenceNumber     Number of L2 blocks since epoch start.
    ///   4. _timestamp          L1 timestamp.
    ///   5. _number             L1 blocknumber.
    ///   6. _basefee            L1 base fee.
    ///   7. _blobBaseFee        L1 blob base fee.
    ///   8. _hash               L1 blockhash.
    ///   9. _batcherHash        Versioned hash to authenticate batcher by.
    function setL1BlockValuesEcotone() public {
        _setL1BlockValuesEcotone();
    }

    /// @notice Updates the L1 block values for an Ecotone upgraded chain.
    /// Params are packed and passed in as raw msg.data instead of ABI to reduce calldata size.
    /// Params are expected to be in the following order:
    ///   1. _baseFeeScalar      L1 base fee scalar
    ///   2. _blobBaseFeeScalar  L1 blob base fee scalar
    ///   3. _sequenceNumber     Number of L2 blocks since epoch start.
    ///   4. _timestamp          L1 timestamp.
    ///   5. _number             L1 blocknumber.
    ///   6. _basefee            L1 base fee.
    ///   7. _blobBaseFee        L1 blob base fee.
    ///   8. _hash               L1 blockhash.
    ///   9. _batcherHash        Versioned hash to authenticate batcher by.
    function _setL1BlockValuesEcotone() internal {
        address depositor = DEPOSITOR_ACCOUNT();
        assembly {
            // Revert if the caller is not the depositor account.
            if xor(caller(), depositor) {
                mstore(0x00, 0x3cc50b45) // 0x3cc50b45 is the 4-byte selector of "NotDepositor()"
                revert(0x1C, 0x04) // returns the stored 4-byte selector from above
            }
            // sequencenum (uint64), blobBaseFeeScalar (uint32), baseFeeScalar (uint32)
            sstore(sequenceNumber.slot, shr(128, calldataload(4)))
            // number (uint64) and timestamp (uint64)
            sstore(number.slot, shr(128, calldataload(20)))
            sstore(basefee.slot, calldataload(36)) // uint256
            sstore(blobBaseFee.slot, calldataload(68)) // uint256
            sstore(hash.slot, calldataload(100)) // bytes32
            sstore(batcherHash.slot, calldataload(132)) // bytes32
        }
    }

    /// @notice Sets the gas paying token for the L2 system. Can only be called by the special
    ///         depositor account. This function is not called on every L2 block but instead
    ///         only called by specially crafted L1 deposit transactions.
    function setGasPayingToken(address _token, uint8 _decimals, bytes32 _name, bytes32 _symbol) external {
        if (msg.sender != DEPOSITOR_ACCOUNT()) revert NotDepositor();

        GasPayingToken.set({ _token: _token, _decimals: _decimals, _name: _name, _symbol: _symbol });

        emit GasPayingTokenSet({ token: _token, decimals: _decimals, name: _name, symbol: _symbol });
    }

    /////////////////////////////////
    /// L1 DATA COST CALCULATIONS ///
    /////////////////////////////////

    /// @notice The L1 Cost Intercept, defined in the Fjord spec.
    uint256 public constant L1_COST_INTERCEPT_POSITIVE = 42_585_600;

    /// @notice The L1 Cost FastLZ Coefficient, defined in the Fjord spec.
    uint256 public constant L1_COST_FASTLZ_COEF = 836_500;

    /// @notice The minimum transaction size, defined in the Fjord spec.
    uint256 public constant MIN_TRANSACTION_SIZE_SCALED = 100 * 1e6;

    /// @notice A backup TEA/ETH ratio, in the case that the oracle is not set
    ///         and the fallback price is not set.
    uint256 public constant BACKUP_TEA_PER_ETH = 1_500_000;

    /// @notice The amount of $TEA required to pay L1 Data Costs for the transaction.
    /// @param fastLzSize The size of the transaction after FastLZ compression (calculated in op-geth).
    /// @param isDepositTx Whether the transaction is a deposit transaction.
    /// @return l1DataCostTEA The amount of $TEA required to pay L1 Data Costs for the transaction.
    /// @return l1GasUsed An estimate of how much L1 gas was used (used in L2 receipts).
    /// @dev Called by the execution layer in L1CostFunc.
    function getL1DataCost(uint256 /* ones */, uint256 /* zeros */, uint256 fastLzSize, bool isDepositTx)
        external view returns (uint256 l1DataCostTEA, uint256 l1GasUsed)
    {
        // Deposit transactions are not included in blobs, so do not pay any L1 Data Cost.
        if (isDepositTx) return (0, 0);

        // Implement the Fjord calculation to determine the ETH L1 Data Cost.
        uint256 l1DataCostETH;
        (l1DataCostETH, l1GasUsed) = _calculateL1DataCostFjord(fastLzSize);

        // Use TeaWAPOracle to adjust the cost from ETH to $TEA.
        (uint256 nativeTokenPerETH, uint256 oracleDecimals) = _getTEAPerETH();
        if (nativeTokenPerETH == 0) {
            nativeTokenPerETH = BACKUP_TEA_PER_ETH;
            oracleDecimals = 0;
        }

        l1DataCostTEA = l1DataCostETH * nativeTokenPerETH / (10 ** oracleDecimals);
    }

    // Implements: https://specs.optimism.io/protocol/fjord/exec-engine.html#fees
    function _calculateL1DataCostFjord(uint256 fastLzSize) internal view returns (uint256, uint256) {
        // Fjord L1 cost function:
		// l1FeeScaled = baseFeeScalar*l1BaseFee*16 + blobFeeScalar*l1BlobBaseFee
		// estimatedSize = max(minTransactionSize, intercept + fastlzCoef*fastlzSize)
		// l1Cost = estimatedSize * l1FeeScaled / 1e12

        uint256 cdCostPerByte = baseFeeScalar * basefee * 16;
        uint256 blobCostPerByte = blobBaseFeeScalar * blobBaseFee;
        uint256 l1FeeScaled = cdCostPerByte + blobCostPerByte;

        uint256 estimatedSize = (fastLzSize * L1_COST_FASTLZ_COEF) - L1_COST_INTERCEPT_POSITIVE;
        if (estimatedSize < MIN_TRANSACTION_SIZE_SCALED) estimatedSize = MIN_TRANSACTION_SIZE_SCALED;

        uint256 l1Cost = l1FeeScaled * uint256(estimatedSize) / 1e12;
        uint256 cdGasUsed = uint256(estimatedSize) * 16 / 1e6;

        return (l1Cost, cdGasUsed);
    }
}
