// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Storage } from "src/libraries/Storage.sol";
import { Predeploys } from "src/libraries/Predeploys.sol";

// todo: what if this is upgraded? before and after that tx will be different
// this means option 2

contract TeaWAPOracle {
    ////////////////////////////////
    /////// STORAGE & EVENTS ///////
    ////////////////////////////////

    /// @notice The storage slot that contains data about the TWAP
    /// @dev  uint96(twapObservations) | address(oracle)
    bytes32 internal constant CUSTOM_GAS_TOKEN_ORACLE_SLOT = bytes32(uint256(keccak256("opstack.customgastoken.oracle")) - 1);

    /// @notice The storage slot that contains the fallback price, set by admin
    uint256 internal constant FALLBACK_PRICE_SLOT = bytes32(uint256(keccak256("opstack.customgastoken.fallbackprice")) - 1);

    /// @notice The storage slot that contains the last known oracle price
    /// @dev uint128(blockTime) | uint128(price)
    uint256 internal constant CACHED_ORACLE_PRICE_SLOT = bytes32(uint256(keccak256("opstack.customgastoken.cachedprice")) - 1);

    /// @notice A backup TEA/ETH ratio, in the case that the oracle is not set
    ///         and the fallback price is not set.
    uint256 public constant BACKUP_TEA_WEI_PER_ETH = 1_500_000e18;

    /// @notice Emitted when the oracle configuration is updated
    event VelodromeConfigUpdated(uint8 twapObservations, address oracle);

    /// @notice Emitted when the fallback price is updated
    event FallbackPriceUpdated(uint80 price, uint8 decimals);

    /// @notice Emitted when oracle price is cached
    event OraclePriceCached(uint128 blockTime, uint128 price);

    ////////////////////////////////
    ///// ORACLE FUNCTIONALITY /////
    ////////////////////////////////

    /// @notice Cache the latest oracle price in storage.
    /// @dev This price is used by the mempool to estimate L1 Data Costs when it doesn't have
    ///      access to the EVM.
    function cacheLatestOraclePrice() external {
        require(msg.sender == Predeploys.L1_BLOCK_ATTRIBUTES, "TeaWAPOracle: L1Block only");

        uint256 price = _getPrice();

        if (price > 0) {
            _setCachedOraclePrice(uint128(block.timestamp), uint128(price));
            emit OraclePriceCached(uint128(block.timestamp), uint128(price));
        }
    }

    function convertToTea(uint256 amount) external view returns (uint256) {
        return amount * _getTeaPerEth() / 1e18;
    }

    /// @notice Get the price of price of 1 Ether (1e18) in $TEA (18 decimals).
    /// @dev If the oracle is not set, we will return fallback price (also in 18 decimals).
    /// @dev If the fallback price is also not set, we will return a hardcoded backup.
    function _getTeaPerEth() public view returns (uint256) {
        (uint80 fallbackPrice, uint8 twapObservations, address oracle) = getOracleConfig();

        if (fallbackPrice == 0) fallbackPrice = BACKUP_TEA_WEI_PER_ETH;

        if (oracle == address(0)) return fallbackPrice;

        (bool success, uint256 price) = _getPrice(oracle, twapObservations);

        if (price == 0) return fallbackPrice;

        return price;
    }

    function _getPrice(address oracle) internal view returns (uint256 price) {
        // https://github.com/velodrome-finance/contracts/blob/main/contracts/Pool.sol
        // quote(address tokenIn, uint256 amountIn, uint256 granularity)
        (bool success, bytes memory returndata) = oracle.staticcall(
            abi.encodeWithSignature(
                "quote(address,uint256,uin256)",
                Predeploys.WETH, 1e18, twapObservations
            )
        );

        // It will revert if we don't have sufficient data points saved.
        if (!success || returndata.length < 32) return 0;

        return abi.decode(returndata, (uint256));
    }

    ////////////////////////////////
    //////////// ADMIN /////////////
    ////////////////////////////////

    function setVelodromeConfig(uint8 _twapObservations, address _oracle) external  {
        // todo: is this the right admin?
        require(msg.sender == Predeploys.PROXY_ADMIN, "TeaWAPOracle: admin only");
        require(_oracle != address(0), "VelodromeOracle: zero address");
        require(_twapObservations > 0, "VelodromeOracle: zero observations");

        (uint80 fallbackPrice, uint8 fallbackDecimals,,) = getOracleConfig();
        _setOracleConfig(fallbackPrice, fallbackDecimals, _twapObservations, _oracle);

        emit VelodromeConfigUpdated(_twapObservations, _oracle);
    }

    /// @dev _price = Native Token per ETH (with _decimals of precision)
    ///      For example, if $TEA is worth 1/10th of ETH, we could represent
    ///      this as 10 with 0 decimals of precision. If 1 $TEA was worth
    ///      2 ETH, we would need to set _price = 5 and _decimals = 1.
    function setFallbackPrice(uint80 _price, uint8 _decimals) external {
        require(msg.sender == Predeploys.PROXY_ADMIN, "TeaWAPOracle: admin only");
        require(_price > 0, "VelodromeOracle: zero price");

        (,, uint8 twapObservations, address oracle) = getOracleConfig();
        _setOracleConfig(_price, _decimals, twapObservations, oracle);

        emit FallbackPriceUpdated(_price, _decimals);
    }

    ////////////////////////////////
    ///// STORAGE READ / WRITE /////
    ////////////////////////////////

    function getFallbackPrice() public view returns (uint256) {
        return Storage.getUint(FALLBACK_PRICE_SLOT);
    }

    function _setFallbackPrice(uint256 _price) internal {
        Storage.setUint(FALLBACK_PRICE_SLOT, _price);
    }

    function getOracleConfig() public view returns (uint96, address) {
        uint256 data = Storage.getUint(CUSTOM_GAS_TOKEN_ORACLE_SLOT);

        uint8 twapObservations = uint96(data >> 160);
        address oracle = address(uint160(data));

        return (twapObservations, oracle);
    }

    function _setOracleConfig(uint96 _twapObservations, address _oracle) internal {
        uint256 data = uint256(_twapObservations) << 160 | uint160(_oracle);
        Storage.setUint(CUSTOM_GAS_TOKEN_ORACLE_SLOT, data);
    }

    function getCachedOraclePrice() public view returns (uint128, uint128) {
        uint256 data = Storage.getUint(CACHED_ORACLE_PRICE_SLOT);

        uint128 blockTime = uint128(data >> 128);
        uint128 price = uint128(data);

        return (blockTime, price);
    }

    function _setCachedOraclePrice(uint128 _blockTime, uint128 _price) internal {
        uint256 data = uint256(_blockTime) << 128 | uint128(_price);
        Storage.setUint(CACHED_ORACLE_PRICE_SLOT, data);
    }
}
