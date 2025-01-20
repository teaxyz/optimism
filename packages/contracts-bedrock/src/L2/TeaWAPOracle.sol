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

    /// @notice A backup TEA/ETH ratio, in the case that the oracle is not set
    ///         and the fallback price is not set.
    uint256 public constant BACKUP_TEA_WEI_PER_ETH = 1_500_000e18;

    /// @notice Emitted when the oracle configuration is updated
    event OracleConfigUpdated(uint96 twapObservations, address oracle);

    /// @notice Emitted when the fallback price is updated
    event FallbackPriceUpdated(uint256 price);

    ////////////////////////////////
    ///// ORACLE FUNCTIONALITY /////
    ////////////////////////////////

    /// @notice Convert the inputted amount of ETH (18 decimals) to $TEA
    /// @dev amount (18 decimals) * teaPerETH (18 decimals) / 1e18 = teaAmount (18 decimals)
    function convertETHToTea(uint256 amount) external view returns (uint256) {
        return amount * teaPerETH() / 1e18;
    }

    /// @notice Get the price of price of 1 Ether (1e18) in $TEA (18 decimals).
    /// @dev If the oracle is not set, we will return fallback price (also in 18 decimals).
    /// @dev If the fallback price is also not set, we will return a hardcoded backup.
    function teaPerETH() public view returns (uint256) {
        // Load oracle config from storage.
        (uint96 twapObservations, address oracle) = getOracleConfig();

        // Load fallback price from storage. (If it hasn't been set, use hardcoded backup.)
        uint256 fallbackPrice = getFallbackPrice();
        if (fallbackPrice == 0) fallbackPrice = BACKUP_TEA_WEI_PER_ETH;

        // If there is no oracle set, return the fallback price.
        if (oracle == address(0)) return fallbackPrice;

        // Call the oracle to get the time weighted price.
        // https://github.com/velodrome-finance/contracts/blob/main/contracts/Pool.sol
        // quote(address tokenIn, uint256 amountIn, uint256 granularity)
        (bool success, bytes memory returndata) = oracle.staticcall(
            abi.encodeWithSignature(
                "quote(address,uint256,uin256)",
                Predeploys.WETH, 1e18, twapObservations
            )
        );

        // Ensure this function doesn't revert.
        // It will revert if we don't have sufficient data points saved.
        if (!success || returndata.length < 32) return 0;

        // Return the price, or the fallback price if the price is 0.
        uint256 price = abi.decode(returndata, (uint256));
        return price > 0 ? price : fallbackPrice;
    }

    ////////////////////////////////
    //////////// ADMIN /////////////
    ////////////////////////////////

    /// @param _twapObservations Number of observations to ask from the oracle
    /// @param _oracle Address of the oracle contract to use
    function setOracleConfig(uint96 _twapObservations, address _oracle) external  {
        // todo: is this the right admin?
        require(msg.sender == Predeploys.PROXY_ADMIN, "TeaWAPOracle: admin only");
        require(_oracle != address(0), "VelodromeOracle: zero address");
        require(_twapObservations > 0, "VelodromeOracle: zero observations");

        _setOracleConfig(_twapObservations, _oracle);

        emit OracleConfigUpdated(_twapObservations, _oracle);
    }

    /// @param _price Fallback price to use if oracle fails
    /// @dev Price should be set in wei of $TEA per 18 decimals of ETH
    function setFallbackPrice(uint256 _price) external {
        require(msg.sender == Predeploys.PROXY_ADMIN, "TeaWAPOracle: admin only");
        require(_price > 0, "VelodromeOracle: zero price");

        _setFallbackPrice(_price);

        emit FallbackPriceUpdated(_price, _decimals);
    }

    ////////////////////////////////
    ///// STORAGE READ / WRITE /////
    ////////////////////////////////

    /// @return The fallback price to use if the oracle fails
    /// @dev Price is in wei of $TEA per 18 decimals of ETH
    function getFallbackPrice() public view returns (uint256) {
        return Storage.getUint(FALLBACK_PRICE_SLOT);
    }

    function _setFallbackPrice(uint256 _price) internal {
        Storage.setUint(FALLBACK_PRICE_SLOT, _price);
    }

    /// @return twapObservations The number of TWAP observations to use with the oracle
    /// @return oracle The address of the oracle contract that is being used
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
}
