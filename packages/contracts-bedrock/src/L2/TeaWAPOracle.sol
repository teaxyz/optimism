// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Storage } from "src/libraries/Storage.sol";
import { Predeploys } from "src/libraries/Predeploys.sol";
import { IVelodromePool } from "interfaces/L2/IVelodromePool.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

contract TeaWAPOracle {
    ////////////////////////////////
    /////// STORAGE & EVENTS ///////
    ////////////////////////////////

    /// @notice The storage slot that contains data about the TWAP oracle
    /// @dev  uint16(twapObservations) | uint80(minWethAmount) | address(oracle)
    bytes32 public constant CUSTOM_GAS_TOKEN_ORACLE_SLOT = bytes32(uint256(keccak256("tea.customgastoken.oracle")) - 1);

    /// @notice The storage slot for the WETH address and its token position in the oracle
    /// @dev bool(token0?) | address(WETH)
    bytes32 public constant WETH_ADDRESS_SLOT = bytes32(uint256(keccak256("tea.customgastoken.weth")) - 1);

    /// @notice The storage slot for the latest price
    /// @dev uint96(latestTime) | uint160(latestPrice)
    bytes32 public constant CUSTOM_GAS_TOKEN_PRICE_SLOT = bytes32(uint256(keccak256("tea.customgastoken.price")) - 1);

    /// @dev This price is stored as a uint160 to align with the `latestPrice` in the previous slot
    bytes32 public constant FALLBACK_PRICE_SLOT = bytes32(uint256(keccak256("tea.customgastoken.fallbackprice")) - 1);

    /// @notice A backup TEA/ETH ratio, in the case that the oracle is not set
    ///         and the fallback price is not set.
    uint160 public constant BACKUP_TEA_WEI_PER_ETH = 1_500_000e18;

    /// @notice The minimum WETH balance of the pool needed for the oracle to be valid.
    /// @dev If the pool has less than this balance, it may be too easy to manipulate.
    uint256 public constant MIN_WETH_BALANCE = 1e18;

    /// @notice The maximum amount of time we will allow failed oracle calls before
    ///         setting the storage value to the fallback.
    uint256 public constant MAX_ORACLE_DOWNTIME = 5 minutes;

    /// @notice One billion (1e9), used for oracle calls and other calculations.
    uint256 constant GWEI = 1e9;

    /// @notice Emitted when the price is updated
    event NewPriceSet(uint160 price);

    /// @notice Emitted when the oracle configuration is updated
    event OracleConfigUpdated(uint16 twapObservations, uint80 minWethBalance, address oracle);

    /// @notice Emitted when the fallback price is updated
    event FallbackPriceUpdated(uint256 price);

    ////////////////////////////////
    ///// ORACLE FUNCTIONALITY /////
    ////////////////////////////////

    /// @notice Convert the inputted amount of ETH (18 decimals) to $TEA
    /// @dev amount (18 decimals) * teaPerETH (18 decimals) / 1e18 = teaAmount (18 decimals)
    function convertETHToTea(uint256 amount) external view returns (uint256) {
        (, uint160 rate) = teaPerETH();
        return amount * rate / 1e18;
    }

    /// @notice Get the price of price of 1 Ether (1e18) in $TEA (18 decimals).
    /// @return valid Returned a valid price from the oracle (ie false = fallback)
    /// @return price The price of 1 Ether in $TEA (18 decimals)
    /// @dev If the oracle is not set, we will return fallback price (also in 18 decimals).
    /// @dev If the fallback price is also not set, we will return a hardcoded backup.
    function teaPerETH() public view returns (bool, uint160) {
        // Load oracle config from storage.
        (
            address oracle,
            uint16 twapObservations,
            uint80 minWethBalance,
            bool wethT0,
            address weth
        ) = getOracleConfig();

        // Load fallback price from storage.
        // If it hasn't been set, this will return hardcoded backup.
        uint160 fallbackPrice = getFallbackPrice();

        // If there is no oracle set, return the fallback price.
        if (oracle == address(0)) return (false, fallbackPrice);

        // If Velodrome is paused, return the fallback price.
        (bool success, bytes memory returndata) = oracle.staticcall(abi.encodeWithSignature("factory()"));
        {
            if (!success || returndata.length != 32) return (false, fallbackPrice);
            address factory = abi.decode(returndata, (address));

            (success, returndata) = factory.staticcall(abi.encodeWithSignature("isPaused()"));
            if (!success || returndata.length != 32) return (false, fallbackPrice);
            bool paused = abi.decode(returndata, (bool));
            if (paused) return (false, fallbackPrice);
        }

        // If there is too little value in the pool, it may be manipulated.
        (success, returndata) = oracle.staticcall(
            abi.encodeWithSignature("getReserves()")
        );
        if (!success || returndata.length != 96) return (false, fallbackPrice);
        (uint256 r0, uint256 r1,) = abi.decode(returndata, (uint, uint, uint));

        // Use WETH reserves for this reliability, because it's the more stable token price.
        uint256 wethReserves = wethT0 ? r0 : r1;
        if (wethReserves < minWethBalance) return (false, fallbackPrice);

        // Call the oracle to get the time weighted price.
        // https://github.com/velodrome-finance/contracts/blob/main/contracts/Pool.sol
        // quote(address tokenIn, uint256 amountIn, uint256 granularity)
        (success, returndata) = oracle.staticcall(
            abi.encodeWithSignature(
                "quote(address,uint256,uint256)",
                weth, GWEI, twapObservations
            )
        );

        // It will revert if we don't have sufficient data points saved.
        if (!success || returndata.length < 32) return (false, fallbackPrice);

        // Return the price, or the fallback price if the price is out of range.
        uint256 price = abi.decode(returndata, (uint256));
        if (price == 0 || price > type(uint160).max) {
            // If the price is zero, return the fallback price.
            if (price == 0) return (false, fallbackPrice);

            // Price is in GWEI because that was the quote requested.
            // Multiply by GWEI to convert to 18 decimals (making sure no overflow).
            uint256 oldPrice = price;
            unchecked { price = price * GWEI; }
            if (price / GWEI != oldPrice) return (false, fallbackPrice);

            // If the new price is greater than the max uint160, return the fallback price.
            if (price > type(uint160).max) return (false, fallbackPrice);
        }
        return (true, uint160(price));
    }

    ////////////////////////////////
    //////////// ADMIN /////////////
    ////////////////////////////////

    /// @param _twapObservations Number of observations to ask from the oracle
    /// @param _minWethBalance Minimum WETH balance of the pool needed for the oracle to be valid
    /// @param _oracle Address of the oracle contract to use
    function setOracleConfig(
        uint16 _twapObservations,
        uint80 _minWethBalance,
        address _oracle
    ) external {
        require(_oracle != address(0), "TeaWAPOracle: zero address");
        require(_twapObservations > 0, "TeaWAPOracle: zero observations");
        require(_minWethBalance > 0, "TeaWAPOracle: zero min WETH balance");

        _setOracleConfig(_twapObservations, _minWethBalance, _oracle);

        emit OracleConfigUpdated(_twapObservations, _minWethBalance, _oracle);
    }

    /// @param _price Fallback price to use if oracle fails
    /// @dev Price should be set in wei of $TEA per 18 decimals of ETH
    function setFallbackPrice(uint160 _price) external {
        require(msg.sender == Ownable(Predeploys.PROXY_ADMIN).owner(), "TeaWAPOracle: admin only");
        require(_price > 0, "TeaWAPOracle: zero fallback price");

        _setFallbackPrice(_price);

        emit FallbackPriceUpdated(_price);
    }

    ////////////////////////////////
    ///// STORAGE READ / WRITE /////
    ////////////////////////////////

    /// @return The latest price data from the oracle
    /// @dev Price is in wei of $TEA per 18 decimals of ETH
    function getLatestPrice() public view returns (uint96, uint160) {
        uint256 data = Storage.getUint(CUSTOM_GAS_TOKEN_PRICE_SLOT);

        uint96 latestTime = uint96(data >> 160);
        uint160 latestPrice = uint160(data);

        return (latestTime, latestPrice);
    }

    function _setLatestPrice(uint160 _price) internal {
        uint256 data = uint256(block.timestamp) << 160 | uint160(_price);
        Storage.setUint(CUSTOM_GAS_TOKEN_PRICE_SLOT, data);

        emit NewPriceSet(_price);
    }

    /// @return The fallback price to use if the oracle fails
    /// @dev Price is in wei of $TEA per 18 decimals of ETH
    /// @dev If the fallback price isn't set, returns a hardcoded backup.
    function getFallbackPrice() public view returns (uint160) {
        uint256 fallbackPrice = Storage.getUint(FALLBACK_PRICE_SLOT);
        if (fallbackPrice == 0) fallbackPrice = BACKUP_TEA_WEI_PER_ETH;

        // This downcast is safe because the setter stores the value as a uint160.
        return uint160(fallbackPrice);
    }

    function _setFallbackPrice(uint160 _price) internal {
        Storage.setUint(FALLBACK_PRICE_SLOT, _price);
    }

    /// @return oracle The address of the oracle contract that is being used
    /// @return twapObservations The number of TWAP observations to use with the oracle
    /// @return minWethBalance The minimum WETH balance of the pool needed for the oracle to be valid
    /// @return wethT0 Whether WETH is token0 in the oracle
    /// @return weth The address of the WETH token in the oracle
    function getOracleConfig() public view returns (address, uint16, uint80, bool, address) {
        uint256 data = Storage.getUint(CUSTOM_GAS_TOKEN_ORACLE_SLOT);

        uint16 twapObservations = uint16(data >> 240);
        uint80 minWethBalance = uint80(data >> 160);
        address oracle = address(uint160(data));

        data = Storage.getUint(WETH_ADDRESS_SLOT);
        address weth = address(uint160(data));
        bool wethT0 = data >> 160 == 1;

        return (oracle, twapObservations, minWethBalance, wethT0, weth);
    }

    function _setOracleConfig(
        uint16 _twapObservations,
        uint80 _minWethBalance,
        address _oracle
    ) internal {
        // These tokens should be WTEA and WETH.
        (address t0, address t1) = IVelodromePool(_oracle).tokens();

        // Predeploys.WETH is WTEA, which must be one of the two tokens.
        // WETH should be at the opposite address.
        address weth;
        if (t0 == Predeploys.WETH) weth = t1;
        else if (t1 == Predeploys.WETH) weth = t0;
        else revert("TeaWAPOracle: WTEA not in pool");

        bool wethT0 = weth == t0;

        // Sanity check. This can of course be gamed, but is just meant to catch mistakes.
        (, bytes memory bytesName) = weth.staticcall(abi.encodeWithSignature("name()"));
        require(keccak256(bytesName) == keccak256(abi.encode("Wrapped Ether")));

        Storage.setUint(CUSTOM_GAS_TOKEN_ORACLE_SLOT,
            uint256(_twapObservations) << 240 |
            uint256(_minWethBalance) << 160 |
            uint160(_oracle)
        );

        Storage.setUint(WETH_ADDRESS_SLOT,
            uint256(wethT0 ? 1 : 0) << 160 | uint160(weth)
        );
    }
}
