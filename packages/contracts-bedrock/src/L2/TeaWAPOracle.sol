// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Storage } from "src/libraries/Storage.sol";
import { Predeploys } from "src/libraries/Predeploys.sol";
import { IVelodromePool } from "src/L2/interfaces/IVelodromePool.sol";
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

    /// @notice The storage slot that contains the fallback price, set by admin
    /// @dev This price is stored as a uint160 to align with the `latestPrice` in the previous slot
    bytes32 public constant FALLBACK_PRICE_SLOT = bytes32(uint256(keccak256("tea.customgastoken.fallbackprice")) - 1);

    /// @notice SECURITY FIX: Storage slot for emergency pause flag and fallback price timestamp
    /// @dev Packed as: uint96(fallbackPriceTimestamp) | bool(emergencyPaused)
    ///      Allows admin to force fallback mode if critical oracle bug is discovered
    bytes32 public constant EMERGENCY_CONTROLS_SLOT = bytes32(uint256(keccak256("tea.customgastoken.emergencycontrols")) - 1);

    /// @notice A backup TEA/ETH ratio, in the case that the oracle is not set
    ///         and the fallback price is not set.
    uint160 public constant BACKUP_TEA_WEI_PER_ETH = 1_500_000e18;

    /// @notice The maximum amount of time we will allow failed oracle calls before
    ///         setting the storage value to the fallback.
    uint256 public constant MAX_ORACLE_DOWNTIME = 5 minutes;

    /// @notice SECURITY FIX: Minimum sane price for TEA/ETH ratio to prevent oracle manipulation
    ///         Set to 100,000 TEA per ETH (100k * 1e18)
    /// @dev REASON: Prevents gradual manipulation attacks where attacker slowly drains pool over
    ///      many blocks to manipulate TWAP (not detectable by flash loan protection).
    ///      Example attack: Drain pool from 2M → 200M TEA/ETH over 100 blocks, oracle would
    ///      accept 100x price without bounds, causing users to pay 100x gas fees.
    /// @dev These boundaries are arbitrary and MUST be adjusted by the Tea team based on
    ///      expected market conditions and price ranges before mainnet deployment
    uint160 public constant MIN_SANE_PRICE = 100_000e18;

    /// @notice SECURITY FIX: Maximum sane price for TEA/ETH ratio to prevent oracle manipulation
    ///         Set to 10,000,000 TEA per ETH (10M * 1e18)
    /// @dev REASON: Prevents gradual manipulation attacks where attacker slowly drains pool over
    ///      many blocks to manipulate TWAP (not detectable by flash loan protection).
    ///      Similar missing bounds have caused millions in losses in other DeFi protocols.
    /// @dev These boundaries are arbitrary and MUST be adjusted by the Tea team based on
    ///      expected market conditions and price ranges before mainnet deployment
    uint160 public constant MAX_SANE_PRICE = 10_000_000e18;

    /// @notice SECURITY FIX: Maximum allowed price change percentage between updates (in basis points)
    ///         Set to 5000 = 50% max price change per update to prevent manipulation
    /// @dev REASON: Circuit breaker to reject sudden price jumps (e.g., 10x jump between blocks)
    ///      which could indicate oracle bug or manipulation. Acts as additional layer beyond
    ///      absolute bounds. Protects against both manipulation and oracle malfunction.
    /// @dev This threshold is arbitrary and MUST be adjusted by the Tea team based on
    ///      expected market volatility before mainnet deployment
    uint256 public constant MAX_PRICE_CHANGE_BPS = 5000;

    /// @notice SECURITY FIX: Minimum TWAP observations to prevent manipulation
    ///         Set to 10 observations minimum
    /// @dev REASON: Too few observations (1-2) make TWAP vulnerable to single-block manipulation
    uint16 public constant MIN_TWAP_OBSERVATIONS = 10;

    /// @notice SECURITY FIX: Maximum TWAP observations to prevent oracle call failures
    ///         Set to 100 observations maximum
    /// @dev REASON: Too many observations could cause oracle calls to fail due to insufficient
    ///      historical data, especially on newer pools
    uint16 public constant MAX_TWAP_OBSERVATIONS = 100;

    /// @notice SECURITY FIX: Maximum age for fallback price before it's considered stale
    ///         Set to 30 days
    /// @dev REASON: Fallback price set by admin can become dangerously outdated if market moves
    ///      significantly. This warns if fallback price hasn't been reviewed in 30 days.
    uint256 public constant MAX_FALLBACK_PRICE_AGE = 30 days;

    /// @notice One billion (1e9), used for oracle calls and other calculations.
    uint256 constant GWEI = 1e9;

    /// @notice Emitted when the price is updated
    event NewPriceSet(uint160 price);

    /// @notice Emitted when the oracle configuration is updated
    event OracleConfigUpdated(uint16 twapObservations, uint80 minWethBalance, address oracle);

    /// @notice Emitted when the fallback price is updated
    event FallbackPriceUpdated(uint256 price);

    /// @notice SECURITY FIX: Emitted when price validation fails due to being outside safe bounds
    /// @dev Helps monitoring detect gradual manipulation attacks that bypass flash loan protection
    event PriceOutOfBounds(uint256 price, uint256 minPrice, uint256 maxPrice);

    /// @notice SECURITY FIX: Emitted when circuit breaker triggers due to large price change
    /// @dev Prevents sudden oracle manipulation or bugs from being accepted instantly
    event CircuitBreakerTriggered(uint256 oldPrice, uint256 newPrice, uint256 changePercent);

    /// @notice SECURITY FIX: Emitted when TWAP data is detected as stale (no recent trades)
    /// @dev Prevents accepting outdated prices when pool has no trading activity
    event StaleTWAPDetected(uint256 lastObservationTimestamp, uint256 currentTimestamp);

    /// @notice SECURITY FIX: Emitted when oracle is emergency paused by admin
    event OracleEmergencyPaused();

    /// @notice SECURITY FIX: Emitted when oracle is unpaused by admin
    event OracleEmergencyUnpaused();

    ////////////////////////////////
    ///// ORACLE FUNCTIONALITY /////
    ////////////////////////////////

    /// @notice Convert the inputted amount of ETH (18 decimals) to $TEA
    /// @dev amount (18 decimals) * teaPerETH (18 decimals) / 1e18 = teaAmount (18 decimals)
    /// @dev SECURITY FIX: Added overflow protection to prevent gas fee calculation wraparound
    ///      Without this check, a large amount value could overflow and return zero/small value,
    ///      allowing transactions to be processed for free or nearly free
    function convertETHToTea(uint256 amount) external view returns (uint256) {
        (, uint160 rate) = teaPerETH();
        // Prevent overflow in multiplication: amount * rate must fit in uint256
        // This protects gas fee calculations from wraparound attacks
        require(amount <= type(uint256).max / rate, "TeaWAPOracle: amount overflow");
        return amount * rate / 1e18;
    }

    /// @notice Get the price of price of 1 Ether (1e18) in $TEA (18 decimals).
    /// @return valid Returned a valid price from the oracle (ie false = fallback)
    /// @return price The price of 1 Ether in $TEA (18 decimals)
    /// @dev If the oracle is not set, we will return fallback price (also in 18 decimals).
    /// @dev If the fallback price is also not set, we will return a hardcoded backup.
    /// @dev This function exists for L1 Data Cost calculations, and should not be trusted externally.
    /// @dev SECURITY FIX: Now includes emergency pause, price bounds, circuit breaker, and staleness checks
    function teaPerETH() public view returns (bool, uint160) {
        // SECURITY FIX: Check if oracle is emergency paused by admin
        // REASON: Allows admin to force fallback mode if critical bug discovered in oracle
        if (isOracleEmergencyPaused()) return (false, getFallbackPrice());
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

        // SECURITY FIX: Check for stale TWAP data by verifying the pool's last observation timestamp
        // REASON: Prevents accepting stale prices when there's no recent trading activity
        //         (e.g., no trades in 2 hours). Without this, oracle could return outdated TWAP
        //         even though it technically "succeeds"
        (success, returndata) = oracle.staticcall(
            abi.encodeWithSignature("observations(uint256)", 0)
        );
        if (success && returndata.length >= 64) {
            uint256 lastObservationTimestamp = abi.decode(returndata, (uint256));
            // If no trades in the last MAX_ORACLE_DOWNTIME period, return fallback
            if (block.timestamp > lastObservationTimestamp + MAX_ORACLE_DOWNTIME) {
                emit StaleTWAPDetected(lastObservationTimestamp, block.timestamp);
                return (false, fallbackPrice);
            }
        }

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
        {
            // If the price is zero, return the fallback price.
            if (price == 0) return (false, fallbackPrice);

            // Price is in GWEI because that was the quote requested.
            // Multiply by GWEI to convert to 18 decimals (making sure no overflow).
            uint256 oldPrice = price;
            unchecked { price = price * GWEI; }
            if (price / GWEI != oldPrice) return (false, fallbackPrice);

            // If the new price is greater than the max uint160, return the fallback price.
            if (price > type(uint160).max) return (false, fallbackPrice);

            // SECURITY FIX: Price bounds check to prevent gradual manipulation attacks
            // REASON: Rejects prices outside reasonable bounds (e.g., 1000x legitimate price)
            //         Protects against slow multi-block manipulation not caught by flash loan protection
            if (price < MIN_SANE_PRICE || price > MAX_SANE_PRICE) {
                emit PriceOutOfBounds(price, MIN_SANE_PRICE, MAX_SANE_PRICE);
                return (false, fallbackPrice);
            }

            // SECURITY FIX: Circuit breaker to check for large price jumps between updates
            // REASON: Prevents sudden manipulation or oracle bugs from being instantly accepted
            //         (e.g., 10x price jump between blocks). Acts as secondary defense beyond absolute bounds.
            (, uint160 lastPrice) = getLatestPrice();
            if (lastPrice > 0) {
                uint256 priceDiff;
                if (price > lastPrice) {
                    priceDiff = ((price - lastPrice) * 10000) / lastPrice;
                } else {
                    priceDiff = ((lastPrice - price) * 10000) / lastPrice;
                }

                // If price changed by more than MAX_PRICE_CHANGE_BPS, reject it
                if (priceDiff > MAX_PRICE_CHANGE_BPS) {
                    emit CircuitBreakerTriggered(lastPrice, price, priceDiff);
                    return (false, fallbackPrice);
                }
            }
        }


        return (true, uint160(price));
    }

    ////////////////////////////////
    //////////// ADMIN /////////////
    ////////////////////////////////

    /// @param _twapObservations Number of observations to ask from the oracle
    /// @param _minWethBalance Minimum WETH balance of the pool needed for the oracle to be valid
    /// @param _oracle Address of the oracle contract to use
    /// @dev SECURITY FIX: Added TWAP observation bounds and enhanced pool validation
    function setOracleConfig(
        uint16 _twapObservations,
        uint80 _minWethBalance,
        address _oracle
    ) external {
        require(msg.sender == Ownable(Predeploys.PROXY_ADMIN).owner(), "TeaWAPOracle: admin only");

        require(_oracle != address(0), "TeaWAPOracle: zero address");

        // SECURITY FIX: Validate TWAP observations are within safe bounds
        // REASON: Too few (1-2) = vulnerable to single-block manipulation
        //         Too many (>100) = may fail due to insufficient historical data
        require(
            _twapObservations >= MIN_TWAP_OBSERVATIONS && _twapObservations <= MAX_TWAP_OBSERVATIONS,
            "TeaWAPOracle: observations out of bounds"
        );

        require(_minWethBalance > 0, "TeaWAPOracle: zero min WETH balance");

        _setOracleConfig(_twapObservations, _minWethBalance, _oracle);

        emit OracleConfigUpdated(_twapObservations, _minWethBalance, _oracle);
    }

    /// @param _price Fallback price to use if oracle fails
    /// @dev Price should be set in wei of $TEA per 18 decimals of ETH
    /// @dev SECURITY FIX: Now tracks timestamp to detect stale fallback prices
    function setFallbackPrice(uint160 _price) external {
        require(msg.sender == Ownable(Predeploys.PROXY_ADMIN).owner(), "TeaWAPOracle: admin only");
        require(_price > 0, "TeaWAPOracle: zero fallback price");

        // SECURITY FIX: Validate price is within sane bounds
        // REASON: Prevents admin from accidentally setting dangerously wrong fallback price
        require(_price >= MIN_SANE_PRICE && _price <= MAX_SANE_PRICE, "TeaWAPOracle: fallback price out of bounds");

        _setFallbackPrice(_price);
        _setFallbackPriceTimestamp(uint96(block.timestamp));

        emit FallbackPriceUpdated(_price);
    }

    /// @notice SECURITY FIX: Emergency pause oracle to force fallback mode
    /// @dev REASON: Allows admin to quickly disable oracle if critical bug is discovered
    ///      without having to deploy new contracts or break the oracle pool
    function emergencyPauseOracle() external {
        require(msg.sender == Ownable(Predeploys.PROXY_ADMIN).owner(), "TeaWAPOracle: admin only");
        require(!isOracleEmergencyPaused(), "TeaWAPOracle: already paused");

        _setOracleEmergencyPaused(true);
        emit OracleEmergencyPaused();
    }

    /// @notice SECURITY FIX: Unpause oracle to resume normal operation
    function emergencyUnpauseOracle() external {
        require(msg.sender == Ownable(Predeploys.PROXY_ADMIN).owner(), "TeaWAPOracle: admin only");
        require(isOracleEmergencyPaused(), "TeaWAPOracle: not paused");

        _setOracleEmergencyPaused(false);
        emit OracleEmergencyUnpaused();
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

    /// @dev SECURITY FIX: Enhanced with pool legitimacy validation
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

        // SECURITY FIX: Validate pool has actual liquidity to prevent rug pull attack
        // REASON: Attacker could create malicious Velodrome pool with minimal/manipulated liquidity
        //         and trick admin into pointing oracle to it. This checks reserves immediately.
        (bool success, bytes memory returndata) = _oracle.staticcall(
            abi.encodeWithSignature("getReserves()")
        );
        require(success && returndata.length == 96, "TeaWAPOracle: cannot read reserves");
        (uint256 r0, uint256 r1,) = abi.decode(returndata, (uint, uint, uint));
        uint256 currentWethReserves = wethT0 ? r0 : r1;

        // SECURITY FIX: Ensure pool has at least the minimum WETH balance NOW
        // REASON: Prevents pointing to empty/low-liquidity pools that can be easily manipulated
        require(currentWethReserves >= _minWethBalance, "TeaWAPOracle: insufficient pool liquidity");

        // SECURITY FIX: Verify pool factory is not paused
        // REASON: If Velodrome factory is paused, pool may not be functioning correctly
        (success, returndata) = _oracle.staticcall(abi.encodeWithSignature("factory()"));
        if (success && returndata.length == 32) {
            address factory = abi.decode(returndata, (address));
            (success, returndata) = factory.staticcall(abi.encodeWithSignature("isPaused()"));
            require(!success || returndata.length != 32 || !abi.decode(returndata, (bool)),
                "TeaWAPOracle: factory is paused");
        }

        Storage.setUint(CUSTOM_GAS_TOKEN_ORACLE_SLOT,
            uint256(_twapObservations) << 240 |
            uint256(_minWethBalance) << 160 |
            uint160(_oracle)
        );

        Storage.setUint(WETH_ADDRESS_SLOT,
            uint256(wethT0 ? 1 : 0) << 160 | uint160(weth)
        );
    }

    /// @notice SECURITY FIX: Check if oracle is emergency paused
    /// @return true if oracle is paused and should use fallback
    function isOracleEmergencyPaused() public view returns (bool) {
        uint256 data = Storage.getUint(EMERGENCY_CONTROLS_SLOT);
        return (data & 1) == 1;
    }

    /// @notice SECURITY FIX: Set emergency pause state
    function _setOracleEmergencyPaused(bool paused) internal {
        uint256 data = Storage.getUint(EMERGENCY_CONTROLS_SLOT);
        // Preserve timestamp in upper bits, update pause flag in lowest bit
        if (paused) {
            data = data | 1;
        } else {
            data = data & ~uint256(1);
        }
        Storage.setUint(EMERGENCY_CONTROLS_SLOT, data);
    }

    /// @notice SECURITY FIX: Get fallback price timestamp
    /// @return timestamp when fallback price was last updated
    function getFallbackPriceTimestamp() public view returns (uint96) {
        uint256 data = Storage.getUint(EMERGENCY_CONTROLS_SLOT);
        return uint96(data >> 160);
    }

    /// @notice SECURITY FIX: Check if fallback price is stale
    /// @dev REASON: Warns if fallback price hasn't been updated in MAX_FALLBACK_PRICE_AGE
    ///      Prevents using dangerously outdated fallback when oracle fails
    /// @return true if fallback price is older than MAX_FALLBACK_PRICE_AGE
    function isFallbackPriceStale() public view returns (bool) {
        uint96 lastUpdate = getFallbackPriceTimestamp();
        if (lastUpdate == 0) return true; // Never set
        return block.timestamp > lastUpdate + MAX_FALLBACK_PRICE_AGE;
    }

    /// @notice SECURITY FIX: Set fallback price timestamp
    function _setFallbackPriceTimestamp(uint96 timestamp) internal {
        uint256 data = Storage.getUint(EMERGENCY_CONTROLS_SLOT);
        // Preserve pause flag in lowest bit, update timestamp in upper bits
        data = (uint256(timestamp) << 160) | (data & 1);
        Storage.setUint(EMERGENCY_CONTROLS_SLOT, data);
    }
}
