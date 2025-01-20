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
    /// @dev  uint80(fallbackPrice) | uint8(fallbackPriceDecimals) | uint8(twapObservations) | address(oracle)
    bytes32 internal constant CUSTOM_GAS_TOKEN_ORACLE_SLOT = bytes32(uint256(keccak256("opstack.customgastokenoracle")) - 1);

    /// @notice The number of decimals that the oracle's result will be returned in
    uint256 constant ORACLE_DECIMALS = 18;

    /// @notice Emitted when the oracle configuration is updated
    event VelodromeConfigUpdated(uint8 twapObservations, address oracle);

    /// @notice Emitted when the fallback price is updated
    event FallbackPriceUpdated(uint80 price, uint8 decimals);

    ////////////////////////////////
    ///// ORACLE FUNCTIONALITY /////
    ////////////////////////////////

    /// @dev If the oracle is not set, we will return fallback price & decimals.
    ///      If the fallback price is not set, it will override with a backup in L1Block.sol.
    function _getTEAPerETH() internal view returns (uint256, uint256) {
        (uint80 fallbackPrice, uint8 fallbackDecimals, uint8 twapObservations, address oracle) = getOracleConfig();

        if (oracle == address(0)) return (fallbackPrice, fallbackDecimals);

        // https://github.com/velodrome-finance/contracts/blob/main/contracts/Pool.sol
        // quote(address tokenIn, uint256 amountIn, uint256 granularity)
        (bool success, bytes memory returndata) = oracle.staticcall(
            abi.encodeWithSignature(
                "quote(address,uint256,uin256)",
                Predeploys.WETH, 10 ** ORACLE_DECIMALS, twapObservations
            )
        );

        // It will revert if we don't have sufficient data points saved.
        if (!success || returndata.length < 32) return (fallbackPrice, fallbackDecimals);

        return (abi.decode(returndata, (uint256)), ORACLE_DECIMALS);
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

    function getOracleConfig() public view returns (uint80, uint8, uint8, address) {
        uint256 data = Storage.getUint(CUSTOM_GAS_TOKEN_ORACLE_SLOT);

        uint80 fallbackPrice = uint80(data >> 176);
        uint8 fallbackPriceDecimals = uint8(data >> 168);
        uint8 twapObservations = uint8(data >> 160);
        address oracle = address(uint160(data));

        return (fallbackPrice, fallbackPriceDecimals, twapObservations, oracle);
    }

    function _setOracleConfig(uint80 fallbackPrice, uint8 fallbackDecimals, uint8 twapObservations, address oracle) public {
        uint256 value = (
            uint256(fallbackPrice << 176) |
            uint256(fallbackDecimals << 168) |
            uint256(twapObservations << 160) |
            uint256(uint160(oracle))
        );
        Storage.setUint(CUSTOM_GAS_TOKEN_ORACLE_SLOT, value);
    }
}
