// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IGasPriceOracle {
    function DECIMALS() external view returns (uint256);
    function baseFee() external view returns (uint256);
    function baseFeeScalar() external view returns (uint32);
    function blobBaseFee() external view returns (uint256);
    function blobBaseFeeScalar() external view returns (uint32);
    function decimals() external pure returns (uint256);
    function gasPrice() external view returns (uint256);
    function getL1Fee(bytes memory _data) external view returns (uint256);
    function getL1FeeUpperBound(uint256 _unsignedTxSize) external view returns (uint256);
    function getL1GasUsed(bytes memory _data) external view returns (uint256);
    function getOperatorFee(uint256 _gasUsed) external view returns (uint256);
    function isEcotone() external view returns (bool);
    function isFjord() external view returns (bool);
    function isIsthmus() external view returns (bool);
    function isJovian() external view returns (bool);
    function l1BaseFee() external view returns (uint256);
    function overhead() external view returns (uint256);
    function scalar() external view returns (uint256);
    function setEcotone() external;
    function setFjord() external;
    function setIsthmus() external;
    function setJovian() external;
    function version() external view returns (string memory);

    function updateGasTokenPriceRatio() external;
    function convertETHToTea(uint256) external view returns (uint256);
    function teaPerETH() external view returns (uint160);
    function getLatestPrice() external view returns (uint96, uint160);
    function getOracleConfig() external view returns (address,uint16,uint80,bool,address);
    function setOracleConfig(uint16,uint80,address) external;
    function setFallbackPrice(uint160) external;
    function setOracleConfig(uint96,address) external;
    function CUSTOM_GAS_TOKEN_ORACLE_SLOT() external view returns (bytes32);
    function WETH_ADDRESS_SLOT() external view returns (bytes32);
    function CUSTOM_GAS_TOKEN_PRICE_SLOT() external view returns (bytes32);
    function FALLBACK_PRICE_SLOT() external view returns (bytes32);


    function __constructor__() external;
}
