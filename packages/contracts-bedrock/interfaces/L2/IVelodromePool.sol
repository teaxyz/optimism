// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVelodromePool {
    function tokens() external view returns (address, address);
    function getReserves() external view returns (uint256, uint256, uint256);
}
