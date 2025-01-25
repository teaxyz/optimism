// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Testing utilities
import { CommonTest } from "test/setup/CommonTest.sol";
import { Predeploys } from "src/libraries/Predeploys.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

contract OtherTokenWETH {
    function name() public pure returns (string memory) {
        return "Wrapped Ether";
    }
}

contract OtherTokenNot {
    function name() public pure returns (string memory) {
        return "Not Wrapped Ether";
    }
}

contract MockOracle {
    address otherToken;
    bool goodReserves;

    constructor(address _otherToken, bool _goodReserves) {
        otherToken = _otherToken;
        goodReserves = _goodReserves;
    }

    function getReserves() public view returns (uint256, uint256, uint256) {
        // Let's say this is 2mm WTEA for 1 WETH
        // WTEA is token0 (at Predeploys.WETH)
        if (goodReserves) return (0, 1e18, 0);
        else return (0, 1e17, 0);
    }

    function tokens() public view returns (address, address) {
        return (Predeploys.WETH, otherToken);
    }

    function quote(address token, uint256 amount, uint256) external view returns (uint256) {
        if (token == Predeploys.WETH) {
            return amount / 2_000_000;
        } else {
            return amount * 2_000_000;
        }
    }
}

contract TeaWAPOracle_Test is CommonTest {
    MockOracle public oracle;
    address myWeth;

    function setUp() public override {
        super.setUp();

        // Start at a reasonable timestamp.
        vm.warp(1737668792);

        myWeth = address(new OtherTokenWETH());
        oracle = new MockOracle(myWeth, true);
    }

    function testTeaWAP_UpdatePrice() public {
        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (uint96 ts, uint160 price) = gasPriceOracle.getLatestPrice();
        assertEq(ts, block.timestamp);
        assertEq(price, 1_500_000e18);

        // This emulates what will happen in op-geth.
        bytes32 priceData = vm.load(address(gasPriceOracle), gasPriceOracle.CUSTOM_GAS_TOKEN_PRICE_SLOT());
        uint96 ts2 = uint96(uint256(priceData) >> 160);
        uint160 price2 = uint160(uint256(priceData));

        assertEq(ts2, block.timestamp);
        assertEq(price2, 1_500_000e18);
    }

    function testTeaWAP_SetUpOracle() public {
        vm.prank(Ownable(Predeploys.PROXY_ADMIN).owner());
        gasPriceOracle.setOracleConfig(10, address(oracle));

        (address oracle_, uint96 twapObservations, bool wethT0, address weth_) = gasPriceOracle.getOracleConfig();
        assertEq(oracle_, address(oracle));
        assertEq(twapObservations, 10);
        assertFalse(wethT0);
        assertEq(weth_, myWeth);
    }

    function testTeaWAP_GetPriceFromOracle() public {
        vm.prank(Ownable(Predeploys.PROXY_ADMIN).owner());
        gasPriceOracle.setOracleConfig(10, address(oracle));

        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (uint96 ts, uint160 price) = gasPriceOracle.getLatestPrice();
        assert(ts == block.timestamp);
        assert(price == oracle.quote(myWeth, 1e18, 10));
    }

    function testTeaWAP_FallbackIfBadReserves() public {
        MockOracle badResevesOracle = new MockOracle(myWeth, false);
        vm.prank(Ownable(Predeploys.PROXY_ADMIN).owner());
        gasPriceOracle.setOracleConfig(10, address(badResevesOracle));

        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (uint96 ts, uint160 price) = gasPriceOracle.getLatestPrice();
        assert(ts == block.timestamp);
        assert(price == 1_500_000e18);
    }

    function testTeaWAP_StalePriceRevertToFallback() public {
        vm.prank(Ownable(Predeploys.PROXY_ADMIN).owner());
        gasPriceOracle.setOracleConfig(10, address(oracle));

        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (uint96 ts, uint160 price) = gasPriceOracle.getLatestPrice();
        assert(ts == block.timestamp);
        assert(price == 2_000_000e18);

        // now let's break the oracle
        vm.etch(address(oracle), abi.encode(""));

        // after 59 minutes, should still skip
        vm.warp(block.timestamp + 59 minutes);

        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (uint96 newTs, uint160 newPrice) = gasPriceOracle.getLatestPrice();
        assert(ts == newTs);
        assert(price == newPrice);

        // but after an hour, we go to fallback
        vm.warp(block.timestamp + 61);

        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (uint96 finalTs, uint160 finalPrice) = gasPriceOracle.getLatestPrice();
        assert(finalTs == block.timestamp);
        assert(finalPrice == 1_500_000e18);
    }

    function testTeaWAP_NonWETHOracleFails() public {
        address notWeth = address(new OtherTokenNot());
        MockOracle nonWethOracle = new MockOracle(notWeth, true);

        vm.prank(Ownable(Predeploys.PROXY_ADMIN).owner());
        vm.expectRevert();
        gasPriceOracle.setOracleConfig(10, address(nonWethOracle));
    }
}
