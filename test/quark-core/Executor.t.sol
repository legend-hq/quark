// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.27;

import "forge-std/console.sol";

import {Test} from "forge-std/Test.sol";

import {CodeJar} from "codejar/src/CodeJar.sol";

import {QuarkNonceManager} from "quark-core/src/QuarkNonceManager.sol";
import {QuarkWallet} from "quark-core/src/QuarkWallet.sol";
import {QuarkWalletStandalone} from "quark-core/src/QuarkWalletStandalone.sol";

import {Counter} from "test/lib/Counter.sol";
import {YulHelper} from "test/lib/YulHelper.sol";
import {SignatureHelper} from "test/lib/SignatureHelper.sol";
import {QuarkOperationHelper, ScriptType} from "test/lib/QuarkOperationHelper.sol";

contract ExecutorTest is Test {
    CodeJar public codeJar;
    Counter public counter;
    QuarkNonceManager public nonceManager;

    uint256 alicePrivateKey = 0xa11ce;
    address aliceAccount = vm.addr(alicePrivateKey);
    QuarkWallet public aliceWallet;

    uint256 bobPrivateKey = 0xb0b1337;
    address bobAccount = vm.addr(bobPrivateKey);
    QuarkWallet public bobWallet;

    constructor() {
        codeJar = new CodeJar();
        console.log("CodeJar deployed to: %s", address(codeJar));

        nonceManager = new QuarkNonceManager();
        console.log("QuarkNonceManager deployed to: %s", address(nonceManager));

        counter = new Counter();
        console.log("Counter deployed to: %s", address(counter));

        // alice sets her EOA to be her wallet's executor
        aliceWallet = new QuarkWalletStandalone(aliceAccount, aliceAccount, codeJar, nonceManager);
        console.log("aliceWallet at: %s", address(aliceWallet));

        // bob sets alice's wallet as his wallet's executor
        bobWallet = new QuarkWalletStandalone(bobAccount, address(aliceWallet), codeJar, nonceManager);
        console.log("bobWallet at: %s", address(bobWallet));
    }

    function testExecutorCanDirectCall() public {
        // gas: do not meter set-up
        vm.pauseGasMetering();

        bytes memory ethcall = new YulHelper().getCode("Ethcall.sol/Ethcall.json");
        address ethcallAddress = codeJar.saveCode(ethcall);

        bytes memory executeOnBehalf = new YulHelper().getCode("ExecuteOnBehalf.sol/ExecuteOnBehalf.json");
        address executeOnBehalfAddress = codeJar.saveCode(executeOnBehalf);

        vm.startPrank(aliceAccount);

        bytes32 nonce0 = new QuarkOperationHelper().semiRandomNonce(nonceManager, aliceWallet);
        bytes32 nonce1 = new QuarkOperationHelper().semiRandomNonce(nonceManager, bobWallet);

        // gas: meter execute
        vm.resumeGasMetering();

        // execute counter.increment(5) as bob from alice's wallet (that is, from bob's wallet's executor)
        aliceWallet.executeScript(
            nonce0,
            executeOnBehalfAddress,
            abi.encodeWithSignature(
                "run(address,bytes32,address,bytes)",
                address(bobWallet),
                nonce1,
                address(ethcallAddress),
                abi.encodeWithSignature(
                    "run(address,bytes,uint256)", address(counter), abi.encodeWithSignature("increment(uint256)", 5), 0
                )
            ),
            new bytes[](0)
        );

        assertEq(counter.number(), 5);
    }

    function testExecutorCanDirectCallBySig() public {
        // gas: do not meter set-up
        vm.pauseGasMetering();

        bytes memory ethcall = new YulHelper().getCode("Ethcall.sol/Ethcall.json");
        address ethcallAddress = codeJar.saveCode(ethcall);

        bytes memory executeOnBehalf = new YulHelper().getCode("ExecuteOnBehalf.sol/ExecuteOnBehalf.json");

        QuarkWallet.QuarkOperation memory op = new QuarkOperationHelper().newBasicOpWithCalldata(
            aliceWallet,
            executeOnBehalf,
            abi.encodeWithSignature(
                "run(address,bytes32,address,bytes)",
                address(bobWallet),
                new QuarkOperationHelper().semiRandomNonce(nonceManager, bobWallet),
                address(ethcallAddress),
                abi.encodeWithSignature(
                    "run(address,bytes,uint256)", address(counter), abi.encodeWithSignature("increment(uint256)", 3), 0
                )
            ),
            ScriptType.ScriptSource
        );
        bytes memory signature = new SignatureHelper().signOp(alicePrivateKey, aliceWallet, op);

        // gas: meter execute
        vm.resumeGasMetering();
        aliceWallet.executeQuarkOperation(op, signature);
        assertEq(counter.number(), 3);
    }
}
