pragma solidity 0.8.27;

import {EIP1271MultiSigner} from "quark-core/src/EIP1271MultiSigner.sol";

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {CodeJar} from "codejar/src/CodeJar.sol";

import {QuarkNonceManager} from "quark-core/src/QuarkNonceManager.sol";
import {QuarkWallet} from "quark-core/src/QuarkWallet.sol";
import {QuarkWalletStandalone} from "quark-core/src/QuarkWalletStandalone.sol";

import {SignatureHelper} from "test/lib/SignatureHelper.sol";

import {QuarkOperationHelper, ScriptType} from "test/lib/QuarkOperationHelper.sol";

import {Counter} from "test/lib/Counter.sol";
import {YulHelper} from "test/lib/YulHelper.sol";

contract EIP1271MultiSignerTest is Test {
    bytes4 internal constant EIP_1271_MAGIC_VALUE = 0x1626ba7e;

    CodeJar public codeJar;
    QuarkNonceManager public nonceManager;

    Counter public counter;

    // 0x725A4Dd182a4Bf869D5589790B390f3392A1c912 = dexterAccount
    // 0x84aFb5f670c6Ea3cc88FC3cbaBf5402B68526E2a = edwinAccount
    // 0x9A998AEb5627705b86ff1F569Dbe0041b5B01049 = fredAccount
    // 0xae899f7C78632cd658143D6Cf645F7479f6f8E4c = ingridAccount
    // 0xC086AD613AC14916ec1BCf37616c1eb617D09346 = jackAccount
    // 0xCBbedc988E9dB0EDCb01B6EE86b507C09f8e605D = henryAccount
    // 0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7 = aliceAccount
    // 0xE7f297b4715BbECBe95193d3Ec6902b67dC1D3D9 = georgeAccount
    // 0xfCD9241C05232F071Fb261Dac1C1C67154B22621 = charlieAccount
    // 0xFe1fE00D6FDa57173447e44c5218A189c3177Adc = bobAccount

    uint256 alicePrivateKey = 0xa11ce;
    address aliceAccount = vm.addr(alicePrivateKey);

    uint256 bobPrivateKey = 0xb0b1337;
    address bobAccount = vm.addr(bobPrivateKey);

    uint256 charliePrivateKey = 0xc4671e;
    address charlieAccount = vm.addr(charliePrivateKey);

    uint256 dexterPrivateKey = 0xde4735;
    address dexterAccount = vm.addr(dexterPrivateKey);

    uint256 edwinPrivateKey = 0xed314;
    address edwinAccount = vm.addr(edwinPrivateKey);

    uint256 fredPrivateKey = 0xf53d;
    address fredAccount = vm.addr(fredPrivateKey);

    uint256 georgePrivateKey = 0x630563;
    address georgeAccount = vm.addr(georgePrivateKey);

    uint256 henryPrivateKey = 0x43457;
    address henryAccount = vm.addr(henryPrivateKey);

    uint256 ingridPrivateKey = 0x14561d;
    address ingridAccount = vm.addr(ingridPrivateKey);

    uint256 jackPrivateKey = 0x74c3;
    address jackAccount = vm.addr(jackPrivateKey);

    constructor() {
        codeJar = new CodeJar();
        console.log("CodeJar deployed to: %s", address(codeJar));

        nonceManager = new QuarkNonceManager();
        console.log("QuarkNonceManager deployed to: %s", address(nonceManager));

        counter = new Counter();
        console.log("Counter deployed to: %s", address(counter));

        console.log("%s = aliceAccount", aliceAccount);
        console.log("%s = bobAccount", bobAccount);
        console.log("%s = charlieAccount", charlieAccount);
        console.log("%s = dexterAccount", dexterAccount);
        console.log("%s = edwinAccount", edwinAccount);
        console.log("%s = fredAccount", fredAccount);
        console.log("%s = georgeAccount", georgeAccount);
        console.log("%s = henryAccount", henryAccount);
        console.log("%s = ingridAccount", ingridAccount);
        console.log("%s = jackAccount", jackAccount);
    }

    function testMultiSignerConstructorValid1() external {
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            1,
            address(1),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0)
        );

        assertEq(multiSigner.signer0(), address(1), "Address 0 match");
        assertEq(multiSigner.signer1(), address(0));
        assertEq(multiSigner.signer2(), address(0));
        assertEq(multiSigner.signer3(), address(0));
        assertEq(multiSigner.signer4(), address(0));
        assertEq(multiSigner.signer5(), address(0));
        assertEq(multiSigner.signer6(), address(0));
        assertEq(multiSigner.signer7(), address(0));
        assertEq(multiSigner.signer8(), address(0));
        assertEq(multiSigner.signer9(), address(0));
    }

    function testMultiSignerConstructorValid2() external {
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            2,
            address(1),
            address(2),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0)
        );

        assertEq(multiSigner.signer0(), address(1), "Address 0 match");
        assertEq(multiSigner.signer1(), address(2), "Address 1 match");
        assertEq(multiSigner.signer2(), address(0));
        assertEq(multiSigner.signer3(), address(0));
        assertEq(multiSigner.signer4(), address(0));
        assertEq(multiSigner.signer5(), address(0));
        assertEq(multiSigner.signer6(), address(0));
        assertEq(multiSigner.signer7(), address(0));
        assertEq(multiSigner.signer8(), address(0));
        assertEq(multiSigner.signer9(), address(0));
    }

    function testMultiSignerConstructorValid10() external {
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            10,
            address(1),
            address(2),
            address(3),
            address(4),
            address(5),
            address(6),
            address(7),
            address(8),
            address(9),
            address(10)
        );

        assertEq(multiSigner.signer0(), address(1));
        assertEq(multiSigner.signer1(), address(2));
        assertEq(multiSigner.signer2(), address(3));
        assertEq(multiSigner.signer3(), address(4));
        assertEq(multiSigner.signer4(), address(5));
        assertEq(multiSigner.signer5(), address(6));
        assertEq(multiSigner.signer6(), address(7));
        assertEq(multiSigner.signer7(), address(8));
        assertEq(multiSigner.signer8(), address(9));
        assertEq(multiSigner.signer9(), address(10));
    }

    function testMultiSignerConstructorRequiredSignersNotZero() external {
        vm.expectRevert(EIP1271MultiSigner.InvalidRequiredSigners.selector);
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            0,
            address(1),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0)
        );
    }

    function testMultiSignerConstructorRequiredSignersLTE10() external {
        vm.expectRevert(EIP1271MultiSigner.InvalidRequiredSigners.selector);
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            20,
            address(1),
            address(2),
            address(3),
            address(4),
            address(5),
            address(6),
            address(7),
            address(8),
            address(9),
            address(10)
        );
    }

    function testMultiSignerConstructorRequiredHasSigner0() external {
        vm.expectRevert(EIP1271MultiSigner.InvalidRequiredSigners.selector);
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            1,
            address(0),
            address(2),
            address(3),
            address(4),
            address(5),
            address(6),
            address(7),
            address(8),
            address(9),
            address(10)
        );
    }

    // TODO: We should make it illegal to have a signer beyond any zero signer.
    // function testMultiSignerConstructorRequiredHasSignerBeyond() external {
    //     vm.expectRevert(EIP1271MultiSigner.InvalidRequiredSigners.selector);
    //     EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
    //         1,
    //         address(1),
    //         address(0),
    //         address(0),
    //         address(0),
    //         address(0),
    //         address(0),
    //         address(0),
    //         address(0),
    //         address(0),
    //         address(10)
    //     );
    // }

    function testMultiSignerConstructorRequiredHasSigner1() external {
        vm.expectRevert(EIP1271MultiSigner.InvalidRequiredSigners.selector);
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            2,
            address(0),
            address(0),
            address(3),
            address(4),
            address(5),
            address(6),
            address(7),
            address(8),
            address(9),
            address(10)
        );
    }

    function testMultiSignerConstructorRequiredHasSigner10() external {
        vm.expectRevert(EIP1271MultiSigner.InvalidRequiredSigners.selector);
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            10,
            address(1),
            address(2),
            address(3),
            address(4),
            address(5),
            address(6),
            address(7),
            address(8),
            address(9),
            address(0)
        );
    }

    function testMultiSignerConstructorRequiredHasSignerMid() external {
        vm.expectRevert(EIP1271MultiSigner.InvalidRequiredSigners.selector);
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            10,
            address(1),
            address(2),
            address(3),
            address(4),
            address(0),
            address(6),
            address(7),
            address(8),
            address(9),
            address(10)
        );
    }

    function testMultiSignerConstructorOrdered() external {
        vm.expectRevert(EIP1271MultiSigner.MisplacedSigner.selector);
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            10,
            address(1),
            address(2),
            address(3),
            address(5),
            address(4),
            address(6),
            address(7),
            address(8),
            address(9),
            address(10)
        );
    }

    function testMultiSignerIsValidSignature1of1() external {
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            1,
            address(aliceAccount),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0)
        );

        QuarkWalletStandalone quarkWallet =
            new QuarkWalletStandalone(address(multiSigner), address(multiSigner), codeJar, nonceManager);

        bytes memory incrementer = new YulHelper().getCode("Incrementer.sol/Incrementer.json");
        assertEq(counter.number(), 0);
        QuarkWallet.QuarkOperation memory op = new QuarkOperationHelper().newBasicOpWithCalldata(
            quarkWallet,
            incrementer,
            abi.encodeWithSignature("incrementCounter(address)", counter),
            ScriptType.ScriptAddress
        );

        bytes memory aliceSignature = new SignatureHelper().signOp(alicePrivateKey, quarkWallet, op);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = aliceSignature;
        bytes memory signatureEncoded = abi.encode(signatures);

        // gas: meter execute
        vm.resumeGasMetering();
        quarkWallet.executeQuarkOperation(op, signatureEncoded);
        assertEq(counter.number(), 3);
    }

    function testMultiSignerIsValidSignature2of2of2() external {
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            2,
            address(aliceAccount),
            address(bobAccount),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0)
        );

        QuarkWalletStandalone quarkWallet =
            new QuarkWalletStandalone(address(multiSigner), address(multiSigner), codeJar, nonceManager);

        bytes memory incrementer = new YulHelper().getCode("Incrementer.sol/Incrementer.json");
        assertEq(counter.number(), 0);
        QuarkWallet.QuarkOperation memory op = new QuarkOperationHelper().newBasicOpWithCalldata(
            quarkWallet,
            incrementer,
            abi.encodeWithSignature("incrementCounter(address)", counter),
            ScriptType.ScriptAddress
        );

        bytes memory aliceSignature = new SignatureHelper().signOp(alicePrivateKey, quarkWallet, op);
        bytes memory bobSignature = new SignatureHelper().signOp(bobPrivateKey, quarkWallet, op);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = aliceSignature;
        signatures[1] = bobSignature;
        bytes memory signatureEncoded = abi.encode(signatures);

        // gas: meter execute
        vm.resumeGasMetering();
        quarkWallet.executeQuarkOperation(op, signatureEncoded);
        assertEq(counter.number(), 3);
    }

    function testMultiSignerIsValidSignature1of2of2Reverts() external {
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            2,
            address(aliceAccount),
            address(bobAccount),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0)
        );

        QuarkWalletStandalone quarkWallet =
            new QuarkWalletStandalone(address(multiSigner), address(multiSigner), codeJar, nonceManager);

        bytes memory incrementer = new YulHelper().getCode("Incrementer.sol/Incrementer.json");
        assertEq(counter.number(), 0);
        QuarkWallet.QuarkOperation memory op = new QuarkOperationHelper().newBasicOpWithCalldata(
            quarkWallet,
            incrementer,
            abi.encodeWithSignature("incrementCounter(address)", counter),
            ScriptType.ScriptAddress
        );

        bytes memory aliceSignature = new SignatureHelper().signOp(alicePrivateKey, quarkWallet, op);
        bytes memory bobSignature = new SignatureHelper().signOp(bobPrivateKey, quarkWallet, op);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = aliceSignature;
        bytes memory signatureEncoded = abi.encode(signatures);

        // gas: meter execute
        vm.resumeGasMetering();
        vm.expectRevert(QuarkWallet.InvalidEIP1271Signature.selector);
        quarkWallet.executeQuarkOperation(op, signatureEncoded);
        assertEq(counter.number(), 0);
    }

    function testMultiSignerIsValidSignature2of2of3() external {
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            2,
            address(aliceAccount),
            address(charlieAccount),
            address(bobAccount),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0)
        );

        QuarkWalletStandalone quarkWallet =
            new QuarkWalletStandalone(address(multiSigner), address(multiSigner), codeJar, nonceManager);

        bytes memory incrementer = new YulHelper().getCode("Incrementer.sol/Incrementer.json");
        assertEq(counter.number(), 0);

        /// Alice and Charlie

        QuarkWallet.QuarkOperation memory op0 = new QuarkOperationHelper().newBasicOpWithCalldata(
            quarkWallet,
            incrementer,
            abi.encodeWithSignature("incrementCounter(address)", counter),
            ScriptType.ScriptAddress
        );

        bytes memory aliceSignature0 = new SignatureHelper().signOp(alicePrivateKey, quarkWallet, op0);
        bytes memory charlieSignature0 = new SignatureHelper().signOp(charliePrivateKey, quarkWallet, op0);

        bytes[] memory signatures0 = new bytes[](2);
        signatures0[0] = aliceSignature0;
        signatures0[1] = charlieSignature0;
        bytes memory signatureEncoded0 = abi.encode(signatures0);

        // gas: meter execute
        vm.resumeGasMetering();
        quarkWallet.executeQuarkOperation(op0, signatureEncoded0);
        assertEq(counter.number(), 3);

        bytes memory aliceSignature = new SignatureHelper().signOp(alicePrivateKey, quarkWallet, op0);
        bytes memory charlieSignature = new SignatureHelper().signOp(charliePrivateKey, quarkWallet, op0);

        /// Alice and Bob

        QuarkWallet.QuarkOperation memory op1 = new QuarkOperationHelper().newBasicOpWithCalldata(
            quarkWallet,
            incrementer,
            abi.encodeWithSignature("incrementCounter(address)", counter),
            ScriptType.ScriptAddress
        );

        bytes memory aliceSignature1 = new SignatureHelper().signOp(alicePrivateKey, quarkWallet, op1);
        bytes memory bobSignature1 = new SignatureHelper().signOp(bobPrivateKey, quarkWallet, op1);

        bytes[] memory signatures1 = new bytes[](2);
        signatures1[0] = aliceSignature1;
        signatures1[1] = bobSignature1;
        bytes memory signatureEncoded1 = abi.encode(signatures1);

        // gas: meter execute
        vm.resumeGasMetering();
        quarkWallet.executeQuarkOperation(op1, signatureEncoded1);
        assertEq(counter.number(), 6);

        /// Bob and Charlie

        QuarkWallet.QuarkOperation memory op2 = new QuarkOperationHelper().newBasicOpWithCalldata(
            quarkWallet,
            incrementer,
            abi.encodeWithSignature("incrementCounter(address)", counter),
            ScriptType.ScriptAddress
        );

        bytes memory charlieSignature2 = new SignatureHelper().signOp(charliePrivateKey, quarkWallet, op2);
        bytes memory bobSignature2 = new SignatureHelper().signOp(bobPrivateKey, quarkWallet, op2);

        bytes[] memory signatures2 = new bytes[](2);
        signatures2[0] = charlieSignature2;
        signatures2[1] = bobSignature2;
        bytes memory signatureEncoded2 = abi.encode(signatures2);

        // gas: meter execute
        vm.resumeGasMetering();
        quarkWallet.executeQuarkOperation(op2, signatureEncoded2);
        assertEq(counter.number(), 9);
    }

    function testMultiSignerIsValidSignatureFail3of2of3() external {
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            2,
            address(aliceAccount),
            address(charlieAccount),
            address(bobAccount),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0)
        );

        QuarkWalletStandalone quarkWallet =
            new QuarkWalletStandalone(address(multiSigner), address(multiSigner), codeJar, nonceManager);

        bytes memory incrementer = new YulHelper().getCode("Incrementer.sol/Incrementer.json");
        assertEq(counter.number(), 0);

        /// Alice, Bob and Charlie

        QuarkWallet.QuarkOperation memory op = new QuarkOperationHelper().newBasicOpWithCalldata(
            quarkWallet,
            incrementer,
            abi.encodeWithSignature("incrementCounter(address)", counter),
            ScriptType.ScriptAddress
        );

        bytes memory aliceSignature = new SignatureHelper().signOp(alicePrivateKey, quarkWallet, op);
        bytes memory bobSignature = new SignatureHelper().signOp(bobPrivateKey, quarkWallet, op);
        bytes memory charlieSignature = new SignatureHelper().signOp(charliePrivateKey, quarkWallet, op);

        bytes[] memory signatures = new bytes[](3);
        signatures[0] = aliceSignature;
        signatures[1] = bobSignature;
        signatures[2] = charlieSignature;
        bytes memory signatureEncoded = abi.encode(signatures);

        // gas: meter execute
        vm.resumeGasMetering();
        vm.expectRevert(QuarkWallet.InvalidEIP1271Signature.selector);
        quarkWallet.executeQuarkOperation(op, signatureEncoded);
        assertEq(counter.number(), 0);

        /// But still can submit any two, e.g. Alice and Charlie

        signatures = new bytes[](2);
        signatures[0] = aliceSignature;
        signatures[1] = charlieSignature;
        signatureEncoded = abi.encode(signatures);

        // gas: meter execute
        vm.resumeGasMetering();
        quarkWallet.executeQuarkOperation(op, signatureEncoded);
        assertEq(counter.number(), 3);
    }

    function testMultiSignerIsValidSignatureCannotReplayWithDifferentPair() external {
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            2,
            address(dexterAccount),
            address(aliceAccount),
            address(charlieAccount),
            address(bobAccount),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0)
        );

        QuarkWalletStandalone quarkWallet =
            new QuarkWalletStandalone(address(multiSigner), address(multiSigner), codeJar, nonceManager);

        bytes memory incrementer = new YulHelper().getCode("Incrementer.sol/Incrementer.json");
        assertEq(counter.number(), 0);

        /// Alice, Bob and Charlie

        QuarkWallet.QuarkOperation memory op = new QuarkOperationHelper().newBasicOpWithCalldata(
            quarkWallet,
            incrementer,
            abi.encodeWithSignature("incrementCounter(address)", counter),
            ScriptType.ScriptAddress
        );

        bytes memory aliceSignature = new SignatureHelper().signOp(alicePrivateKey, quarkWallet, op);
        bytes memory bobSignature = new SignatureHelper().signOp(bobPrivateKey, quarkWallet, op);
        bytes memory charlieSignature = new SignatureHelper().signOp(charliePrivateKey, quarkWallet, op);
        bytes memory dexterSignature = new SignatureHelper().signOp(dexterPrivateKey, quarkWallet, op);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = aliceSignature;
        signatures[1] = bobSignature;
        bytes memory signatureEncoded = abi.encode(signatures);

        // gas: meter execute
        vm.resumeGasMetering();
        quarkWallet.executeQuarkOperation(op, signatureEncoded);
        assertEq(counter.number(), 3);

        /// Cannot re-submit with another pair

        signatures = new bytes[](2);
        signatures[0] = dexterSignature;
        signatures[1] = charlieSignature;
        signatureEncoded = abi.encode(signatures);

        // gas: meter execute
        vm.resumeGasMetering();
        vm.expectRevert(
            abi.encodeWithSelector(
                QuarkNonceManager.NonReplayableNonce.selector, address(quarkWallet), op.nonce, op.nonce
            )
        );
        quarkWallet.executeQuarkOperation(op, signatureEncoded);
        assertEq(counter.number(), 3);
    }

    function testMultiSignerIsValidSignature10of10of10() external {
        EIP1271MultiSigner multiSigner = new EIP1271MultiSigner(
            10,
            dexterAccount,
            edwinAccount,
            fredAccount,
            ingridAccount,
            jackAccount,
            henryAccount,
            aliceAccount,
            georgeAccount,
            charlieAccount,
            bobAccount
        );

        QuarkWalletStandalone quarkWallet =
            new QuarkWalletStandalone(address(multiSigner), address(multiSigner), codeJar, nonceManager);

        bytes memory incrementer = new YulHelper().getCode("Incrementer.sol/Incrementer.json");
        assertEq(counter.number(), 0);

        QuarkWallet.QuarkOperation memory op = new QuarkOperationHelper().newBasicOpWithCalldata(
            quarkWallet,
            incrementer,
            abi.encodeWithSignature("incrementCounter(address)", counter),
            ScriptType.ScriptAddress
        );

        SignatureHelper signatureHelper = new SignatureHelper();

        bytes[] memory signatures = new bytes[](10);
        signatures[0] = signatureHelper.signOp(dexterPrivateKey, quarkWallet, op);
        signatures[1] = signatureHelper.signOp(edwinPrivateKey, quarkWallet, op);
        signatures[2] = signatureHelper.signOp(fredPrivateKey, quarkWallet, op);
        signatures[3] = signatureHelper.signOp(ingridPrivateKey, quarkWallet, op);
        signatures[4] = signatureHelper.signOp(jackPrivateKey, quarkWallet, op);
        signatures[5] = signatureHelper.signOp(henryPrivateKey, quarkWallet, op);
        signatures[6] = signatureHelper.signOp(alicePrivateKey, quarkWallet, op);
        signatures[7] = signatureHelper.signOp(georgePrivateKey, quarkWallet, op);
        signatures[8] = signatureHelper.signOp(charliePrivateKey, quarkWallet, op);
        signatures[9] = signatureHelper.signOp(bobPrivateKey, quarkWallet, op);
        bytes memory signatureEncoded = abi.encode(signatures);

        // gas: meter execute
        vm.resumeGasMetering();
        quarkWallet.executeQuarkOperation(op, signatureEncoded);
        assertEq(counter.number(), 3);
    }
}
