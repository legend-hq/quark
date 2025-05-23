// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.27;

import {QuarkScript} from "quark-core/src/QuarkScript.sol";
import {QuarkWallet} from "quark-core/src/QuarkWallet.sol";

contract Stow {
    bytes nestedOperation;

    function getNestedOperation()
        public
        view
        returns (QuarkWallet.QuarkOperation memory op, bytes32 submissionToken, bytes memory signature)
    {
        (op, submissionToken, signature) = abi.decode(nestedOperation, (QuarkWallet.QuarkOperation, bytes32, bytes));
    }

    function setNestedOperation(QuarkWallet.QuarkOperation memory op, bytes32 submissionToken, bytes memory signature)
        public
    {
        nestedOperation = abi.encode(op, submissionToken, signature);
    }
}

contract Noncer is QuarkScript {
    function checkNonce() public view returns (bytes32) {
        return getActiveNonce();
    }

    function checkSubmissionToken() public view returns (bytes32) {
        return getActiveSubmissionToken();
    }

    function checkReplayCount() public view returns (uint256) {
        return getActiveReplayCount();
    }

    // TODO: Test nesting with same nonce
    function nestedNonce(QuarkWallet.QuarkOperation memory op, bytes memory signature)
        public
        returns (bytes32 pre, bytes32 post, bytes memory result)
    {
        pre = getActiveNonce();
        result = QuarkWallet(payable(address(this))).executeQuarkOperation(op, signature);
        post = getActiveNonce();

        return (pre, post, result);
    }

    function nestedSubmissionToken(QuarkWallet.QuarkOperation memory op, bytes memory signature)
        public
        returns (bytes32 pre, bytes32 post, bytes memory result)
    {
        pre = getActiveSubmissionToken();
        result = QuarkWallet(payable(address(this))).executeQuarkOperation(op, signature);
        post = getActiveSubmissionToken();

        return (pre, post, result);
    }

    function nestedReplayCount(QuarkWallet.QuarkOperation memory op, bytes memory signature)
        public
        returns (uint256 pre, uint256 post, bytes memory result)
    {
        pre = getActiveReplayCount();
        result = QuarkWallet(payable(address(this))).executeQuarkOperation(op, signature);
        post = getActiveReplayCount();

        return (pre, post, result);
    }

    function postNestRead(QuarkWallet.QuarkOperation memory op, bytes memory signature) public returns (uint256) {
        QuarkWallet(payable(address(this))).executeQuarkOperation(op, signature);
        return readU256("count");
    }

    function nestedPlay(Stow stow) public returns (uint256) {
        uint256 n = getActiveReplayCount();
        if (n == 0) {
            (QuarkWallet.QuarkOperation memory op, bytes32 submissionToken, bytes memory signature) =
                stow.getNestedOperation();
            bytes memory result = QuarkWallet(payable(address(this))).executeQuarkOperationWithSubmissionToken(
                op, submissionToken, signature
            );
            (uint256 y) = abi.decode(result, (uint256));
            return y + 10;
        } else {
            return getActiveReplayCount() + 50;
        }
    }
}
