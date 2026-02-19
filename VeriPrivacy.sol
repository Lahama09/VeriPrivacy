// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

contract VeriPrivacyFinal {
    // --- CRYPTOGRAPHIC CONSTANTS ---
    uint256 constant r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    address public admin;
    
    struct ForensicLog {
        uint256 identityCommitment;
        uint256 timestamp;
        address verifiedBy;
    }

    ForensicLog[] private auditTrail;
    event VerificationSuccess(uint256 indexed commitment, uint256 time);

    constructor() {
        admin = msg.sender; 
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Forensic Audit: Unauthorized Access");
        _;
    }

    // --- MAIN FORENSIC INTERFACE ---
    function secureVerifyAndLog(
        uint[2] calldata _pA, 
        uint[2][2] calldata _pB, 
        uint[2] calldata _pC, 
        uint[1] calldata _pubSignals
    ) public returns (bool) {
        
        // This calls the helper function below safely
        bool isValid = this.verifyProof(_pA, _pB, _pC, _pubSignals);

        if (isValid) {
            auditTrail.push(ForensicLog({
                identityCommitment: _pubSignals[0],
                timestamp: block.timestamp,
                verifiedBy: msg.sender
            }));
            emit VerificationSuccess(_pubSignals[0], block.timestamp);
        }
        return isValid;
    }

    function getForensicAuditTrail() public view onlyAdmin returns (ForensicLog[] memory) {
        return auditTrail;
    }

    // --- CRYPTOGRAPHIC ENGINE (ONLY DEFINED ONCE) ---
    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[1] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, 21888242871839275222246405745257275088548364400416034343698204186575808495617)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)
                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)
                if iszero(success) { mstore(0, 0) return(0, 0x20) }
                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))
                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)
                if iszero(success) { mstore(0, 0) return(0, 0x20) }
            }
            let pMem := mload(0x40)
            mstore(add(pMem, 0), 1405451938763791003622174963702534698115502985916425632638084649048525747151)
            mstore(add(pMem, 32), 4195387978555227709250415699816347905043853810276468564202850859179749836401)
            g1_mulAccC(pMem, 20307339771029451491474674032727372515507048888836318967504414849042064633937, 9401931764668861050170218745300289496263152524845401471688659460238598401815, calldataload(add(_pubSignals, 0)))
            
            let _pPairing := add(pMem, 128)
            mstore(_pPairing, calldataload(_pA))
            mstore(add(_pPairing, 32), mod(sub(21888242871839275222246405745257275088696311157297823662689037894645226208583, calldataload(add(_pA, 32))), 21888242871839275222246405745257275088696311157297823662689037894645226208583))
            mstore(add(_pPairing, 64), calldataload(_pB))
            mstore(add(_pPairing, 96), calldataload(add(_pB, 32)))
            mstore(add(_pPairing, 128), calldataload(add(_pB, 64)))
            mstore(add(_pPairing, 160), calldataload(add(_pB, 96)))
            mstore(add(_pPairing, 192), 20491192805390485299153009773594534940189261866228447918068658471970481763042)
            mstore(add(_pPairing, 224), 9383485363053290200918347156157836566562967994039712273449902621266178545958)
            mstore(add(_pPairing, 256), 4252822878758300859123897981450591353533073413197771768651442665752259397132)
            mstore(add(_pPairing, 288), 6375614351688725206403948262868962793625744043794305715222011528459656738731)
            mstore(add(_pPairing, 320), 21847035105528745403288232691147584728191162732299865338377159692350059136679)
            mstore(add(_pPairing, 352), 10505242626370262277552901082094356697409835680220590971873171140371331206856)
            mstore(add(_pPairing, 384), mload(pMem))
            mstore(add(_pPairing, 416), mload(add(pMem, 32)))
            mstore(add(_pPairing, 448), 11559732032986387107991004021392285783925812861821192530917403151452391805634)
            mstore(add(_pPairing, 480), 10857046999023057135944570762232829481370756359578518086990519993285655852781)
            mstore(add(_pPairing, 512), 4082367875863433681332203403145435568316851327593401208105741076214120093531)
            mstore(add(_pPairing, 544), 8495653923123431417604973247489272438418190587263600148770280649306958101930)
            mstore(add(_pPairing, 576), calldataload(_pC))
            mstore(add(_pPairing, 608), calldataload(add(_pC, 32)))
            mstore(add(_pPairing, 640), 14865035399266553685977143930773993460646397406203353019265871950208607735322)
            mstore(add(_pPairing, 672), 11136283337317779459238065748080165198169932420268316275747531699515570234308)
            mstore(add(_pPairing, 704), 10953239333630443087042151278057349748235418636349612767613350821360782111786)
            mstore(add(_pPairing, 736), 9978910464660803810951288091467280096137598465841014697119664737570954447507)
            let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)
            mstore(0, and(success, mload(_pPairing)))
            return(0, 0x20)
        }
    }
}