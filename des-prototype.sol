pragma solidity ^0.4.10;
contract deb{
    address public signer;
    address public transferee;
    address public oraclizeAddr;
    bool private grant;
    bool private deny;
    bool private pendWhite;
    bool private pendBlack;
    string public enData;
    uint public now;
    bytes32 public applyId;
    bytes32 public license;
    //==============struct================
    //define records
    struct Record {
        bytes32 dataId;
        bytes32 license;
    }
    //define data infos
    struct DataInfo {
        address owner;
        bytes32 dataId;
        string dataDescription;
    }
    //define policy attribtues
    struct Policy {
        bytes32[] blackList;  //hash of name
        bytes32[] whiteList; 
        uint minPrice;
        uint maxPrice;
        uint appStart;
        uint appEnd;
        uint excStart;
        uint excEnd;
        uint minSam;
        uint maxSam;
        uint minDam;
        uint maxDam;
    }
    //define exchange attributes
    struct Attribute {
        address transferee;
        bytes32 id;
        uint price;
        uint appTime;
        uint excTime;
        uint samRate;
        uint damFee;
    }
    //-----------------struct----------------

    mapping(bytes32 => DataInfo) public data;  //dataId is key
    mapping(bytes32 => Policy) public policy;  //dataId is key
    mapping(bytes32 => Record) public record;  //license is key
    mapping(bytes32 => Attribute) public attribute;  //dataID + transfereeadd is key
      
    //constructor && define policy attributes
    function deb() {
        signer = msg.sender;
        grant = true;
        deny = false;
        pendBlack = true;
        pendWhite = false;
    }
    
    //=============data owner===========
    function releaseData(bytes32 dataId, string dataDescription) {
        data[dataId] = DataInfo(msg.sender, dataId, dataDescription);
    }
    function releasePolicy(bytes32[] blackList, bytes32[] whiteList, bytes32 dataId, uint minPrice, uint maxPrice, 
            uint appStart, uint appEnd, uint excStart, uint excEnd, uint minSam, uint maxSam, uint minDam, uint maxDam) {
        policy[dataId] = Policy(blackList, whiteList, minPrice, maxPrice, appStart, appEnd, excStart, excEnd, minSam, maxSam, minDam, maxDam);
    }
    
    //=============policy======================
    //design of identity policy
    function isInBlackList(bytes32 dataId, bytes32 idTransferee) internal returns (bool) {
        for (uint i = 0; i < policy[dataId].blackList.length; ++i) {
            // compare identity to invalid names
            if (idTransferee == policy[dataId].blackList[i]) {
                return true;
            }
        }
        return false;
    }
    function isInWhiteList(bytes32 dataId, bytes32 idTransferee) internal returns (bool) {
        for (uint i = 0; i < policy[dataId].whiteList.length; ++i) {
            // compare identity to valid names
            if (idTransferee == policy[dataId].whiteList[i]) {
                return true;
            }
        }
        return false;
    }
    function blackPolicy (bytes32 dataId, bytes32 ApplyId) internal returns (bool) {
        bytes32 id = attribute[ApplyId].id;
        //bytes32 idHash = sha3(id);
        if(isInBlackList(dataId, id)) {
            //deny access to the Black List Policy
            return deny;
        }
        return pendBlack;
    }
    function whitePolicy (bytes32 dataId, bytes32 ApplyId) internal returns (bool) {
        bytes32 id = attribute[ApplyId].id;
        //bytes32 idHash = sha3(id);
        if(isInWhiteList(dataId, id)) {
            //grant access to the White List Policy
            return grant;
        }
        return pendWhite;
    }
    //Design of Price Policy
    function pricePolicy (bytes32 dataId, bytes32 ApplyId) internal returns (bool) {
        uint price = attribute[ApplyId].price;
        if (price < policy[dataId].minPrice || price > policy[dataId].maxPrice) {
            return deny;
        }
        return grant;
    }
    //Design of Application Time Policy
    function appPolicy (bytes32 dataId, bytes32 ApplyId) internal returns (bool) {
        uint appTime = attribute[ApplyId].appTime;
        if (appTime < policy[dataId].appStart || appTime > policy[dataId].appEnd) {
            return deny;
        }
        return grant;
    }
    //Design of Exchange Time Policy
    function excPolicy (bytes32 dataId, bytes32 ApplyId) internal returns (bool) {
        uint excTime = attribute[ApplyId].excTime;
        if (excTime < policy[dataId].excStart || excTime > policy[dataId].excEnd) {
            return deny;
        }
        return grant;
    }
    //Design of Sample Rate Policy
    function samPolicy (bytes32 dataId, bytes32 ApplyId) internal returns (bool) {
        uint samRate = attribute[ApplyId].samRate;
        if (samRate < policy[dataId].minSam || samRate > policy[dataId].maxSam) {
            return deny;
        }
        return grant;
    }
    //Design of Liquidated Damages Policy
    function damPolicy (bytes32 dataId, bytes32 ApplyId) internal returns (bool) {
        uint damFee = attribute[ApplyId].damFee;
        if (damFee < policy[dataId].minDam || damFee > policy[dataId].maxDam) {
            return deny;
        }
        return grant;
    }
    //------------------------policy-------------------
    //apply for exchange
    function appExchange(bytes32 dataId, bytes32 id, uint price, uint excTime, uint samRate) payable returns (bytes32){
        bytes32 licence;
        //get the application time attribute
        uint appTime = block.timestamp;
        //get the liquidated damages attribute
        uint damFee = msg.value;
        //get the blockchain address of the data transferee
        address transferee = msg.sender;
        applyId = sha3(transferee, dataId);
        attribute[applyId] = Attribute(transferee, id, price, appTime, excTime, samRate, damFee);
        if (blackPolicy(dataId, applyId) == deny || 
            (whitePolicy(dataId, applyId) == pendWhite && 
            (pricePolicy(dataId, applyId) == deny || 
            appPolicy(dataId, applyId) == deny ||
            excPolicy(dataId, applyId) == deny || 
            samPolicy(dataId, applyId) == deny || 
            damPolicy(dataId, applyId) == deny))) {
            //deny the application, return liquidated damages
            if (!transferee.send(damFee)) {
                throw;
            }
            return "Deny Application";
        }
        //grant the application, generate a license
        license = genLicense(dataId, applyId);
        //keep the record
        record[applyId] = Record(dataId, license);
        return license;
    }
    //generate license
    function genLicense(bytes32 dataId, bytes32 ApplyId) returns (bytes32) {
        Attribute attr = attribute[ApplyId];
        license = sha3(data[dataId].owner, dataId, attr.transferee, attr.id, attr.price, attr.appTime, attr.excTime, attr.samRate, attr.damFee, signer);
        return license;
    }
    //validate license
    function licenseValidate(bytes32 dataId, bytes32 license, address transferee) payable returns (bool) {
        applyId = sha3(transferee, dataId);
        if(record[applyId].license != license)    return false;
        return true;
    }
    //return liquidated damages after exchange
    function returnDam (bytes32 dataId, address transferee, bool result) payable {
        if(msg.sender != data[dataId].owner)    throw;
        applyId = sha3(transferee, dataId);
        uint damFee = attribute[applyId].damFee;
        if(result == true){
            //return to the transferee
            if(!transferee.send(damFee)){
                throw;
            }
        }
        else {
            //return to the owner
            if(!msg.sender.send(damFee)){
                throw;
            }
        }
        attribute[applyId].damFee = 0;
    }
    //destroy the smart contract
    function destroy () payable {
        selfdestruct(signer);
    }
    function getPot() constant returns (uint) {
        return this.balance;
    }
    //test void
    function testvoid () {
        
    }
}