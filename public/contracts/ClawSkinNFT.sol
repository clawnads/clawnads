// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract ClawSkinNFT is ERC721, Ownable, Pausable {
    using Strings for uint256;

    uint256 public maxSupply;
    uint256 public mintPrice;
    uint256 private _nextTokenId;
    address public treasury;
    string private _baseTokenURI;
    bool public transferable;

    constructor(
        string memory name_,
        string memory symbol_,
        uint256 maxSupply_,
        uint256 mintPrice_,
        address treasury_,
        string memory baseURI_,
        bool transferable_
    ) ERC721(name_, symbol_) {
        maxSupply = maxSupply_;
        mintPrice = mintPrice_;
        treasury = treasury_;
        _baseTokenURI = baseURI_;
        transferable = transferable_;
    }

    function mint(address to) external payable whenNotPaused {
        require(msg.value >= mintPrice, "Insufficient payment");
        require(_nextTokenId < maxSupply, "Sold out");
        _safeMint(to, _nextTokenId);
        _nextTokenId++;
    }

    function _baseURI() internal view override returns (string memory) {
        return _baseTokenURI;
    }

    /// @notice Block transfers when non-transferable (soulbound). Mints always allowed.
    function _beforeTokenTransfer(address from, address to, uint256 firstTokenId, uint256 batchSize) internal virtual override {
        super._beforeTokenTransfer(from, to, firstTokenId, batchSize);
        // from == address(0) means mint — always allow
        if (from != address(0)) {
            require(transferable, "Token is non-transferable");
        }
    }

    function totalMinted() external view returns (uint256) { return _nextTokenId; }
    function setMintPrice(uint256 price) external onlyOwner { mintPrice = price; }
    function setMaxSupply(uint256 supply) external onlyOwner {
        require(supply >= _nextTokenId, "Below minted");
        maxSupply = supply;
    }
    function setTreasury(address treasury_) external onlyOwner { treasury = treasury_; }
    function setBaseURI(string memory baseURI_) external onlyOwner { _baseTokenURI = baseURI_; }
    function setTransferable(bool _transferable) external onlyOwner { transferable = _transferable; }
    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
    function withdraw() external onlyOwner {
        (bool ok, ) = payable(treasury).call{value: address(this).balance}("");
        require(ok, "Withdraw failed");
    }
}
