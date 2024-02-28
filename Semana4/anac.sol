pragma solidity ^0.8.0;

// Define the smart contract named VerificarDocumentos
contract VerificarDocumentos {
    // Declare a state variable to store the age
    uint256 idade;
    // Declare a public state variable to store the owner's address
    address public owner;

    // Constructor function that sets the initial age and owner
    constructor() {
        idade = 18;        
        owner = msg.sender; 

    // Modifier to restrict certain functions to the contract owner
    modifier OwnerOnly() {
        require(msg.sender == owner, "Not owner"); 
        _;
    }

    // Function to set the age, restricted to the owner
    function setIdade(uint256 _idade) external OwnerOnly returns (bool) {
        idade = _idade; 
        return true;
    }

    // Function to get the age, accessible to anyone
    function getIdade() external view returns (uint256) {
        return idade; // Return the current age
    }
}
