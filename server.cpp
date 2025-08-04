// server.cpp
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <thread>
#include <unordered_map>

#include "constants.h"
#include "rsa_utils.h"

class clientDetails
{
    public:
    int client_fd;
    RSA* client_public_key;

    clientDetails()
    {
        client_fd = -1;
        client_public_key = nullptr;
    }
};

RSA* server_private_key = nullptr;

RSA* server_public_key = nullptr;

std::unordered_map<int, clientDetails*> clientHashMap; //holds all the clients public key

void doClientCleanUp(int client_fd)
{
    if(clientHashMap.find(client_fd) != clientHashMap.end())
    {
        //free public key
        free(clientHashMap[client_fd]->client_public_key);
        clientHashMap[client_fd]->client_public_key = nullptr;

        //free client details
        free(clientHashMap[client_fd]);
        clientHashMap[client_fd] = nullptr;

        //delete entry from hashmap
        clientHashMap.erase(client_fd);
    }
    close(client_fd);
}

void receive_messages(int client_fd)
{
    char buffer[BUFFER_SIZE];

    while (true) 
    {
        memset(buffer, 0, sizeof(buffer));
        int read_val = read(client_fd, buffer, BUFFER_SIZE);
        if (read_val <= 0) 
        {
            std::cerr << "Client disconnected or error reading!" << std::endl;
            break;
        }

        // Decrypt message from client using private key
        unsigned char decrypted[BUFFER_SIZE];
        int decrypted_length = rsa_private_decrypt((unsigned char*)buffer, read_val, decrypted, server_private_key);
        decrypted[decrypted_length] = '\0';
        std::cout << "Decrypted message from client: " << decrypted << std::endl;
    }

    doClientCleanUp(client_fd);
}

void send_messages(int client_fd) 
{
    while (true) 
    {
        char message[BUFFER_SIZE];
        std::cout << "Enter message to send (or type 'exit' to quit): ";
        std::cin.getline(message, BUFFER_SIZE);

        if (strcmp(message, "exit") == 0) 
        {
            break;  //if server gets exit what do we do?
        }

        // Encrypt response message with client's public key
        if(clientHashMap.find(client_fd) == clientHashMap.end() || !clientHashMap[client_fd]->client_public_key)
        {
            std::cout << "Cannot send mesaage to client "<<client_fd<<" as it probably closed the connection. stopping send thread"<<std::endl;
            break;
        }
        unsigned char encrypted[BUFFER_SIZE];
        int encrypted_length = rsa_public_encrypt(message, encrypted, clientHashMap[client_fd]->client_public_key);

        // Send the encrypted message to the client
        int send_val = send(client_fd, encrypted, encrypted_length, 0);
        if (send_val <= 0)
        {
            std::cerr << "client disconnected or error reading!" << std::endl;
            break;
        }
        std::cout << "Encrypted response sent to client." << std::endl;
    }

    doClientCleanUp(client_fd);
}

int receiveAndProcessClientPublicKey(int client_fd)
{
    // Receive the client's public key
    RSA* client_public_key = nullptr;
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));
    int received_length = read(client_fd, buffer, BUFFER_SIZE);
    if (received_length <= 0) 
    {
        std::cerr << "Failed to receive the client's public key!" << std::endl;
        return -1;
    }
    else
    {
        std::cout << "Public Key from Client is : "<< std::endl << buffer << std::endl;
    }

    // Convert the client's public key from PEM string to RSA public key
    std::string client_public_key_pem(buffer, received_length);
    BIO* bio = BIO_new_mem_buf(client_public_key_pem.c_str(), -1);
    client_public_key = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!client_public_key) {
        std::cerr << "Failed to parse the client's public key!" << std::endl;
        return -1;
    }

    //add client details to the hashmap
    clientDetails *newClient = new clientDetails();
    newClient->client_fd = client_fd;
    newClient->client_public_key = client_public_key;
    clientHashMap[client_fd] = newClient;

    return 0;
}

int sendPublicKeyToClient(int client_fd)
{
    // Send the server's public key to the client
    std::string server_public_key_pem = rsa_public_key_to_pem(server_public_key);
    int send_val =  send(client_fd, server_public_key_pem.c_str(), server_public_key_pem.length(), 0);
    if(send_val < 0){
        std::cerr << "error with sending public key to client" << std::endl;
    }
    return send_val;
}

int performDigitalSignalValidation(int client_fd)
{
    std::string hashValue = sha256(VALIDATION_TEXT);
    
    // Encrypt response message with servers private key to ensure identity
    unsigned char encrypted[BUFFER_SIZE];
    int encrypted_length = rsa_private_encrypt(hashValue.c_str(), encrypted, server_private_key);

    int send_val =  send(client_fd, encrypted, encrypted_length, 0);
    if(send_val < 0)
    {
        std::cerr << "error with sending public key to client" << std::endl;
    }
    std::cout<<"sent hash "<<hashValue<<" to client bytes: "<<send_val<<std::endl;
    return send_val;
}

// Main server function
int main() 
{
    // Generate RSA key pair for the server
    generate_rsa_key_pair(&server_public_key, &server_private_key);

    // Create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) 
    {
        std::cerr << "Socket creation failed!" << std::endl;
        return -1;
    }

    // Set server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Listen on all available interfaces
    server_addr.sin_port = htons(PORT);

    // Bind socket to address
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) 
    {
        std::cerr << "Server bind failed!" << std::endl;
        return -1;
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) 
    {
        std::cerr << "Listen failed!" << std::endl;
        return -1;
    }

    std::cout << "Server listening on port " << PORT << "..." << std::endl;

    // Accept and handle multiple clients
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    while (true) 
    {
        int new_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (new_socket < 0) 
        {
            std::cerr << "Accept failed!" << std::endl;
            continue;
        }
        std::cout << "Client connected!" << std::endl;

        //share server public key to client
        if(sendPublicKeyToClient(new_socket) < 0)
        {
            continue;
        }

        //receive clients public key
        if(receiveAndProcessClientPublicKey(new_socket) < 0)
        {
            continue;
        }
        std::cout << "Key Exchange Success!" << std::endl;

        //perform digital signature validation
        if(performDigitalSignalValidation(new_socket) < 0){
            std::cout<<"digital signature validation falied"<<std::endl;
        }

        // Start receiving and sending in separate threads
        std::thread receive_thread(receive_messages, new_socket);
        std::thread send_thread(send_messages, new_socket);

        // detach both threads so server can accept new client
        receive_thread.detach();
        send_thread.detach();
    }

    // Close the server socket
    close(server_fd);
    return 0;
}