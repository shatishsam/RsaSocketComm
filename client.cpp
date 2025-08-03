// client.cpp
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <thread>

#include "constants.h"
#include "rsa_utils.h"

RSA* client_private_key = nullptr;
RSA* client_public_key = nullptr;
RSA* server_public_key = nullptr;

void receive_messages(int client_fd) 
{
    char buffer[BUFFER_SIZE];
    
    while (true)
    {
        memset(buffer, 0, sizeof(buffer));
        int read_val = read(client_fd, buffer, BUFFER_SIZE);
        if (read_val <= 0)
        {
            std::cerr << "Server disconnected or error reading!" << std::endl;
            break;
        }

        // Decrypt the response from the server
        unsigned char decrypted[BUFFER_SIZE];
        int decrypted_length = rsa_decrypt((unsigned char*)buffer, read_val, decrypted, client_private_key);
        decrypted[decrypted_length] = '\0';
        std::cout << "Decrypted message from server: " << decrypted << std::endl;
    }

    close(client_fd);
}

void send_messages(int client_fd) 
{
    while (true) 
    {
        char message[BUFFER_SIZE];
        std::cout << "Enter message to send (or type 'exit' to quit): ";
        std::cin.getline(message, BUFFER_SIZE);

        if (strcmp(message, "exit") == 0) {
            break;
        }

        // Encrypt message with server's public key
        unsigned char encrypted[BUFFER_SIZE];
        int encrypted_length = rsa_encrypt(message, encrypted, server_public_key);

        // Send encrypted message to server
        int send_val = send(client_fd, encrypted, encrypted_length, 0);
        if (send_val <= 0)
        {
            std::cerr << "client disconnected or error reading!" << std::endl;
            break;
        }
        std::cout << "Encrypted message sent to server." << std::endl;
    }

    close(client_fd);
}

int receiveAndProcessServerPublicKey(int client_fd)
{
    // Receive the server's public key
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));
    int received_length = read(client_fd, buffer, BUFFER_SIZE);
    if (received_length <= 0) 
    {
        std::cerr << "Failed to receive the server's public key!" << std::endl;
        return -1;
    }
    else
    {
        std::cout << "Public Key from Server is : "<< std::endl << buffer << std::endl;
    }

    // Convert the server's public key from PEM string to RSA public key
    std::string server_public_key_pem(buffer, received_length);
    BIO* bio = BIO_new_mem_buf(server_public_key_pem.c_str(), -1);
    server_public_key = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!server_public_key) 
    {
        std::cerr << "Failed to parse the server's public key!" << std::endl;
        return -1;
    }
    return 0;
}

int sendPublicKeyToServer(int client_fd)
{
    // Send the client's public key to the server
    std::string client_public_key_pem = rsa_public_key_to_pem(client_public_key);
    int send_val =  send(client_fd, client_public_key_pem.c_str(), client_public_key_pem.length(), 0);
    if(send_val < 0){
        std::cerr << "error with sending public key to server" << std::endl;
    }
    return send_val;
}

int main()
{
    // Generate RSA key pair for the client
    generate_rsa_key_pair(&client_public_key, &client_private_key);

    // Create socket
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd == -1) {
        std::cerr << "Socket creation failed!" << std::endl;
        return -1;
    }

    // Set server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0)
    {
        std::cerr << "Invalid server address!" << std::endl;
        return -1;
    }

    // Connect to the server
    if (connect(client_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Connection failed!" << std::endl;
        return -1;
    }

    //receive server public key
    if(receiveAndProcessServerPublicKey(client_fd) < 0)
    {
        close(client_fd);
        return -1;
    }

    //share client public key
    if(sendPublicKeyToServer(client_fd) < 0)
    {
        close(client_fd);
        return -1;
    }
    std::cout << "Key Exchange Success!" << std::endl;

    // Start receiving and sending in separate threads
    std::thread receive_thread(receive_messages, client_fd);
    std::thread send_thread(send_messages, client_fd);

    // Wait for both threads to finish
    receive_thread.join();
    send_thread.join();

    // Close the socket
    close(client_fd);

    return 0;
}
