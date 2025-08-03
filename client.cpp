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

void receive_messages(int server_fd) 
{
    char buffer[BUFFER_SIZE];
    
    while (true)
    {
        memset(buffer, 0, sizeof(buffer));
        int read_val = read(server_fd, buffer, BUFFER_SIZE);
        if (read_val <= 0)
        {
            std::cerr << "Server disconnected or error reading!" << std::endl;
            break;
        }

        // Decrypt the response from the server using private key
        unsigned char decrypted[BUFFER_SIZE];
        int decrypted_length = rsa_private_decrypt((unsigned char*)buffer, read_val, decrypted, client_private_key);
        decrypted[decrypted_length] = '\0';
        std::cout << "Decrypted message from server: " << decrypted << std::endl;
    }

    close(server_fd);
}

void send_messages(int server_fd) 
{
    while (true) 
    {
        char message[BUFFER_SIZE];
        std::cout << "Enter message to send (or type 'exit' to quit): ";
        std::cin.getline(message, BUFFER_SIZE);

        if (strcmp(message, "exit") == 0) 
        {
            break;
        }

        // Encrypt message with server's public key
        unsigned char encrypted[BUFFER_SIZE];
        int encrypted_length = rsa_public_encrypt(message, encrypted, server_public_key);

        // Send encrypted message to server
        int send_val = send(server_fd, encrypted, encrypted_length, 0);
        if (send_val <= 0)
        {
            std::cerr << "client disconnected or error reading!" << std::endl;
            break;
        }
        std::cout << "Encrypted message sent to server." << std::endl;
    }

    close(server_fd);
}

int receiveAndProcessServerPublicKey(int server_fd)
{
    // Receive the server's public key
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));
    int received_length = read(server_fd, buffer, BUFFER_SIZE);
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

int sendPublicKeyToServer(int server_fd)
{
    // Send the client's public key to the server
    std::string client_public_key_pem = rsa_public_key_to_pem(client_public_key);
    int send_val =  send(server_fd, client_public_key_pem.c_str(), client_public_key_pem.length(), 0);
    if(send_val < 0){
        std::cerr << "error with sending public key to server" << std::endl;
    }
    return send_val;
}

int performDigitalSignalValidation(int server_fd)
{
    std::string expectedHashValue = sha256(VALIDATION_TEXT);
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));
    int received_length = read(server_fd, buffer, BUFFER_SIZE);
    if (received_length <= 0) 
    {
        std::cerr << "Failed to receive the servers's hash value!" << std::endl;
        return received_length;
    }
    std::cout<<"received bytes form server for hash is: "<<received_length<<std::endl;

    //Decrypt message from client using private key
    unsigned char decrypted[BUFFER_SIZE];
    int decrypted_length = rsa_public_decrypt((unsigned char*)buffer, received_length, decrypted, server_public_key);
    decrypted[decrypted_length] = '\0';
    std::cout << "Received hash value from server is: " << decrypted << std::endl;

    return strcmp(expectedHashValue.c_str(), reinterpret_cast<const char*>(decrypted)) == 0;
}

int main()
{
    // Generate RSA key pair for the client
    generate_rsa_key_pair(&client_public_key, &client_private_key);

    // Create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
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
    if (connect(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Connection failed!" << std::endl;
        return -1;
    }

    //receive server public key
    if(receiveAndProcessServerPublicKey(server_fd) < 0)
    {
        close(server_fd);
        return -1;
    }

    //share client public key
    if(sendPublicKeyToServer(server_fd) < 0)
    {
        close(server_fd);
        return -1;
    }
    std::cout << "Key Exchange Success!" << std::endl;

    //perform digital signature validation
    if(performDigitalSignalValidation(server_fd)) {
        std::cout<<"digital signature of server validated success hash matches"<<std::endl;
    } else { 
        std::cout<<"digital signature validation falied"<<std::endl;
    }

    // Start receiving and sending in separate threads
    std::thread receive_thread(receive_messages, server_fd);
    std::thread send_thread(send_messages, server_fd);

    // Wait for both threads to finish
    receive_thread.join();
    send_thread.join();

    // Close the socket
    close(server_fd);

    return 0;
}
