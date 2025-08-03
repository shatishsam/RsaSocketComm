// server.cpp
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <thread>
#include <atomic>

#include "constants.h"

// Function to handle receiving messages from the server
void receive_messages(int new_socket) 
{
    char buffer[BUFFER_SIZE];
    while (true) 
    {
        memset(buffer, 0, sizeof(buffer));
        int read_val = read(new_socket, buffer, BUFFER_SIZE);
        if (read_val <= 0) 
        {
            std::cerr << "Client disconnected or error reading!" << std::endl;
            break;
        }
        std::cout << "Client says: " << buffer << std::endl;
    }
}

// Function to handle sending messages to the client
void send_messages(int client_fd) 
{
    while (true) 
    {
        //std::cout << "Enter message to send (or type 'exit' to quit): ";
        char message[BUFFER_SIZE];
        std::cin.getline(message, BUFFER_SIZE);

        // Exit if the user types "exit"
        if (strcmp(message, "exit") == 0) {
            break;
        }

        // Send message to client
        send(client_fd, message, strlen(message), 0);
        //std::cout << "Message sent to Client: " << message << std::endl;
    }
}

// Main server function
int main() 
{
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
        std::cerr << "Bind failed!" << std::endl;
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
        if (new_socket < 0) {
            std::cerr << "Accept failed!" << std::endl;
            continue;
        }
        std::cout << "Client connected!" << std::endl;

        // Start receiving and sending in separate threads
        std::thread receive_thread(receive_messages, new_socket);
        std::thread send_thread(send_messages, new_socket);

        // Wait for both threads to finish
        receive_thread.join();
        send_thread.join();
    }

    // Close the server socket
    close(server_fd);
    return 0;
}