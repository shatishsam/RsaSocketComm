// client.cpp
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <thread>

#include "constants.h"

// Function to handle receiving messages from the server
void receive_messages(int client_fd) {
    char buffer[BUFFER_SIZE];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int read_val = read(client_fd, buffer, BUFFER_SIZE);
        if (read_val <= 0) {
            std::cerr << "Server disconnected or error reading!" << std::endl;
            break;
        }
        std::cout << "server says: " << buffer << std::endl;
    }
}

// Function to handle sending messages to the server
void send_messages(int client_fd) {
    while (true) {
        //std::cout << "Enter message to send (or type 'exit' to quit): ";
        char message[BUFFER_SIZE];
        std::cin.getline(message, BUFFER_SIZE);

        // Exit if the user types "exit"
        if (strcmp(message, "exit") == 0) {
            break;
        }

        // Send message to server
        send(client_fd, message, strlen(message), 0);
        //std::cout << "Message sent to server: " << message << std::endl;
    }
}

int main() {
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

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid server address!" << std::endl;
        return -1;
    }

    // Connect to the server
    if (connect(client_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection failed!" << std::endl;
        return -1;
    }

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
