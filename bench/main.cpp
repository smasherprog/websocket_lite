#include <iostream>
#if WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib")
#else 
#include <sys/socket.h>
#include <arpa/inet.h>

#endif
#include <cstring>
#include <string>
#include <chrono>
#include <errno.h>
#include <vector>
#include <mutex>
#include <thread>
#include <fstream>
using namespace std;
using namespace chrono;

int totalConnections = 500000;
unsigned short port = 3000;

#define CONNECTIONS_PER_ADDRESS 28000
#define THREADS 10

int connections, address = 1;
mutex m;

bool nextConnection(int tid)
{
    m.lock();
    int socketfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socketfd == -1) {
        cout << "FD error, connections: " << connections << endl;
        return false;
    }

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(("127.0.0." + to_string(address)).c_str());
    addr.sin_port = htons(port);
    m.unlock();

    // this is a shared upgrade, no need to make it unique
    const char *buf = "GET / HTTP/1.1\r\n"
        "Host: server.example.com\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
        "Sec-WebSocket-Protocol: default\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Origin: http://example.com\r\n\r\n";

    char message[1024];

    int err = connect(socketfd, (sockaddr *)&addr, sizeof(addr));
    if (err) {
        cout << "Connection error "<< err<< ", connections: " << connections << endl;
        return false;
    }
    send(socketfd, buf, strlen(buf), 0);
   memset(message, 0, 1024);
    size_t length;
    do {
        length = recv(socketfd, message, sizeof(message), 0);
    } while (strncmp(&message[length - 4], "\r\n\r\n", 4));

    m.lock();
    if (++connections % CONNECTIONS_PER_ADDRESS == 0) {
        address++;
    }

    if (connections % 1000 == 0 || connections < 1000) {
        cout << "Connections: " << connections << endl;
    }

    if (connections >= totalConnections - THREADS + 1) {
        m.unlock();
        return false;
    }

    m.unlock();
    return true;
}

int main(int argc, char **argv)
{
#if WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    auto startPoint = high_resolution_clock::now();
    vector<thread *> threads;
    for (int i = 0; i < THREADS; i++) {
        threads.push_back(new thread([i] {
            while (nextConnection(i));
        }));
    }

    for (thread *t : threads) {
        t->join();
    }

    double connectionsPerMs = double(connections) / duration_cast<milliseconds>(high_resolution_clock::now() - startPoint).count();
    cout << "Connection performance: " << connectionsPerMs << " connections/ms" << endl;
#if WIN32
    WSACleanup();
#endif
    int t;
    cin >> t;
    return 0;
}