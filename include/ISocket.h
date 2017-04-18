#pragma once
#include <string>


namespace SL {
	namespace WS_LITE {

		struct SocketStats {
			//total bytes that the Socket layer received from the upper layer. This is not the actual amount of data send across the network due to compressoin, encryption, etc
			long long TotalBytesSent;
			//total bytes that the Socket layer seent to the network layer
			long long NetworkBytesSent;
			//total number of messages sent
			long long TotalMessagesSent;
			//total bytes that the upper layer received from the socket layer after decompression, decryption, etc
			long long TotalBytesReceived;
			//total bytes that the Socket layer received from the network layer
			long long NetworkBytesReceived;
			//total number of messages received
			long long TotalMessageReceived;

		};

		class ISocket {
		public:

			virtual ~ISocket() {}
			virtual void send(char *, size_t) = 0;
			virtual void close(int code, std::string reason) = 0;
			virtual bool closed() = 0;

			//Get the statstics for this socket
			virtual SocketStats get_SocketStats() const = 0;

			//s in in seconds
			virtual void set_ReadTimeout(int s) = 0;
			//s in in seconds
			virtual void set_WriteTimeout(int s) = 0;

			virtual std::string get_address() const = 0;
			virtual unsigned short get_port() const = 0;

			virtual bool is_v4() const = 0;
			virtual bool is_v6() const = 0;
			//is the this connection to ourselfs? i.e. 127.0.0.1 or ::1, etc
			virtual bool is_loopback() const = 0;
		};
	}
}