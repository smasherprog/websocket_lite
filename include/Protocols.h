#pragma once
#include <string>
#include <unordered_map>

namespace SL {
	namespace WS_LITE {
		enum SocketTypes {
			SERVER,
			CLIENT
		};
		enum OpCode : unsigned char {
			TEXT = 1,
			BINARY = 2,
			CLOSE = 8,
			PING = 9,
			PONG = 10
		};
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

	}
}