#pragma once
#include <openssl/sha.h>

namespace SL {
	namespace WS_LITE {
		template<class type>
		void SHA1(const type& input, type& hash) {
			SHA_CTX context;
			SHA1_Init(&context);
			SHA1_Update(&context, &input[0], input.size());

			hash.resize(160 / 8);
			SHA1_Final((unsigned char*)&hash[0], &context);
		}
		template<class type>
		type SHA1(const type& input) {
			type hash;
			SHA1(input, hash);
			return hash;
		}

	}
}