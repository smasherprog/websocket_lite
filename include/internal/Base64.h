#pragma once
#include <openssl/buffer.h>

namespace SL {
	namespace WS_LITE {
		
		template<class type>
		void Base64Encode(const type& ascii, type& base64) {
			BIO *bio, *b64;
			BUF_MEM *bptr;

			b64 = BIO_new(BIO_f_base64());
			BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
			bio = BIO_new(BIO_s_mem());
			BIO_push(b64, bio);
			BIO_get_mem_ptr(b64, &bptr);

			//Write directly to base64-buffer to avoid copy
			int base64_length = static_cast<int>(round(4 * ceil((double)ascii.size() / 3.0)));
			base64.resize(base64_length);
			bptr->length = 0;
			bptr->max = base64_length + 1;
			bptr->data = (char*)&base64[0];

			BIO_write(b64, &ascii[0], static_cast<int>(ascii.size()));
			BIO_flush(b64);

			//To keep &base64[0] through BIO_free_all(b64)
			bptr->length = 0;
			bptr->max = 0;
			bptr->data = nullptr;

			BIO_free_all(b64);
		}
		template<class type>
		type Base64Encode(const type& ascii) {
			type base64;
			encode(ascii, base64);
			return base64;
		}

		template<class type>
		void Base64Decode(const type& base64, type& ascii) {
			//Resize ascii, however, the size is a up to two bytes too large.
			ascii.resize((6 * base64.size()) / 8);
			BIO *b64, *bio;

			b64 = BIO_new(BIO_f_base64());
			BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
			bio = BIO_new_mem_buf((char*)&base64[0], static_cast<int>(base64.size()));
			bio = BIO_push(b64, bio);

			int decoded_length = BIO_read(bio, &ascii[0], static_cast<int>(ascii.size()));
			ascii.resize(decoded_length);

			BIO_free_all(b64);
		}
		template<class type>
		type Base64Decode(const type& base64) {
			type ascii;
			decode(base64, ascii);
			return ascii;
		}

	}
}
