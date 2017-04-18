#pragma once
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/deadline_timer.hpp>

namespace SL {
	namespace WS_LITE {

		template<class T>std::string get_address(T& _socket)
		{
			boost::system::error_code ec;
			auto rt(_socket.lowest_layer().remote_endpoint(ec));
			if (!ec) return rt.address().to_string();
			else return "";
		}
		template<class T> unsigned short get_port(T& _socket)
		{
			boost::system::error_code ec;
			auto rt(_socket.lowest_layer().remote_endpoint(ec));
			if (!ec) return rt.port();
			else return -1;
		}
		template<class T> bool is_v4(T& _socket)
		{
			boost::system::error_code ec;
			auto rt(_socket.lowest_layer().remote_endpoint(ec));
			if (!ec) return rt.address().is_v4();
			else return true;
		}
		template<class T> bool is_v6(T& _socket)
		{
			boost::system::error_code ec;
			auto rt(_socket.lowest_layer().remote_endpoint(ec));
			if (!ec) return rt.address().is_v6();
			else return true;
		}
		template<class T> bool is_loopback(T& _socket)
		{
			boost::system::error_code ec;
			auto rt(_socket.lowest_layer().remote_endpoint(ec));
			if (!ec) return rt.address().is_loopback();
			else return true;
		}

		template<class T> void readexpire_from_now(T& self, int seconds)
		{
			boost::system::error_code ec;
			if (seconds <= 0) self->_read_deadline.expires_at(boost::posix_time::pos_infin, ec);
			else  self->_read_deadline.expires_from_now(boost::posix_time::seconds(seconds), ec);
			if (ec) {
				SL_RAT_LOG(Utilities::Logging_Levels::ERROR_log_level, ec.message());
			}
			else if (seconds >= 0) {
				self->_read_deadline.async_wait([self, seconds](const boost::system::error_code& ec) {
					if (ec != boost::asio::error::operation_aborted) {
						self->close("read timer expired. Time waited: ");
					}
				});
			}
		}
		template<class T> void writeexpire_from_now(T& self, int seconds)
		{
			boost::system::error_code ec;
			if (seconds <= 0) self->_write_deadline.expires_at(boost::posix_time::pos_infin, ec);
			else self->_write_deadline.expires_from_now(boost::posix_time::seconds(seconds), ec);
			if (ec) {
				SL_RAT_LOG(Utilities::Logging_Levels::ERROR_log_level, ec.message());
			}
			else if (seconds >= 0) {
				self->_write_deadline.async_wait([self, seconds](const boost::system::error_code& ec) {
					if (ec != boost::asio::error::operation_aborted) {
						//close("write timer expired. Time waited: " + std::to_string(seconds));
						self->close("write timer expired. Time waited: ");
					}
				});
			}
		}
	}
}