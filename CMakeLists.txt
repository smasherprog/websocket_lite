cmake_minimum_required(VERSION 3.8)
project(websocket_lite)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(BUILD_SHARED_LIBS "Build the shared library" ON)

if(MSVC)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
else()
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic")
endif()
add_definitions(-DBOOST_REGEX_NO_LIB -DBOOST_DATE_TIME_NO_LIB -DASIO_STANDALONE -DBOOST_NO_EXCEPTIONS)
find_package(ZLIB REQUIRED) 
find_package(OpenSSL REQUIRED) 
	
set(COMMON_LIBRARIES  
	${ZLIB_LIBRARIES} 
	${OPENSSL_LIBRARIES}
)	

include_directories(
	include
	${OPENSSL_INCLUDE_DIR}
	${ZLIB_INCLUDE_DIRs}
)
add_library(${PROJECT_NAME} 	
	src/Utils.cpp
	src/ListenerImpl.cpp
	src/ClientImpl.cpp
	src/WSContext.cpp
)

if(${BUILD_SHARED_LIBS})
	set_target_properties(${PROJECT_NAME} PROPERTIES DEFINE_SYMBOL WS_LITE_DLL)
	if(WIN32) 
		target_link_libraries(${PROJECT_NAME} ${COMMON_LIBRARIES} Crypt32)
	elseif(APPLE) 
		find_package(Threads REQUIRED)
		target_link_libraries(${PROJECT_NAME} ${COMMON_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
	else()
		find_package(Threads REQUIRED)
		target_link_libraries(${PROJECT_NAME} ${COMMON_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} dl)
	endif()
endif()

install (TARGETS ${PROJECT_NAME}  
	RUNTIME DESTINATION bin
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib)

		
install (FILES 
	include/WS_Lite.h
	include/Logging.h
	DESTINATION include)
	 
enable_testing() 
add_subdirectory(Test)
