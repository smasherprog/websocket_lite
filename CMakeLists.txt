cmake_minimum_required(VERSION 3.8)
project(websocket_lite)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(BUILD_SHARED_LIBS "Build the shared library" OFF)
option(CUSTOM_OPENSSL "Build the library using a custom openssl version" OFF)
option(CUSTOM_ZLIB "Build the library using a custom zlib version" OFF)

message(STATUS CUSTOM_OPENSSL=${CUSTOM_OPENSSL})
message(STATUS CUSTOM_ZLIB=${CUSTOM_ZLIB})

include(CMakeLists-ExternalProjects.txt)

if(MSVC)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
else()
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic")
endif()
add_definitions(-DBOOST_REGEX_NO_LIB -DBOOST_DATE_TIME_NO_LIB -DASIO_STANDALONE -DBOOST_NO_EXCEPTIONS)


set(COMMON_LIBRARIES  
	${ZLIB_LIBRARIES} 
	${OPENSSL_LIBRARIES}
)	

include_directories(
	include
	${CMAKE_INSTALL_PREFIX}/include
)
link_directories(${CMAKE_INSTALL_PREFIX}/lib)
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
add_dependencies(${PROJECT_NAME} asio)
if(NOT ${CUSTOM_OPENSSL})
	add_dependencies(${PROJECT_NAME} openssl)
endif()
if(NOT ${CUSTOM_ZLIB})
	add_dependencies(${PROJECT_NAME} zlib)
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
