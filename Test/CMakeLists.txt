project(websocket_lite_test)

if(MSVC)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /wd4100")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic")
endif()

add_definitions(
	-DTEST_CERTIFICATE_PRIVATE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/../Test/private.key"
	-DTEST_CERTIFICATE_PUBLIC_PATH="${CMAKE_CURRENT_SOURCE_DIR}/../Test/public.crt"
	-DTEST_DH_PATH="${CMAKE_CURRENT_SOURCE_DIR}/../Test/dh.key"
	-DTEST_CERTIFICATE_PRIVATE_PASSWORD="Test pass"
	-DTEST_FUZZING_PATH="${CMAKE_CURRENT_SOURCE_DIR}/../Test/fuzzingclient.json"
)
include_directories(${CMAKE_SOURCE_DIR}/include)
add_executable(${PROJECT_NAME} main.cpp)

if(WIN32) 
	target_link_libraries(${PROJECT_NAME} websocket_lite ${COMMONLIBRARIES} Crypt32)
elseif(APPLE) 
	target_link_libraries(${PROJECT_NAME} websocket_lite ${COMMONLIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
else()
	target_link_libraries(${PROJECT_NAME} websocket_lite ${COMMONLIBRARIES} ${CMAKE_THREAD_LIBS_INIT} dl)
endif()

add_test (NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
