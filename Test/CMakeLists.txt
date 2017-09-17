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
include_directories(${CMAKE_SOURCE_DIR}/include ${COMMON_INCLUDE_DIRS})
add_executable(${PROJECT_NAME} main.cpp)


if(${BUILD_SHARED_LIBS})
	set_target_properties(${PROJECT_NAME} PROPERTIES DEFINE_SYMBOL WS_LITE_DLL)
	if(WIN32) 
		target_link_libraries(${PROJECT_NAME} websocket_lite ${COMMON_LIBRARIES} Crypt32)
		
	add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD 
				   COMMAND ${CMAKE_COMMAND} -E copy_if_different
				   $<TARGET_FILE:websocket_lite>              
				   $<TARGET_FILE_DIR:${PROJECT_NAME}>)
			   
	add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD 
				   COMMAND ${CMAKE_COMMAND} -E copy_if_different
				   $<TARGET_FILE:${OPENSSL_LIBRARIES}>              
				   $<TARGET_FILE_DIR:${PROJECT_NAME}>)
			   
	add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD 
				   COMMAND ${CMAKE_COMMAND} -E copy_if_different
				   $<TARGET_FILE:${ZLIB_LIBRARIES}>              
				   $<TARGET_FILE_DIR:${PROJECT_NAME}>)

	elseif(APPLE) 
		find_package(Threads REQUIRED)
		target_link_libraries(${PROJECT_NAME} websocket_lite ${COMMON_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
	else()
		find_package(Threads REQUIRED)
		target_link_libraries(${PROJECT_NAME} websocket_lite ${COMMON_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} dl)
	endif()

endif()

add_test (NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
