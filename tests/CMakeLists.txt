add_executable(pkicxx-test src/pkicxx-test.cpp)
# Basic memory bug catcher
target_compile_options(pkicxx-test PRIVATE -fsanitize=address -fno-omit-frame-pointer)
target_link_options(pkicxx-test PRIVATE -fsanitize=address)
target_link_libraries(pkicxx-test PRIVATE pkicxx)
target_include_directories(pkicxx-test PRIVATE "${CMAKE_SOURCE_DIR}/include")
add_test(NAME "Keypair factory" COMMAND pkicxx-test --factoryInit)
add_test(NAME "Keypair generation" COMMAND pkicxx-test --pairGen)
add_test(NAME "Keypair re-generation" COMMAND pkicxx-test --pairGen)
add_test(NAME "Keypair multi-generation" COMMAND pkicxx-test --pairMultigen)
add_test(NAME "DER pivkey" COMMAND pkicxx-test --privDER)
add_test(NAME "DER pubkey" COMMAND pkicxx-test --pubDER)
add_test(NAME "PEM privkey string" COMMAND pkicxx-test --privPEM)
add_test(NAME "PEM pubkey string" COMMAND pkicxx-test --pubPEM)
add_test(NAME "PEM bundle string" COMMAND pkicxx-test --bundlePEM)
add_test(NAME "Encrypt" COMMAND pkicxx-test --encrypt)
add_custom_command(TARGET pkicxx-test POST_BUILD COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure)


