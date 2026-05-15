# CMake generated Testfile for 
# Source directory: /home/mete/routa
# Build directory: /home/mete/routa/build_asan
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[test_buf]=] "/home/mete/routa/build_asan/test_buf")
set_tests_properties([=[test_buf]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/mete/routa/CMakeLists.txt;77;add_test;/home/mete/routa/CMakeLists.txt;0;")
add_test([=[test_request]=] "/home/mete/routa/build_asan/test_request")
set_tests_properties([=[test_request]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/mete/routa/CMakeLists.txt;78;add_test;/home/mete/routa/CMakeLists.txt;0;")
add_test([=[test_middleware]=] "/home/mete/routa/build_asan/test_middleware")
set_tests_properties([=[test_middleware]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/mete/routa/CMakeLists.txt;79;add_test;/home/mete/routa/CMakeLists.txt;0;")
add_test([=[test_chunked]=] "/home/mete/routa/build_asan/test_chunked")
set_tests_properties([=[test_chunked]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/mete/routa/CMakeLists.txt;80;add_test;/home/mete/routa/CMakeLists.txt;0;")
