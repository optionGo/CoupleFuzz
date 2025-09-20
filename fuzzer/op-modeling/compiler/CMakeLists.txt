
add_executable(TestClang test_clang.c)
set_target_properties(TestClang PROPERTIES OUTPUT_NAME "test-clang")

add_custom_command(TARGET TestClang POST_BUILD
    COMMAND ln -sf "test-clang" "test-clang++")
install (TARGETS TestClang DESTINATION ${ANGORA_BIN_DIR})
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/test-clang++ DESTINATION ${ANGORA_BIN_DIR})


# add_executable(OoClangFast op-clang-fast.c)
# set_target_properties(OoClangFast PROPERTIES OUTPUT_NAME "op-clang-fast")

# add_custom_command(TARGET OoClangFast POST_BUILD
#     COMMAND ln -sf "op-clang-fast" "op-clang-fast++")
# install (TARGETS OoClangFast DESTINATION ${ANGORA_BIN_DIR})
# install (FILES ${CMAKE_CURRENT_BINARY_DIR}/op-clang-fast++ DESTINATION ${ANGORA_BIN_DIR})