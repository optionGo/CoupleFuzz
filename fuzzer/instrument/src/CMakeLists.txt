llvm_map_components_to_libnames(llvm_libs bitwriter core ipo irreader instcombine instrumentation target linker analysis scalaropts support )
file (GLOB SOURCES
   *.cpp
)

add_executable(cbi cbi.cpp)

target_link_libraries(cbi ${SVF_LIB} ${LLVMCudd} ${llvm_libs})

set_target_properties( cbi PROPERTIES
                        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )



# add_library(argv STATIC argv-fuzz-inl.c)


# set_target_properties(argv PROPERTIES
#     OUTPUT_NAME "argv-replace"
#     ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
# )
