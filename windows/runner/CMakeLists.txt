cmake_minimum_required(VERSION 3.14)
project(runner LANGUAGES CXX)

add_executable(${BINARY_NAME} WIN32
        "flutter_window.cpp"
        "main.cpp"
        "utils.cpp"
        "win32_window.cpp"
        "toast_notifier.cpp"
        "${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
        "Runner.rc"
        "runner.exe.manifest"
)

apply_standard_settings(${BINARY_NAME})

target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION=\"${FLUTTER_VERSION}\"")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_MAJOR=${FLUTTER_VERSION_MAJOR}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_MINOR=${FLUTTER_VERSION_MINOR}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_PATCH=${FLUTTER_VERSION_PATCH}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_BUILD=${FLUTTER_VERSION_BUILD}")

target_compile_definitions(${BINARY_NAME} PRIVATE "NOMINMAX")

target_link_libraries(${BINARY_NAME} PRIVATE flutter flutter_wrapper_app)
target_link_libraries(${BINARY_NAME} PRIVATE "dwmapi.lib")
target_link_libraries(${BINARY_NAME} PRIVATE "windowsapp.lib")
target_include_directories(${BINARY_NAME} PRIVATE "${CMAKE_SOURCE_DIR}")

add_dependencies(${BINARY_NAME} flutter_assemble)

set(VX_ENGINE_DLL
        "${CMAKE_SOURCE_DIR}/../engine/windows/vx_titanium.dll"
)
set(TFLITE_DLL
        "${CMAKE_SOURCE_DIR}/../engine/windows/tensorflowlite_c.dll"
)
set(VX_DEFS_DIR
        "${CMAKE_SOURCE_DIR}/../assets/defs"
)
set(AXSERVICE_EXE
        "${CMAKE_SOURCE_DIR}/../assets/axservice/axservice.exe"
)
set(AXNOTIFY_EXE
        "${CMAKE_SOURCE_DIR}/../assets/axservice/axnotify.exe"
)

if(NOT EXISTS "${VX_ENGINE_DLL}")
    message(FATAL_ERROR "Missing vx_titanium.dll: ${VX_ENGINE_DLL}")
endif()

if(NOT EXISTS "${TFLITE_DLL}")
    message(FATAL_ERROR "Missing tensorflowlite_c.dll: ${TFLITE_DLL}")
endif()

if(NOT EXISTS "${VX_DEFS_DIR}")
    message(FATAL_ERROR "Missing defs dir: ${VX_DEFS_DIR}")
endif()

if(NOT EXISTS "${AXSERVICE_EXE}")
    message(FATAL_ERROR "Missing axservice.exe: ${AXSERVICE_EXE}")
endif()

if(NOT EXISTS "${AXNOTIFY_EXE}")
    message(FATAL_ERROR "Missing axnotify.exe: ${AXNOTIFY_EXE}")
endif()

add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${VX_ENGINE_DLL}"
        "$<TARGET_FILE_DIR:${BINARY_NAME}>/vx_titanium.dll"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${TFLITE_DLL}"
        "$<TARGET_FILE_DIR:${BINARY_NAME}>/tensorflowlite_c.dll"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${AXSERVICE_EXE}"
        "$<TARGET_FILE_DIR:${BINARY_NAME}>/axservice.exe"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${AXNOTIFY_EXE}"
        "$<TARGET_FILE_DIR:${BINARY_NAME}>/axnotify.exe"
        COMMAND ${CMAKE_COMMAND} -E make_directory
        "$<TARGET_FILE_DIR:${BINARY_NAME}>/assets/defs"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${VX_DEFS_DIR}"
        "$<TARGET_FILE_DIR:${BINARY_NAME}>/assets/defs"
)