cmake_minimum_required(VERSION 3.14)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


find_package(QT NAMES Qt6 REQUIRED COMPONENTS Core)
find_package(Qt6 REQUIRED COMPONENTS Core)
find_package(Qt6 REQUIRED COMPONENTS WebSockets)
if(MSVC)
    include_directories(win64/includes)
    link_directories(win64)
else()
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    find_package(Botan REQUIRED)
endif()

add_subdirectory(obfy)

add_library(OpenLicenseCommunication	STATIC
   websocketserver.h websocketserver.cpp
   request.h request.cpp
   servercommunicator.h servercommunicator.cpp
   networkclient.h networkclient.cpp
   servicecommunicator.h servicecommunicator.cpp
   license.h license.cpp
   licenseencrypter.h licenseencrypter.cpp
   fileencrypter.h fileencrypter.cpp
   keycreator.h keycreator.cpp
   report.h report.cpp
   violation.h violation.cpp
   obfuscate.h
)

if(MSVC)
    target_link_libraries(OpenLicenseCommunication PUBLIC
        Qt6::Core
        Qt6::WebSockets
        botan
)
else()
    target_link_libraries(OpenLicenseCommunication PUBLIC
        Qt6::Core
        Qt6::WebSockets
        Botan::Botan
    )
endif()
