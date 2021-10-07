
set(TARGET MessageU-Client)

find_package(Boost 1.76.0)
if(Boost_FOUND)
    message("Found boost")

    include_directories(${Boost_INCLUDE_DIRS})
    add_executable(${TARGET} main.cpp)
    target_link_libraries(${TARGET} ${Boost_LIBRARIES})

    #add_subdirectory(Utils)


else()
    message("Boost not found")
endif()

#add_subdirectory(Client)
#add_subdirectory(Crypto)
#add_subdirectory(Menu)
#add_subdirectory(MessageU)

