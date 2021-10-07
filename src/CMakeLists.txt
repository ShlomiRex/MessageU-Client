
set(TARGET MessageU-Client)

#add_subdirectory(Client)
#add_subdirectory(Crypto)
#add_subdirectory(Menu)
#add_subdirectory(MessageU)
#add_subdirectory(Utils)

add_executable(${TARGET} main.cpp ../include/Test/Test.h Test/Test.cpp)
