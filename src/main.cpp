//
// Created by Shlomi Domnenko on 07/10/2021.
//
#include <iostream>
//#include "Utils/BufferUtils.h"
#include "Utils/Debug.h"

#include <boost/filesystem.hpp>

#define DEBUG_PREFIX "[main] "

int main() {
    std::cout << "Hello" << std::endl;

    //BufferWriter bufferWriter(100);
//    bufferWriter.writeVal(0, 100);
//
    //LOG(bufferWriter.getBuffer());

    LOG("Test");

    boost::filesystem::ofstream file("test.txt");
    std::string txt = "hello";
    file.write(txt.c_str(), txt.size());
    file.close();

    return 0;
}