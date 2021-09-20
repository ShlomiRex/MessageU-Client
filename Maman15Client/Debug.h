#pragma once

#include <iostream>

//using namespace std; //not good practice

//Uncomment to stop debugging messages
#define DEBUGGING 

#ifndef DEBUG_PREFIX
#define DEBUG_PREFIX ""
#endif

#define LOG(msg) std::cout << DEBUG_PREFIX << msg << std::endl;

#ifdef DEBUGGING
#define DEBUG(msg) std::cout << "[Debug] "; LOG(msg);
#endif

#ifndef DEBUGGING
#define DEBUG(msg) 
#endif

