#pragma once

//Uncomment to stop debugging messages
#define DEBUGGING 

#ifndef DEBUG_PREFIX
#define DEBUG_PREFIX ""
#endif

#define LOG(msg) cout << DEBUG_PREFIX << msg << endl;

#ifdef DEBUGGING
#define DEBUG(msg) cout << "[Debug] "; LOG(msg);
#endif

#ifndef DEBUGGING
#define DEBUG(msg) 
#endif

