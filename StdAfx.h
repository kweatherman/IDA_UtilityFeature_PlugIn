
#pragma once

#define WIN32_LEAN_AND_MEAN
#define WINVER		 0x0A00 // _WIN32_WINNT_WIN10
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdlib.h>
#include <mmsystem.h>
#include <intrin.h>
#pragma intrinsic(memset, memcpy, strcat, strcmp, strcpy, strlen)

// IDA libs
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
//#define NO_OBSOLETE_FUNCS
#pragma warning(push)
#pragma warning(disable:4244)  // conversion from 'ssize_t' to 'int', possible loss of data
#pragma warning(disable:4267)  // conversion from 'size_t' to 'uint32', possible loss of data
#pragma warning(disable:4018)  // warning C4018: '<': signed/unsigned mismatch
#include <ida.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include <graph.hpp>
#include <allins.hpp>
#include <entry.hpp>
#pragma warning(pop)

#include "Utility.h"

#define MY_VERSION MAKE_SEMANTIC_VERSION(VERSION_RELEASE, 4, 0, 0)