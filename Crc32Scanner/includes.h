#pragma once

#include <iostream>
#include <Windows.h>
#include <cstdio>
#include <tlhelp32.h>
#include <iomanip>
#include <inttypes.h>
#include <conio.h>
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <vector>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>


#include "VirtualAddressMap.h"
#include "cr32scanner.h"

#ifdef _WIN32
#include "getwinopt.h"
#else
#include <unistd.h>
#endif