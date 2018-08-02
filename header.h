#pragma once

#include <winsock2.h>
#include <windows.h>

#include <bitset>
#include <iostream>
#include <fstream>
#include <string>
#include <deque>

using namespace std;

#define IDT_MAX_SIZE 1000  //±ØÐëÎªÅ¼Êý
#define IDT_HALF_SIZE (IDT_MAX_SIZE/2)

#define DEFAULT_PORT 53
#define DEFAULT_DNS_SERVER "10.3.9.4"
#define DEFAULT_LOCAL_PATH ".\\DNS-Relay.txt"

#define OUTPUT_QUIET 0
#define OUTPUT_NORMAL 1
#define OUTPUT_DEBUG 2

#define LOCAL_NOT_FOUND "LNF"

#define QR_QUERY 0
#define QR_RESPONSE 1