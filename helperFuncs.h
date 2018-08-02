#pragma once

#include "header.h"
#include "helperClasses.h"

#define LOGI(msg) (std::cout<< "[INFO] " << msg << std::endl)
#define LOGW(msg) (std::cout<< "[WARNING] " << msg << std::endl)
#define LOGD(msg) (std::cout<< "[DEBUG] " << msg << std::endl)
#define LOGE(msg) (std::cout<< "[ERROR] " << msg << std::endl)

void parseParam(int argc,
                char** argv,
                string &localPath,
                string &outAddr,
                int &outputLevel);

void loadLocalList(string localPath,
                   deque<IpDomainNode> &ipdict,
                   int outputLevel);

string localQuery(string tempdomain, deque<IpDomainNode> ipdict);

string getDomain(char* rec_buf,
                 int Rec_f,
                 unsigned short &QClASS,
                 unsigned short &QTYPE);

void printBuf(char* s, int num);

void handleIDTList(deque<IDTransferNode> &idtlist,
                   int &idtlist_base);

int pos2id(deque<IDTransferNode> idtlist,
           int idtlist_base);

int id2pos(int x, int idtlist_base);
