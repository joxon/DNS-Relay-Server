#pragma once

#include "header.h"

class IpDomainNode
{
public:
    string ip;
    string domain;

    void set(string pip, string pdomain)
    {
        ip = pip;
        domain = pdomain;
    }
};

//ID转换表
//中继DNS请求包更名前的相关信息
class IDTransferNode
{
public:
    //旧ID
    unsigned short oldID;

    //请求者套接字地址
    SOCKADDR_IN clientAddr;

    //标记是否已经完成解析
    bool processed;
};

class MySystemTime
{
public:
    SYSTEMTIME t;
    void print()
    {
        GetLocalTime(&t);
        cout << endl
            << dec << t.wYear << "-" << t.wMonth << "-" << t.wDay
            << ' ' << t.wHour << ':' << t.wMinute << ':' << t.wSecond << ":" << t.wMilliseconds << endl;
    }
};

class Flags
{
public:
    //(2字节)ID号
    unsigned short id;

    //(1比特)queryOrResponse，查询/响应的标志位，1为响应，0为查询
    int QR;

    //(4比特)operationCode，定义查询或响应的类型(若为0则表示是标准的，若为1则是反向的，若为2则是服务器状态请求)。
    unsigned short OPCODE;

    //(1比特)authoritativeAnswer，授权回答的标志位。该位在响应报文中有效，1表示名字服务器是权限服务器
    int AA;

    //(1比特)trunCated，截断标志位。1表示响应已超过512字节并已被截断
    int TC;

    //(1比特)recursionDesired，该位为1表示客户端希望得到递归回答
    int RD;

    //(1比特)recursionAvailable，该位为1表示客户端希望得到递归回答
    int RA;

    //(4比特)responseCode，返回码，表示响应的差错状态，0无差错，3有差错
    unsigned short RCODE;

    //RR=Resource Record，资源记录
    //questionCount，问题数
    unsigned short QDCOUNT;

    //answerCount，回答数
    unsigned short ANCOUNT;

    //nameServerCount，权威服务器数
    unsigned short NSCOUNT;

    //additionalRecordCount，附加记录数
    unsigned short ARCOUNT;

    void set(char* buf)
    {
        //从报文头部前16bit获得ID
        unsigned short * us = (unsigned short *)malloc(sizeof(unsigned short));
        memcpy(us, buf, sizeof(unsigned short));
        id = ntohs(*us);

        //处理第二行（共16bit）
        //第二行前8个比特，注意反向接收
        bitset<8> bs8(buf[2]);
        QR = bs8[7];
        OPCODE = 0;
        OPCODE += bs8[6] * 8;
        OPCODE += bs8[5] * 4;
        OPCODE += bs8[4] * 2;
        OPCODE += bs8[3];
        AA = bs8[2];
        TC = bs8[1];
        RD = bs8[0];

        //第二行后8个比特，注意反向接收
        bs8 = buf[3];
        RA = bs8[7];
        RCODE = 0;
        RCODE += bs8[3] * 8;
        RCODE += bs8[2] * 4;
        RCODE += bs8[1] * 2;
        RCODE += bs8[0];

        //第三行
        memcpy(us, &buf[4], 2);
        QDCOUNT = ntohs(*us);

        //第四行
        memcpy(us, &buf[6], 2);
        ANCOUNT = ntohs(*us);

        //第五行
        memcpy(us, &buf[8], 2);
        NSCOUNT = ntohs(*us);

        //第六行
        memcpy(us, &buf[10], 2);
        ARCOUNT = ntohs(*us);

        free(us);
    }

    void print()
    {
        cout << "ID = " << id << endl
            << "QR = " << QR << endl
            << "OPCODE = " << OPCODE << endl
            << "AA = " << AA << endl
            << "TC = " << TC << endl
            << "RD = " << RD << endl
            << "RA = " << RA << endl
            << "RCODE = " << RCODE << endl
            << "QDCOUNT = " << QDCOUNT << endl
            << "ANCOUNT = " << ANCOUNT << endl
            << "NSCOUNT = " << NSCOUNT << endl
            << "ARCOUNT = " << ARCOUNT << endl;
    }
};
