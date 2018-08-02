#include "helperFuncs.h"

void parseParam(int argc,
                char** argv,
                string &localPath,
                string &dnsServer,
                int &outputLevel)
{
    string arg;
    switch (argc)
    {
        //至少有一个参数，即程序名
        case 1:
            localPath = DEFAULT_LOCAL_PATH;
            dnsServer = DEFAULT_DNS_SERVER;
            outputLevel = OUTPUT_QUIET;//无调试信息输出
            break;
            //处理第二个参数
        case 2:
            //输出等级为1
            if (strcmp(argv[1], "-d") == 0)
            {
                outputLevel = OUTPUT_NORMAL;
                localPath = DEFAULT_LOCAL_PATH;
                dnsServer = DEFAULT_DNS_SERVER;
            }
            //输出等级为2
            else if (strcmp(argv[1], "-dd") == 0)
            {
                outputLevel = OUTPUT_DEBUG;
                localPath = DEFAULT_LOCAL_PATH;
                dnsServer = DEFAULT_DNS_SERVER;
            }
            //指定DNS服务器IP或者本地列表
            else
            {
                outputLevel = OUTPUT_QUIET;
                arg = argv[1];
                cout << arg << endl;
                //传入DNS服务器IP
                if (arg.find(':', 0) == string::npos)
                {
                    localPath = DEFAULT_LOCAL_PATH;
                    dnsServer = argv[1];
                }
                //传入本地列表路径
                else
                {
                    localPath = argv[1];
                    dnsServer = DEFAULT_DNS_SERVER;
                }
            }
            break;

        case 3:
            if (strcmp(argv[1], "-d") == 0)
            {
                outputLevel = OUTPUT_NORMAL;
                arg = argv[2];
                cout << arg << endl;
                if (arg.find(':', 0) == string::npos)//传的是ip
                {
                    localPath = DEFAULT_LOCAL_PATH;
                    dnsServer = argv[2];
                }
                else//传的是txt路径
                {
                    localPath = argv[2];
                    dnsServer = DEFAULT_DNS_SERVER;
                }
            }
            else if (strcmp(argv[1], "-dd") == 0)
            {
                outputLevel = OUTPUT_DEBUG;
                arg = argv[2];
                cout << arg << endl;
                if (arg.find(':', 0) == string::npos)//传的是ip
                {
                    localPath = DEFAULT_LOCAL_PATH;
                    dnsServer = argv[2];
                }
                else//传的是txt路径
                {
                    localPath = argv[2];
                    dnsServer = DEFAULT_DNS_SERVER;
                }
            }
            else
            {
                outputLevel = OUTPUT_QUIET;
                dnsServer = argv[1];
                localPath = argv[2];
            }
            break;

        case 4:
            if (strcmp(argv[1], "-d") == 0)
            {
                outputLevel = OUTPUT_NORMAL;
            }
            else
            {
                outputLevel = OUTPUT_DEBUG;
            }
            dnsServer = argv[2];
            localPath = argv[3];
            break;

        default:
            LOGE("Unknown params");
            exit(-1);
    }

    switch (outputLevel)
    {
        case OUTPUT_QUIET:
            LOGI("outputLevel = QUIET");
            break;
        case OUTPUT_NORMAL:
            LOGI("outputLevel = NORMAL");
            break;
        case OUTPUT_DEBUG:
            LOGI("outputLevel = DEBUG");
            break;
    }
    LOGI("dnsServer = " << dnsServer);
    LOGI("localPath = " << localPath);
}

void loadLocalList(string localPath,
                   deque<IpDomainNode> &ipList,
                   int outputLevel)
{
    ifstream ipFile(localPath.c_str());
    if (!ipFile.is_open())
    {
        LOGE("Failed to load " << localPath);
        exit(-1);
    }
    else
    {
        IpDomainNode tidnode;
        string ip, domain;
        while (!ipFile.eof())
        {
            ipFile >> ip >> domain;
            tidnode.set(ip, domain);
            ipList.push_back(tidnode);
        }
        ipFile.close();
        LOGI("Successfully loaded " << localPath);

        if (outputLevel == OUTPUT_DEBUG)
        {
            LOGI("Local list:");
            for (unsigned i = 0; i < ipList.size(); i++)
            {
                cout << ipList[i].ip << " " << ipList[i].domain << endl;
            }
        }
    }
}

string getDomain(char* recvbuf,
                 int recvflag,
                 unsigned short &qclass,
                 unsigned short &qtype)
{
    //报文头部占12个字节
    const int headLen = 12;
    //获取报文内容长度
    int strLen = recvflag - headLen;
    //指向报文内容
    char* recvstr = recvbuf + headLen;
    //(char *)malloc(sizeof(char)*strLen);
    //memcpy(recvstr, &recvbuf[headLen], strLen);

    //解析报文内容开始
    //解析QNAME，请求域名
    string domain = "";
    char inIdx = 0;
    int outIdx = 0;
    while (outIdx < strLen)
    {
        //www.baidu.com
        //3www5baidu3com0
        //组装域名字符串
        if ((short)recvstr[outIdx] > 0 && (short)recvstr[outIdx] < 64)
        {
            //计数器
            inIdx = recvstr[outIdx];
            outIdx++;
            while (inIdx != 0)
            {
                domain += recvstr[outIdx];
                outIdx++;
                inIdx--;
            }
        }
        //不为0，则补上小数点
        if ((short)recvstr[outIdx] != 0)
        {
            domain += '.';
        }
        //0表示域名结束，停止解析
        else
        {
            outIdx++;
            break;
        }
    }

    unsigned short* us = (unsigned short *)malloc(sizeof(unsigned short));

    //解析QTYPE
    memcpy(us, &recvstr[outIdx], 2);
    qtype = ntohs(*us);

    //解析QCLASS
    memcpy(us, &recvstr[outIdx + 2], 2);
    qclass = ntohs(*us);

    free(us);

    //解析报文内容结束

    return domain;
}

void printBuf(char* buf, int buflen)
{
    for (int i = 0; i < buflen; i++)
    {
        if ((buf[i] & 0xf0) == 0x00)
        {
            cout << "0";
        }
        //输出十六进制数
        cout << hex << int((buf[i]) & 0xff) << " ";
    }
    cout << endl;
}

string localQuery(string tempdomain, deque<IpDomainNode> ipdict)
{
    for (unsigned i = 0; i < ipdict.size(); i++)
    {
        if (strcmp(tempdomain.c_str(), ipdict[i].domain.c_str()) == 0)
        {
            return ipdict[i].ip;
        }
    }
    //本地未找到，进行中继
    return LOCAL_NOT_FOUND;
}

void handleIDTList(deque<IDTransferNode> &idtlist,
                   int &idtlist_base)
{
    //如果队列已满
    if (idtlist.size() == IDT_MAX_SIZE)
    {
        //丢弃前半部分的请求
        for (int i = 0; i < IDT_HALF_SIZE; i++)
        {
            idtlist.pop_front();
        }
        //调整队列的起始下标为500
        if (idtlist_base == 0)
        {
            idtlist_base = IDT_HALF_SIZE;
        }
        else
        {
            idtlist_base = 0;
        }
    }
}

int pos2id(deque<IDTransferNode> idtlist,
           int idtlist_base)
{
    return ((idtlist.size() + idtlist_base) % IDT_MAX_SIZE);
}

int id2pos(int x, int idtlist_base)
{
    return((x + idtlist_base) % IDT_MAX_SIZE);
}