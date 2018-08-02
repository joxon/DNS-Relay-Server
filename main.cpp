#pragma comment(lib,"Ws2_32.lib")

#include "helperClasses.h"
#include "helperFuncs.h"

int main(int argc, char** argv)
{
    cout << "DNS-Relay-Server v1.0. Build time: " << __DATE__ << " " << __TIME__ << endl
        << "Usage: DNS-Relay-Server.exe [-d | -dd] [<dns-server>] [<local-list-path>]" << endl
        << endl;

    //本地列表地址
    string localPath;
    //外部DNS地址
    string dnsServer;
    //调试输出级别，取值为0、1、2
    //=0，什么都不输出
    //=1，输出时间信息、DNS请求包中的域名、QCLASS、QTYPE
    //=2，在“级别1”的基础上附加FLAG
    int outputLevel;
    //命令行参数处理
    parseParam(argc, argv, localPath, dnsServer, outputLevel); //lxj

    //存储
    deque<IpDomainNode> ipList;
    //初始化IP转换表
    loadLocalList(localPath, ipList, outputLevel);

    //初始化动态链接库用的，之后socket才能用
    WSADATA wsaData;
    //初始化ws2_32.dll动态链接库。第一个2表示副版本号，第二个号表示主版本号，第二个参数返回请求socket的版本信息
    //当一个应用程序调用WSAStartup函数时，
    //操作系统根据请求的Socket版本来搜索相应的Socket库，
    //然后绑定找到的Socket库到该应用程序中。
    //以后应用程序就可以调用所请求的Socket库中的其它Socket函数了。该函数执行成功后返回0。
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    //本地DNS套接字
    SOCKET localSocket;
    //创建套接字：
    //UDP（非TCP/IP）,数据报（非流），通信协议
    //建立socket，注意必须是SOCK_DGRAM
    //第三个参数为0，自动选择第二参数对应的协议类型
    if ((localSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        LOGE("Failed to create socket! Error code = " << WSAGetLastError());
        getchar();
        exit(1);
    }

    //本地DNS套接字地址
    SOCKADDR_IN localAddr;
    //设置套接字：
    memset(&localAddr, 0, sizeof(localAddr));
    //指定地址族，表示是UDP协议族的套接字；
    localAddr.sin_family = AF_INET;
    //指明端口号
    localAddr.sin_port = htons(DEFAULT_PORT);
    //接收任意IP发来的数据
    //sin_addr：用inet_addr()把字符串形式的IP地址转换成unsigned long型的整数值后再置给s_addr，
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    //绑定本地DNS服务器地址
    if (bind(localSocket, (SOCKADDR*)&localAddr, sizeof(localAddr)))
    {
        LOGE("Failed to bind localSocket! Error code = " << WSAGetLastError());
        exit(-2);
    }
    else
    {
        LOGI("Successfully binded localSocket!");
    }

    //外部DNS套接字地址
    SOCKADDR_IN  dnsServerAddr;
    dnsServerAddr.sin_family = AF_INET;
    dnsServerAddr.sin_port = htons(DEFAULT_PORT);
    dnsServerAddr.sin_addr.s_addr = ::inet_addr(dnsServer.c_str());

    //请求端套接字地址
    SOCKADDR_IN clientAddr;
    int clientLen = sizeof(clientAddr);

    //采集、输出系统时间的一个接口
    MySystemTime systime;

    //deque是双端队列
    //存储中继DNS包的oldID，和原请求套接字信息
    deque<IDTransferNode> idtList;
    //记录一个请求的节点
    IDTransferNode idtNode;
    //初始时队列基准为0，然后超过1000时变为500
    int idtListBase = 0;

    //保存DNS报文中QCLASS, QTYPE的信息
    unsigned short qclass, qtype;

    //发送、接收的缓冲区
    char sendBuffer[512];
    char recvBuffer[512];
    int recvBufLen = sizeof(recvBuffer);
    //初始化接收缓冲区，全部置零
    memset(recvBuffer, 0, recvBufLen);

    //接收到的DNS报文的头部
    Flags rflags;

    LOGI("DNS Relay Server is now listening...");
    while (1)
    {
        //接收DNS请求
        //参数：
        //localSocket:标识一个已连接套接口的描述字；
        //recvBuffer:接收数据缓冲区；
        //recvBufLen:缓冲区长度
        //0:调用操作方式
        //(SOCKADDR*)&clientAddr：指针，指向装有源地址的缓冲区
        //&clientLen：指针，指向clientAddr的长度值
        //
        //用途：
        //用于从（已连接）套接口上接收数据，并捕获数据发送源的地址
        //
        //返回值：
        //recvFlag=接收到的字符数
        //读入的字节数：无错
        //0：连接中断
        //SOCKET_ERROR：没成功接收。
        //接收UDP消息的sockaddr存在clientAddr里
        //
        //是阻塞式的，一直等待客户端请求来到
        //
        int recvFlag = recvfrom(localSocket,
                                recvBuffer, recvBufLen,
                                0,
                                (SOCKADDR*)&clientAddr, &clientLen);

        //接收的消息长度为0
        if (recvFlag == 0)
        {
            LOGE("recvfrom: Disconnected!");
            break;
        }
        //Socket错误
        else if (recvFlag == SOCKET_ERROR)
        {
            if (outputLevel > OUTPUT_QUIET)
            {
                systime.print();
                LOGE("recvfrom: Failed!");
            }
            continue;
        }
        //接收UDP消息成功
        else
        {
            //获取域名，得到QTYPE、QCLASS
            string domain = getDomain(recvBuffer, recvFlag, qclass, qtype);

            //QCLASS=1为IPv4
            //否则不是IPV4
            string queryResult;
            if (qclass != 1)
            {
                if (outputLevel > OUTPUT_QUIET)
                {
                    systime.print();
                    LOGW("getDomain: Not IPV4");
                }
                queryResult = LOCAL_NOT_FOUND;
                continue;
            }

            //recvBuffer[0]+recvBuffer[1]=ID
            //recvBuffer[2]=QR+OPCODE+AA+TC+RD
            //recvBuffer[3]=RA+Z+RCODE
            //recvBuffer[4]+recvBuffer[5]=QDCOUNT
            //recvBuffer[6]+recvBuffer[7]=ANCOUNT
            //recvBuffer[8]+recvBuffer[9]=NSCOUNT
            //recvBuffer[10]+recvBuffer[11]=ARCOUNT
            rflags.set(recvBuffer);

            if (outputLevel > OUTPUT_QUIET)
            {
                systime.print();
                LOGI("domain = " << domain);

                if (outputLevel > OUTPUT_NORMAL)
                {
                    LOGD("idtList.size() = " << idtList.size());
                    LOGD("QTYPE = " << qtype);
                    LOGD("QCLASS = " << qclass);
                    LOGD("Recv FLAGS = ");
                    rflags.print();
                    LOGD("recvBuffer HEX = ");
                    printBuf(recvBuffer, recvFlag);
                }
            }

            //QR=0，处理查询
            if (rflags.QR == QR_QUERY)
            {
                queryResult = localQuery(domain, ipList);
                //在本地找到，发挥服务器功能
                if (queryResult != LOCAL_NOT_FOUND)
                {
                    //构造响应报文返回
                    //初始化：复制一份和请求一样的报文
                    for (int i = 0; i < recvFlag; ++i)
                    {
                        sendBuffer[i] = recvBuffer[i];
                    }

                    //char: 8bit
                    //short: 16bit
                    //int: 32bit
                    //long: 64bit
                    unsigned short us16bit;

                    //构造DNS报头开始
                    //sendBuffer[0]，sendBuffer[1]为ID，和请求报文一样

                    //sendBuffer[2]，sendBuffer[3]为QR到RCODE的报头
                    //设置标志域1000 0001 1000 00（00/11）
                    //QR = QueryResponse = 1,表示响应
                    //OPCODE = 0,表示标准查询
                    //AA = AuthoritativeAnswer = 0,表示名字服务器非权限服务器
                    //TC = TrunCated = 0，非截断
                    //RD = RecursionDesired = 1，表示客户端希望得到递归回答
                    //RA = RecursionAvailable = 1，表示可以得到递归响应
                    //Z = Zero = 0，保留字段
                    //RCODE = 0，无差错（本地列表服务）
                    //RCODE = 3，有差错（本地列表屏蔽）
                    if (queryResult == "0.0.0.0")
                    {
                        us16bit = htons(0x8183);
                        if (outputLevel > OUTPUT_QUIET)
                        {
                            LOGI("Domain found in local list.");
                            LOGW("Domain forbidden!");
                        }
                    }
                    else
                    {
                        us16bit = htons(0x8180);
                        if (outputLevel > OUTPUT_QUIET)
                        {
                            LOGI("Domain found in local list.");
                            LOGI("Local returns " << queryResult);
                        }
                    }
                    memcpy(&sendBuffer[2], &us16bit, 2);

                    //sendBuffer[4]，sendBuffer[5]为QDCOUNT，和原报文相同，跳过

                    //sendBuffer[6]，sendBuffer[7]为ANCOUNT，回答数
                    if (queryResult == "0.0.0.0")
                    {
                        //发挥屏蔽功能，主机字节转网络字节，RR=0
                        us16bit = htons(0x0000);
                    }
                    else
                    {
                        //发挥服务器功能 ,主机字节转网络字节。RR=1
                        us16bit = htons(0x0001);
                    }
                    memcpy(&sendBuffer[6], &us16bit, 2);

                    //sendBuffer[8]，sendBuffer[9]为NSCOUNT，域名服务器数

                    //sendBuffer[10]，sendBuffer[11]为ARCOUNT，附加记录数
                    //构造DNS报头结束

                    //构造DNS响应RR开始
                    int sendLen = recvFlag;//接收的字节长度

                    //NAME：问题域的域名
                    us16bit = htons(0xc00c);
                    memcpy(&sendBuffer[sendLen], &us16bit, 2);
                    sendLen += 2;

                    //TYPE=1，为IPV4
                    us16bit = htons(0x0001);
                    memcpy(&sendBuffer[sendLen], &us16bit, 2);
                    sendLen += 2;

                    //CLASS=1，为IN类型
                    us16bit = htons(0x0001);
                    memcpy(&sendBuffer[sendLen], &us16bit, 2);
                    sendLen += 2;

                    //TTL不确定，这里取为273
                    unsigned long ul32bit;
                    ul32bit = htonl(0x00000111);
                    memcpy(&sendBuffer[sendLen], &ul32bit, 4);
                    sendLen += 4;

                    //RDLENGTH，到结束还需要4个字节(IPv4地址的长度)
                    us16bit = htons(0x0004);
                    memcpy(&sendBuffer[sendLen], &us16bit, 2);
                    sendLen += 2;

                    //RDATA，inet_addr()把字符串形式的IP地址转换成unsigned long型的整数值
                    ul32bit = (unsigned long)inet_addr(queryResult.c_str());
                    memcpy(&sendBuffer[sendLen], &ul32bit, 4);
                    sendLen += 4;

                    //构造DNS响应RR结束

                    //size_t x = queryResult.size();
                    //usTemp = htons(x);
                    //memcpy(&sendBuffer[sendLen - x - 2], &usTemp, 2);

                    //打印刚刚构造的响应报文
                    if (outputLevel > OUTPUT_NORMAL)
                    {
                        Flags sflags;

                        sflags.set(sendBuffer);

                        LOGD("Sent FLAGS = ");
                        sflags.print();
                        LOGD("sendBuffer HEX = ");
                        printBuf(sendBuffer, sendLen);
                    }

                    //发送响应报文
                    int sendFlag = sendto(localSocket,
                                          sendBuffer, sendLen,
                                          0,
                                          (SOCKADDR*)&clientAddr, clientLen);
                    //若无错误发生，返回所发送数据的总数。否则的话，返回SOCKET_ERROR错误
                    if (sendFlag == SOCKET_ERROR && outputLevel > OUTPUT_QUIET)
                    {
                        LOGE("sendto: Failed to send to clients! Error code = " << WSAGetLastError());
                    }
                    else
                    {
                        LOGI("Successfully sent response to the client.");
                    }
                }
                //没有在本地找到，发挥中继功能
                else
                {
                    //获取旧ID
                    unsigned short *oldID = (unsigned short*)malloc(sizeof(unsigned short));
                    memcpy(oldID, recvBuffer, 2);

                    //保证队列不为满
                    handleIDTList(idtList, idtListBase);

                    //为确保中继DNS的id具有唯一性
                    int newIDint = pos2id(idtList, idtListBase);
                    unsigned short newID = htons((unsigned short)(newIDint));

                    //变更中继DNS包的id，使之newID唯一,并记录oldID,cname
                    idtNode.oldID = ntohs(*oldID);
                    idtNode.clientAddr = clientAddr;
                    idtNode.processed = false;
                    idtList.push_back(idtNode);

                    if (outputLevel > OUTPUT_QUIET)
                    {
                        LOGI("Domain NOT found in local list. Relaying...");
                    }
                    //把新ID放在新的请求报文的头部
                    memcpy(recvBuffer, &newID, 2);

                    //把recvBuffer转发到外部DNS服务器
                    int sendFlag = sendto(localSocket, recvBuffer, recvFlag, 0,
                        (SOCKADDR*)&dnsServerAddr, sizeof(dnsServerAddr));

                    if (sendFlag == SOCKET_ERROR)
                    {
                        if (outputLevel > OUTPUT_QUIET)
                        {
                            LOGE("sendto: Failed to reach DNS server! Error code = " << WSAGetLastError());
                        }
                        continue;
                    }
                    else if (sendFlag == 0)
                    {
                        if (outputLevel > OUTPUT_QUIET)
                        {
                            LOGE("sendto: Disconected!");
                        }
                        break;
                    }

                    free(oldID);

                    if (outputLevel > OUTPUT_QUIET)
                    {
                        LOGI("Successfully relayed request to external DNS server.");
                    }
                }
            }

            //QR=1，处理响应
            else if (rflags.QR == QR_RESPONSE)
            {
                //将newID转为oldID，并找到对应的cname
                unsigned short *newID = (unsigned short*)malloc(sizeof(unsigned short));

                //从buffer获取新ID
                memcpy(newID, recvBuffer, 2);

                //将新ID转成int型，ntohs = net to host short，网络顺序转成主机顺序
                int a = (int)ntohs(*newID);
                free(newID);

                //获取新ID对应的旧ID的下标
                int pos = id2pos(a, idtListBase);

                //若当该query已处理，则直接跳过
                if (idtList[pos].processed) continue;

                //若当该query未处理，获取旧ID，htons = host to net short，主机顺序转成网络顺序
                unsigned short oldID = htons(idtList[pos].oldID);

                //构造响应报文头ID，准备发送回客户端
                memcpy(recvBuffer, &oldID, 2);

                //标记为已处理
                idtList[pos].processed = true;

                //发给客户端
                int sendFlag = sendto(localSocket,
                                      recvBuffer, recvFlag,
                                      0,
                                      (SOCKADDR*)&idtList[pos].clientAddr, sizeof(idtList[pos].clientAddr));
                //判断发送结果
                if (sendFlag == SOCKET_ERROR)
                {
                    if (outputLevel > OUTPUT_QUIET)
                    {
                        LOGE("sendto: Failed to send to the client! Error code = " << WSAGetLastError());
                    }
                    continue;
                }
                else if (sendFlag == 0)
                {
                    if (outputLevel > OUTPUT_QUIET)
                    {
                        LOGE("sendto: Disconnected!");
                    }
                    break;
                }

                if (outputLevel > OUTPUT_QUIET)
                {
                    LOGI("Successfully sent response to the client.");
                }
            }

            //错误的QR字段
            else if (outputLevel > OUTPUT_QUIET)
            {
                LOGE("QR field incorrect!");
            }
        }
    }

    //关闭套接字
    closesocket(localSocket);
    WSACleanup();

    return 0;
}