#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/timeb.h>
#include <time.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#define SERVER_PORT 8000 //监听本机8000端口
#define MAX 4096

using namespace std;
//打印时间
char* log_Time(void)
{
	struct tm *ptm;
	struct timeb nowTimeb;
	static char Time[19];
	ftime(&nowTimeb);
	ptm=localtime(&nowTimeb.time);
	sprintf(Time,"%02d-%02d %02d:%02d:%02d.%03d",ptm->tm_mon+1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec, nowTimeb.millitm);//打印对应时间
	Time[18]=0;
	return Time;
}
//判断连接正常函数
int SocketConnected(int sock)
{
    if (sock <= 0)
        return 0;
    struct tcp_info info;
    int len = sizeof(info);
    getsockopt(sock, IPPROTO_TCP, TCP_INFO, &info, (socklen_t*)&len);
    if ((info.tcpi_state == TCP_ESTABLISHED)) {
        //myprintf("socket connected\n");
        return 1;
    }
    else {
        //myprintf("socket disconnected\n");
        return 0;
    }
}
//main函数
int main(void)
{
    struct sockaddr_in serveraddr, clientaddr;
    int sockfd, confd, len, i = 0,flag_connect=1;
    socklen_t addrlen;
    char ipstr[128];
    char buf[4096];
    pid_t pid;
    //1.socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    //2.bind
    bzero(&serveraddr, sizeof(serveraddr));
    //地址族协议ipv4
    serveraddr.sin_family = AF_INET;
    //ip地址
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons(SERVER_PORT);
    bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    listen(sockfd, 128);//3.listen
    while (1)
    {
        //4. accept阻塞监听客户端的链接请求
        addrlen = sizeof(clientaddr);
	confd = accept(sockfd, (struct sockaddr *)&clientaddr, &addrlen);
      	flag_connect=SocketConnected(confd);
        std::cout<<flag_connect<<endl;
	//打印时间
        printf("[%s]\t", log_Time());
        //如果有客户端连接上服务器，就输出客户端的ip地址和端口号
	printf("client ip %s\tport %d\t is connected\n",inet_ntop(AF_INET, (struct sockaddr *)&clientaddr.sin_addr.s_addr, ipstr, sizeof(ipstr)), ntohs(clientaddr.sin_port));
        //这块是多进程的关键，当accept收到了客户端的连接之后，就创建子进程,让子进程去处理客户端
        //发来的数据，父进程里面关闭confd（因为用不到了），然后父进程回到while循环继续监听客户端的连接
        pid = fork();
        //5. 子进程处理客户端请求
        if (pid == 0)
        { //子进程
            close(sockfd);
            while (1)
            {
		flag_connect=SocketConnected(confd);
		if(flag_connect==1)
		{
			len = read(confd, buf, sizeof(buf));
			printf("[%s] ", log_Time());
			printf("client ip %s\tport %d send:\t",inet_ntop(AF_INET, (struct sockaddr *)&clientaddr.sin_addr.s_addr, ipstr, sizeof(ipstr)), ntohs(clientaddr.sin_port));
			printf("%s\n",&buf[0]);
			continue;	
		}	
		else
		{
			break;
		}
                write(confd, buf, len);
            }
	    printf("client ip %s\tport %d is unconnected successfully\n",inet_ntop(AF_INET, (struct sockaddr *)&clientaddr.sin_addr.s_addr, ipstr, sizeof(ipstr)), ntohs(clientaddr.sin_port));
            close(confd);
            return 0;
        }
        else if (pid > 0)
        { //父进程关闭文件描述符，释放资源
	  // printf("the father data dealing is shutted down successfully\n");	
	   close(confd);
        }
    }
    return 0;
}
