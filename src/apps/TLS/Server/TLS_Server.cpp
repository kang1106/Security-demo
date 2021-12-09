#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "glog/logging.h"

using namespace std;

#define BUF_SIZE 1024

int main(int argc, char *argv[]) {
   int serv_socket;
   int clnt_socket;
   int id = 1, strlen;
   struct sockaddr_in serv_addr;
   struct sockaddr_in clnt_addr;
   socklen_t clnt_addr_size;
   char message[BUF_SIZE];

    // Input validation
    if(argc != 2) {
        LOG(ERROR) << "Usage: " << argv[0] << "<port>";
        exit(0);
    }

    serv_socket = socket(PF_INET, SOCK_STREAM, 0);
    if(serv_socket == -1) {
        LOG(ERROR) << "Creat socket error";
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);  //自动获取计算机的IP地址
    serv_addr.sin_port = htons(atoi(argv[1]));  //atoi (表示ascii to integer)是把字符串转换成整型数的一个函数

    if(bind(serv_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
        LOG(ERROR) << "Socket bind error";
    }
    if(listen(serv_socket, 5) == -1) {
        LOG(ERROR) << "Socket listen error";
    }
    clnt_addr_size = sizeof(clnt_addr);

    //处理五次连接请求
    for (int i = 0; i < 5; ++i) {
        clnt_socket = accept(serv_socket, (sockaddr*)&clnt_addr, &clnt_addr_size);
        if(clnt_socket == -1)
          LOG(ERROR) << "Socket accept error";
        else {
          LOG(INFO) << "Socket accept success";
        }

        while((strlen=read(clnt_socket, message, BUF_SIZE)) != 0){
            LOG(INFO) << "Message from client: " << message;;
            write(clnt_socket, message, strlen);
            memset(message, 0, sizeof(message));
        }
        id++;
        close(clnt_socket);
    }
    close(serv_socket);
    return 0;
}
