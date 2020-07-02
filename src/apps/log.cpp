#include <iostream>
#include "log.hpp"

void seclog::info(const std::string str) {
    std::cout << str << std::endl;
}

void seclog::info(const std::string str, const int i) {
    std::cout << str << i << std::endl;
}

void seclog::info(const std::string str, const std::string i) {
    std::cout << str << i << std::endl;
}

void seclog::info(const std::string str, const unsigned long i) {
    std::cout << str << i << std::endl;
}

void seclog::info(const std::string str, const long i) {
    std::cout << str << i << std::endl;
}

void seclog::debug(const std::string str) {
    std::cout << str << std::endl;
}

void seclog::warning(const std::string str) {
    std::cout << str << std::endl;
}

void seclog::signprint(const std::string str, unsigned char* signature, int signLen) {
    std::cout << str << std::endl;
    for(int i = 0; i < signLen-1; ++i) {
        printf("%02x-", signature[i]);
    }
    printf("%02x\n", signature[signLen-1]);
}
