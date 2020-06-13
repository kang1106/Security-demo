#include <iostream>
#include "log.hpp"

void seclog::info(const std::string str) {
    std::cout << str << std::endl;
}

void seclog::info(const std::string str, const int i) {
    std::cout << str << i << std::endl;
}

void seclog::debug(const std::string str) {
    std::cout << str << std::endl;
}

void seclog::warning(const std::string str) {
    std::cout << str << std::endl;
}
