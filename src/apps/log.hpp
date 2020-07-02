#ifndef LOG_HPP_
#define LOG_HPP_

#include <string>

class seclog {
  public:
    void info(const std::string str);
    void info(const std::string str, const int i);
    void info(const std::string str, const unsigned long i);
    void info(const std::string str, const long i);
    void info(const std::string str, const std::string i);
    void debug(const std::string str);
    void warning(const std::string str);
    void signprint(const std::string str, unsigned char* signature, int signLen);
};

#endif /* LOG_HPP_ */